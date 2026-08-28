"""Solver-backed MBA simplification as a d810 instruction rule.

Why a rule rather than a block walk
-----------------------------------
An earlier version walked the blocks itself and installed replacements with
``ins.swap()`` + ``mark_lists_dirty()``.  That passes ``mba.verify(True)`` on a
standalone ``mba`` from ``gen_microcode``, but a *live* decompilation with the
same rewrites returns ``None``: a structurally valid mba is not the same thing
as one the decompiler will consume.

The framework contract avoids the whole class of problem -- ``check_and_replace``
**returns** a replacement and the optimizer installs it, so Hex-Rays owns the
swap, the invalidation and the maturity scheduling.

What this costs
---------------
The rule sees one instruction at a time, so the cross-instruction def-use
inlining the standalone detector used is not available here.  Nested ``mop_d``
sub-trees are still followed, which is where Hex-Rays has already folded
sub-expressions, so the reach is narrower but not nothing.  Measure before
assuming which matters more.
"""

from __future__ import annotations

import dataclasses
import uuid

import ida_hexrays

from d810_cobra.convert import ReconstructionError, build_replacement
from d810_cobra.detect import (
    DEFAULT_MAX_LEAVES,
    MbaCandidate,
    UnsupportedMicrocode,
    _TreeBuilder,
    _walk,
)
from d810_cobra.escalate import EscalationProver
from d810_cobra.expr import accept_rewrite, node_count
from d810_cobra.prove import (
    INLINE_TIMEOUT_MS,
    ProofResult,
    proof_gate_status,
    prove_equivalent,
)
from d810_cobra.store import ProofCacheStore, proof_cache_db_path
from d810_cobra.table import Outcome, RewriteTable
from d810_cobra.solve import (
    SolveStatus,
    binding_available,
    solve_signature,
)
from d810.core import getLogger
from d810.mba.extension_api import (
    NativeMbaCandidate,
    NativeMbaHostServices,
    PendingMbaProviderObservation,
)
from d810.mba.provider_outcome import MbaProviderOutcome, ProviderOutcomeStatus
from d810.mba.provider_routing import MbaProviderKind
from d810.mba.typed_term import term_cost, term_fingerprint
from d810.optimizers.microcode.instructions.peephole.handler import (
    PeepholeSimplificationRule,
)

logger = getLogger(__name__)

_BOOL_OPS = frozenset({"~", "|", "&", "^"})
_ARITH_OPS = frozenset({"-", "+", "*"})
#: Persist after this many newly-settled entries. Flushing per write would
#: rewrite the whole table for every candidate.
_FLUSH_EVERY = 16

#: Portable IRMaturity name -> IDA maturity. The pass layer speaks the portable
#: vocabulary because it must stay hexrays-agnostic; the mapping belongs here,
#: on the IDA side of the seam.
_MATURITY_BY_NAME = {
    "LIFTED": ida_hexrays.MMAT_GENERATED,
    "CANONICAL": ida_hexrays.MMAT_PREOPTIMIZED,
    "LOCAL_OPTIMIZED": ida_hexrays.MMAT_LOCOPT,
    "CALL_MODELED": ida_hexrays.MMAT_CALLS,
    "GLOBAL_ANALYZED": ida_hexrays.MMAT_GLBOPT1,
    "GLOBAL_OPTIMIZED": ida_hexrays.MMAT_GLBOPT2,
    "STRUCTURED": ida_hexrays.MMAT_LVARS,
}

_LEAF_TYPES = frozenset(
    {ida_hexrays.mop_r, ida_hexrays.mop_l, ida_hexrays.mop_S, ida_hexrays.mop_v}
)


class CobraSolveRule(PeepholeSimplificationRule):
    """Simplify an MBA expression with the CoBRA solver, gated on a Z3 proof."""

    DESCRIPTION = "Solve MBA expressions with CoBRA (proof-gated)"
    CATEGORY = "MBA Solving"

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        # MMAT_GLBOPT2 only. Measured end-to-end on VM_DecryptPacket:
        #
        #   MMAT_CALLS    61 rewrites,  87.6 min, NEVER COMPLETED
        #   MMAT_GLBOPT1  40 rewrites,  26+  min, NEVER COMPLETED
        #   MMAT_GLBOPT2  17 rewrites,  46.2 s,   completed, 626 -> 563 lines
        #
        # The earlier list was chosen on candidate count (55 at GLBOPT1 vs 10
        # at GLBOPT2), which is the wrong measure: by GLBOPT2 Hex-Rays has
        # already folded aggressively, so there is far less microcode to walk
        # and far less re-optimisation churn over the same addresses. 17
        # rewrites that finish beat 40 that never do.
        #
        # Overridable via config; see mba_solve.DEFAULT_MATURITIES.
        self.maturities = [ida_hexrays.MMAT_GLBOPT2]
        self.max_leaves = DEFAULT_MAX_LEAVES
        self.require_proof = True
        self.auto_install_solver = False
        # One table and one escalator per rule instance. Both are pure-data and
        # carry no IDA reference, so the worker thread never reaches Hex-Rays.
        #
        # NOT started here. d810's reload machinery leaves several distinct
        # copies of a class in one process, and rules are constructed whether
        # or not a project activates them -- starting in __init__ would spawn a
        # worker thread per dead copy.
        self.table = RewriteTable()
        self.escalator = EscalationProver(self.table)
        # The durable cache is loaded lazily, not here: the manager assigns
        # ``log_dir`` *after* construction, so resolving the path now would
        # silently fall back to the temp directory.
        self._store: ProofCacheStore | None = None
        self._store_loaded = False
        self._unflushed = 0
        self._mba_host: NativeMbaHostServices | None = None
        self._pending_observation: PendingMbaProviderObservation | None = None

    def bind_mba_host(self, host: NativeMbaHostServices) -> None:
        """Bind the IDA-native capture facade once for this rule instance."""
        if self._mba_host is not None:
            raise RuntimeError("native MBA host is already bound")
        self._mba_host = host

    def stop_escalator(self) -> None:
        """Stop the off-path prover during activation shutdown."""
        self.escalator.stop()

    def close_store(self) -> None:
        """Close the durable proof cache after its final flush."""
        close = getattr(self._store, "close", None)
        if callable(close):
            close()

    def _begin_attempt(self, candidate: NativeMbaCandidate) -> None:
        source = candidate.raw_term if candidate.raw_term is not None else candidate.term
        cost = term_cost(candidate.term)
        outcome = MbaProviderOutcome(
            provider=MbaProviderKind.COEFFICIENT_SOLVER,
            status=ProviderOutcomeStatus.UNCHANGED,
            fingerprint=term_fingerprint(candidate.term),
            input_cost=cost,
            refusal_reason="pending",
        )
        self._pending_observation = PendingMbaProviderObservation(
            attempt_uuid=str(uuid.uuid4()),
            raw_term=source,
            canonical_term=candidate.term,
            outcome=outcome,
            candidate_cost=cost,
        )

    def _finish_attempt(
        self,
        status: ProviderOutcomeStatus,
        reason: str | None = None,
        *,
        proof_verdict: bool | None = None,
    ) -> None:
        pending = self._pending_observation
        if pending is None:
            return
        outcome = dataclasses.replace(
            pending.outcome,
            status=status,
            refusal_reason=reason,
            proof_verdict=proof_verdict,
        )
        self._pending_observation = dataclasses.replace(pending, outcome=outcome)

    def record_mutation_accepted(self) -> None:
        pending = self._pending_observation
        if pending is None or (
            getattr(pending.outcome.status, "value", None)
            != ProviderOutcomeStatus.IMPROVED.value
        ):
            return
        self._pending_observation = dataclasses.replace(
            pending,
            outcome=dataclasses.replace(
                pending.outcome,
                status=ProviderOutcomeStatus.APPLIED,
                refusal_reason=None,
            ),
        )

    def record_mutation_rejected(self, reason: str) -> None:
        pending = self._pending_observation
        if pending is None or (
            getattr(pending.outcome.status, "value", None)
            != ProviderOutcomeStatus.IMPROVED.value
        ):
            return
        self._pending_observation = dataclasses.replace(
            pending,
            outcome=dataclasses.replace(
                pending.outcome,
                refusal_reason=reason or "outer_rejected",
            ),
        )

    def pending_provider_observation(self) -> PendingMbaProviderObservation | None:
        pending = self._pending_observation
        self._pending_observation = None
        return pending

    def configure(self, kwargs) -> None:
        super().configure(kwargs)
        self.max_leaves = int(self.config.get("max_leaves", DEFAULT_MAX_LEAVES))
        self.require_proof = bool(self.config.get("require_proof", True))
        # OFF by default, and it must stay that way. Installing runs pip, which
        # needs the network and can take tens of seconds; doing that
        # unprompted while IDA loads a project would freeze the UI for reasons
        # the user never asked for. Opt in, or use the workbench action.
        self.auto_install_solver = bool(self.config.get("auto_install_solver", False))
        names = self.config.get("maturities")
        if names:
            mapped = [_MATURITY_BY_NAME[n] for n in names if n in _MATURITY_BY_NAME]
            if mapped:
                self.maturities = mapped
            else:
                logger.warning(
                    "cobra-solve: no usable maturity in %s; keeping %s",
                    names, self.maturities,
                )
        logger.info(
            "cobra-solve configured: maturities=%s max_leaves=%d proof=%s",
            self.maturities, self.max_leaves, self.require_proof,
        )
        # A proof gate that cannot be honoured skips every candidate, which is
        # indistinguishable from "the solver matched nothing". Say so once, at
        # configure time, rather than letting the pass look inert.
        gate_warning = proof_gate_status(self.require_proof)
        if gate_warning is not None:
            if self.auto_install_solver:
                self._install_solver_support()
                gate_warning = proof_gate_status(self.require_proof)
            if gate_warning is not None:
                logger.warning("cobra-solve: %s", gate_warning)
        # Only an activated rule gets configured, so this is the first point at
        # which a worker is known to be wanted. start() is idempotent.
        self.escalator.start()

    def _install_solver_support(self) -> None:
        """Install the solver d810 keeps in ~/.d810-speedups, on explicit opt-in.

        d810 owns the installation because it owns the isolated directory and
        the native-library pinning that goes with it; this only asks. On success
        d810 bumps its optional-dependency generation, so ``z3_available()``
        re-probes and the gate opens without restarting IDA.

        Never raises: this runs during rule configuration, on the decompiler's
        thread, where an escaping exception crosses into Hex-Rays C++.
        """
        try:
            from d810.speedups.install import install_solver_support
        except Exception:  # noqa: BLE001 - older d810 without the helper
            logger.warning(
                "cobra-solve: auto_install_solver is set but this d810 has no "
                "installer; run the 'install-speedups' command instead"
            )
            return
        logger.info("cobra-solve: auto_install_solver is set, installing z3...")
        result = install_solver_support()
        if result.ok:
            logger.info("cobra-solve: %s", result.message)
        else:
            logger.warning("cobra-solve: %s", result.message)

    def _ensure_store(self) -> None:
        """Load the durable proof cache once, on first use.

        Deferred to first call rather than done in configure() because the
        manager sets ``log_dir`` on the rule after construction, and the rule
        is only ever invoked once setup is complete.
        """
        if self._store_loaded:
            return
        self._store_loaded = True
        try:
            self._store = ProofCacheStore(
                proof_cache_db_path(getattr(self, "log_dir", None))
            )
            loaded = self._store.load()
            # Seed the live table with everything already settled. A cold cache
            # is normal and simply means paying the solve once more.
            n = 0
            for key, entry in loaded._entries.items():  # noqa: SLF001
                if key not in self.table._entries:  # noqa: SLF001
                    self.table._entries[key] = entry  # noqa: SLF001
                    n += 1
            # FLUSH-BEFORE-EVICT: the table is bounded, so anything pushed out
            # must reach disk on its way. The alternative -- load-on-miss --
            # is worse here because a miss is precisely what the table exists
            # to prevent: an evicted NO_REWRITE would be re-solved (~84ms) only
            # to find the store already knew.
            self.table.set_evict_sink(self._store.put_entry)
            logger.info(
                "cobra-solve proof cache: %d entries from %s", n, self._store.db_path
            )
        except Exception:  # noqa: BLE001 - a bad cache must never break a decompile
            logger.exception("cobra-solve could not load its proof cache")
            self._store = None

    def _record_and_maybe_flush(self) -> None:
        """Persist settled entries in batches.

        Flushing on every write would rewrite the whole table per candidate;
        batching keeps the cost proportional to new knowledge rather than to
        traffic.
        """
        self._unflushed += 1
        if self._store is None or self._unflushed < _FLUSH_EVERY:
            return
        self._unflushed = 0
        try:
            self._store.flush(self.table)
        except Exception:  # noqa: BLE001
            logger.exception("cobra-solve could not flush its proof cache")

    def flush_store(self) -> None:
        """Force a flush. Safe to call when no store was ever opened."""
        if self._store is None:
            return
        try:
            self._store.flush(self.table)
            self._unflushed = 0
        except Exception:  # noqa: BLE001
            logger.exception("cobra-solve could not flush its proof cache")

    def log_stats(self) -> None:
        """Report table accounting.

        The intra-run hit rate is the number this whole design was missing: the
        0% tree reuse measured earlier came from a single-pass offline
        detection, which by construction cannot repeat.  The live rule is
        re-invoked on the same addresses as Hex-Rays re-optimises (61
        applications across 44 EAs), so this is where reuse actually shows up.
        """
        s = self.table.stats
        logger.info(
            "cobra-solve table: lookups=%d hits=%d negative=%d pending=%d "
            "misses=%d balanced=%s",
            s.lookups, s.hits, s.negative_hits, s.pending_hits, s.misses,
            s.balanced,
        )

    def check_and_replace(self, blk, ins):
        """Never let an exception reach Hex-Rays.

        ``check_and_replace`` is invoked from the C++ optimizer callback. A
        Python exception crossing that boundary does not surface as a
        traceback -- it takes the process down. That is exactly how the z3
        context-mismatch bug presented: SIGSEGV (EXIT=139) after two
        applications, with no INTERR and no assertion. The guard is
        belt-and-braces on top of the context fix, because *any* future bug in
        this path would otherwise have the same catastrophic presentation.
        """
        try:
            return self._check_and_replace(blk, ins)
        except Exception:  # noqa: BLE001 - see docstring; must not propagate
            self._finish_attempt(ProviderOutcomeStatus.ERROR, "callback_error")
            logger.exception(
                "cobra-solve raised at %#x; skipping this instruction",
                getattr(ins, "ea", 0),
            )
            return None

    def _check_and_replace(self, blk, ins):
        portable_candidate = None
        if self._mba_host is not None:
            portable_candidate = self._mba_host.capture_instruction(ins)
            self._begin_attempt(portable_candidate)

        builder = _TreeBuilder()
        try:
            tree = builder.instruction(ins)
        except UnsupportedMicrocode:
            self._finish_attempt(
                ProviderOutcomeStatus.INELIGIBLE, "unsupported_microcode"
            )
            return None
        if tree["kind"] not in ("bin", "un"):
            self._finish_attempt(ProviderOutcomeStatus.INELIGIBLE, "not_mba")
            return None

        names: list[str] = []
        ops: list[str] = []
        _walk(tree, names, ops)
        if not any(o in _BOOL_OPS for o in ops) or not any(
            o in _ARITH_OPS for o in ops
        ):
            self._finish_attempt(ProviderOutcomeStatus.INELIGIBLE, "not_mba")
            return None
        if not names or len(names) > self.max_leaves:
            self._finish_attempt(ProviderOutcomeStatus.INELIGIBLE, "leaf_budget")
            return None

        dest_size = ins.d.size if ins.d is not None else 0
        if dest_size not in (1, 2, 4, 8):
            self._finish_attempt(
                ProviderOutcomeStatus.INELIGIBLE, "unsupported_width"
            )
            return None
        # Uniform widths only: a leaf narrower than the destination produces
        # mixed operand sizes that IDA's verifier rejects.
        if any(builder.snapshots[n].size != dest_size for n in names):
            self._finish_attempt(ProviderOutcomeStatus.INELIGIBLE, "mixed_widths")
            return None

        candidate = MbaCandidate(
            ea=ins.ea,
            block_serial=blk.serial if blk is not None else 0,
            tree=tree,
            leaf_names=tuple(names),
            leaf_snapshots={n: builder.snapshots[n] for n in names},
            dest_size=dest_size,
        )

        if not binding_available():
            self._finish_attempt(
                ProviderOutcomeStatus.UNAVAILABLE, "solver_unavailable"
            )
            return None

        # --- tier 1: the table. A hit skips BOTH solving and proving. -------
        self._ensure_store()
        entry = self.table.lookup(candidate.tree, candidate.bitwidth)
        if entry is not None:
            outcome = getattr(entry.outcome, "value", None)
            if outcome != Outcome.PROVED.value:
                # NO_REWRITE: settled, nothing better exists.
                # PENDING: the escalation prover owns it; asking again this
                # pass would just re-solve work already in flight.
                status = (
                    ProviderOutcomeStatus.OVER_BUDGET
                    if outcome == Outcome.PENDING.value
                    else ProviderOutcomeStatus.UNCHANGED
                )
                reason = (
                    "proof_timeout_escalated"
                    if outcome == Outcome.PENDING.value
                    else "cached_no_rewrite"
                )
                self._finish_attempt(status, reason)
                return None
            return self._install(candidate, entry.rewrite, ins)

        # --- tier 2: solve, then accept, then a BOUNDED proof ---------------
        result = solve_signature(
            candidate.tree, candidate.leaf_names, candidate.bitwidth
        )
        if getattr(result.status, "value", None) != SolveStatus.SOLVED.value \
                or result.tree is None:
            # Negative caching is what stops this candidate being re-solved on
            # every pass; 46 of 60 measured candidates end here.
            self.table.record_no_rewrite(candidate.tree, candidate.bitwidth)
            self._record_and_maybe_flush()
            if getattr(result.status, "value", None) == SolveStatus.UNCHANGED.value:
                self._finish_attempt(ProviderOutcomeStatus.UNCHANGED, "no_rewrite")
            else:
                self._finish_attempt(ProviderOutcomeStatus.ERROR, "solver_failed")
            return None
        # Accept before proving: a rejected rewrite is never used, so proving
        # it first is pure waste.
        if not accept_rewrite(candidate.tree, result.tree):
            self.table.record_no_rewrite(candidate.tree, candidate.bitwidth)
            self._record_and_maybe_flush()
            self._finish_attempt(ProviderOutcomeStatus.UNCHANGED, "accept_refused")
            return None

        if self.require_proof:
            verdict = prove_equivalent(
                candidate.tree,
                result.tree,
                candidate.leaf_names,
                candidate.bitwidth,
                timeout_ms=INLINE_TIMEOUT_MS,
            )
            # Compare by value: d810's reload machinery can leave two distinct
            # ProofResult classes in one process, and `is` then fails for a
            # verdict that really is PROVED.
            value = getattr(verdict, "value", None)
            if value == ProofResult.REFUTED.value:
                logger.warning(
                    "cobra-solve REFUTED a rewrite at %#x; not applying", ins.ea
                )
                self.table.record_no_rewrite(candidate.tree, candidate.bitwidth)
                self._record_and_maybe_flush()
                self._finish_attempt(
                    ProviderOutcomeStatus.PROOF_FAILED,
                    "proof_refuted",
                    proof_verdict=False,
                )
                return None
            if value != ProofResult.PROVED.value:
                # --- tier 3: starved, not disproved. Hand it to the off-path
                # prover and skip it this pass. Measured, this is where the
                # expensive minority goes: 98% of proof time sat in 4 of 14
                # proofs, the worst at 93.6s.
                self.escalator.submit(
                    candidate.tree,
                    candidate.bitwidth,
                    result.tree,
                    candidate.leaf_names,
                )
                self._finish_attempt(
                    ProviderOutcomeStatus.OVER_BUDGET,
                    "proof_timeout_escalated",
                )
                return None

        self.table.record_proved(candidate.tree, candidate.bitwidth, result.tree)
        self._record_and_maybe_flush()
        return self._install(candidate, result.tree, ins)

    def _install(self, candidate, rewrite, ins):
        if rewrite is None:
            return None
        try:
            out = build_replacement(candidate, rewrite, ins)
            logger.info(
                "cobra-solve applied @ %#x  %d -> %d nodes",
                ins.ea, candidate.node_count, node_count(rewrite),
            )
            self._finish_attempt(
                ProviderOutcomeStatus.IMPROVED,
                proof_verdict=True if self.require_proof else None,
            )
            return out
        except ReconstructionError as exc:
            logger.debug("cobra-solve could not rebuild %#x: %s", ins.ea, exc)
            self._finish_attempt(
                ProviderOutcomeStatus.RECONSTRUCTION_FAILED,
                "reconstruction_failed",
            )
            return None
