"""IDA-runtime coverage for CoBRA's D810-owned residual publication seam.

Everything on d810's side of the seam is real: the process-wide host capability
registry, entry-point discovery through ``d810.backends.registry()``, a compiled
pipeline-v2 schedule, native capture of a real ``minsn_t``, the outer
``InstructionOptimizerManager`` and its mutation commit. This mirrors d810's own
acceptance test (tests/system/runtime/backends/test_plugin_residual_discovery.py)
rather than re-assembling d810 internals by hand, which is what the previous
version of this file did -- and why it broke when those internals moved.

Only CoBRA's own seams are patched, to force each outcome. The ``accepted`` case
patches nothing: ``x + y - 2*(x & y)`` really solves to ``x ^ y``, is really
proved, and is really committed by d810.
"""

# ``ida_hexrays`` is intentionally imported before D810's IDA-coupled modules
# so local collection reports one skip when the native runtime is unavailable.
# ruff: noqa: E402

from __future__ import annotations

import contextlib
import importlib.metadata
import os
import platform
from collections import defaultdict
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest

ida_hexrays = pytest.importorskip("ida_hexrays")

from d810.backends import _host_capability_registry, registry
from d810.core.config import ProjectConfiguration
from d810.core.function_execution_identity import (
    FunctionExecutionIdentity,
    MbaObservationContext,
)
from d810.hexrays.expr import ast as ast_dispatcher
from d810.hexrays.hooks.optinsn_adapter import InstructionOptimizerManager
from d810.hexrays.ir.mop_snapshot import MopSnapshot
from d810.ir.maturity import IRMaturity
from d810.mba.discovery_store import MbaDiscoveryStore
from d810.mba.extension_api import (
    D810_MBA_RESIDUAL_OBSERVATION_CAPABILITY,
    MbaResidualObservationSink,
)
from d810.mba.native_callback_lease import native_mba_callback_scope
from d810.mba.residual_observation_sink import SqliteMbaResidualObservationSink
from d810.optimizers.microcode.instructions.handler import InstructionOptimizer
from d810.passes.config_v2_hook_runtime import compile_config_v2_hook_schedule

from d810_cobra.convert import ReconstructionError
from d810_cobra.prove import ProofResult
from d810_cobra.rules import cobra_solve
from d810_cobra.solve import SolveResult, SolveStatus

try:
    COBRA_VERSION = importlib.metadata.version("d810-cobra")
except importlib.metadata.PackageNotFoundError:  # pragma: no cover - env guard
    COBRA_VERSION = None

# Discovery goes through the d810.backends entry point, which only an installed
# distribution has; a source checkout on PYTHONPATH is invisible to it.
pytestmark = pytest.mark.skipif(
    COBRA_VERSION is None, reason="d810-cobra distribution is not installed"
)

RUNTIME_MATURITY = ida_hexrays.MMAT_PREOPTIMIZED
FUNCTION_EA = 0x401000
INSTRUCTION_EA = 0x401002
BLOCK_SERIAL = 7


def _get_default_binary() -> str:
    override = os.environ.get("D810_TEST_BINARY")
    if override:
        return override
    return (
        "libobfuscated.dylib" if platform.system() == "Darwin" else "libobfuscated.dll"
    )


def _leaf(name: str, register: int, size: int = 4):
    leaf = ast_dispatcher.AstLeaf(name)
    leaf.mop = MopSnapshot(t=ida_hexrays.mop_r, size=size, reg=register)
    leaf.dest_size = size
    return leaf


def _constant(value: int, size: int = 4):
    constant = ast_dispatcher.AstConstant(str(value), value, size)
    constant.mop = MopSnapshot(t=ida_hexrays.mop_n, size=size, value=value)
    constant.dest_size = size
    return constant


def _node(opcode: int, left, right=None, size: int = 4):
    node = ast_dispatcher.AstNode(opcode, left, right)
    node.dest_size = size
    return node


def _mba_instruction():
    """A real native ``out = (x + y) + (-2 * (x & y))``, which equals ``x ^ y``."""
    common_sum = _node(ida_hexrays.m_add, _leaf("x", 1), _leaf("y", 2))
    common_and = _node(ida_hexrays.m_and, _leaf("x", 1), _leaf("y", 2))
    coefficient = _node(ida_hexrays.m_mul, _constant(-2), common_and)
    destination = _leaf("out", 7).create_mop(INSTRUCTION_EA)
    return _node(ida_hexrays.m_add, common_sum, coefficient).create_minsn(
        INSTRUCTION_EA, destination
    )


class _Optimizer(InstructionOptimizer):
    RULE_CLASSES = [object]

    def add_rule(self, rule):
        self.rules.add(rule)
        return True


def _context(identity) -> MbaObservationContext:
    return MbaObservationContext(
        function_identity=FunctionExecutionIdentity(
            input_identity="sha256:" + "c" * 64,
            input_identity_provenance="verified_loader_sha256",
            external_evidence_allowed=True,
            database_uuid="12345678-1234-5678-1234-567812345678",
            database_identity="cobra-publication-idb",
            function_ea=FUNCTION_EA,
            function_rva=0x1000,
            function_fingerprint="cobra-publication-function",
            decompilation_session_id="12345678-1234-5678-1234-567812345679",
            top_level_epoch=1,
            maturity=IRMaturity.CANONICAL.value,
            evidence_generation=1,
        ),
        plugin_identity=identity,
        instruction_ea=INSTRUCTION_EA,
        block_serial=BLOCK_SERIAL,
        block_ea=FUNCTION_EA,
    )


def _manager(optimizer):
    """The outer optimizer, shaped exactly as d810's acceptance test builds it."""
    manager = InstructionOptimizerManager.__new__(InstructionOptimizerManager)
    manager.current_maturity = RUNTIME_MATURITY
    manager._active_optimizers = [optimizer]
    manager._last_optimizer_tried = None
    manager._rewrite_seen = defaultdict(set)
    manager._cycle_quarantined_rule_names = defaultdict(set)
    manager._scheduled_implementation_names = frozenset()
    manager._resolve_active_instruction_rule_names = lambda _block: None
    manager._residual_admission_cache_key = None
    manager._residual_admission_cache_value = False
    manager.analyzer = SimpleNamespace(analyze=lambda _block, _instruction: None)
    manager.stats = None
    manager.generate_z3_code = False
    manager.mba_observation_context = lambda _block, _instruction, identity: _context(
        identity
    )
    return manager


def _block():
    return SimpleNamespace(
        mba=SimpleNamespace(maturity=RUNTIME_MATURITY, entry_ea=FUNCTION_EA),
        serial=BLOCK_SERIAL,
    )


@contextlib.contextmanager
def _real_cobra_rule(store: MbaDiscoveryStore):
    """Activate cobra-solve through d810's real registry; always clean up.

    The capability lease is taken first and released in ``finally`` no matter
    where activation fails. Registering it and then raising before cleanup is
    set up would leave ``d810.mba.residual-observation.v1`` registered on the
    process-wide host registry, and every later test in the interpreter that
    starts a D810Manager would fail with "already registered".
    """
    sink = SqliteMbaResidualObservationSink(store)
    lease = _host_capability_registry().register(
        D810_MBA_RESIDUAL_OBSERVATION_CAPABILITY,
        MbaResidualObservationSink,
        sink,
        activation_binder=sink.bind_activation,
        implementation_binder=sink.bind_implementation,
    )
    backends = None
    try:
        schedule = compile_config_v2_hook_schedule(
            ProjectConfiguration(
                path=Path("cobra-publication.runtime-config-v2.json"),
                additional_configuration={
                    "pipeline_v2": [
                        {
                            "pass_id": "mba-solve",
                            "options": {
                                "maturities": ["CANONICAL"],
                                "require_proof": True,
                                "max_leaves": 8,
                            },
                        }
                    ]
                },
            )
        )
        binding = next(
            item for item in schedule.instruction_bindings if item.pass_id == "mba-solve"
        )
        backends = registry()
        candidate = backends.require_unique_implementation(
            "mba-solve", install_hint="d810-cobra"
        )
        assert candidate.rule_name == binding.implementation_id
        rule = backends.activate_implementation(candidate)
        rule.bind_plugin_services(backends.plugin_rule_services(candidate))
        rule.configure(dict(binding.config))
        # The durable proof cache is keyed by the expression tree, and every
        # case uses the same tree: a PROVED entry left by one case would let a
        # later case skip the very gate it exists to exercise.
        rule._ensure_store = lambda: None
        assert rule.maturities == [RUNTIME_MATURITY]
        yield rule
    finally:
        if backends is not None:
            backends.close_activations()
        lease.release()
        sink.close()


@contextlib.contextmanager
def _drained_observations(rule):
    """Record what d810's outer optimizer drains from the rule.

    The manager calls ``pending_provider_observation()`` exactly once per
    attempt, after deciding whether to commit. What it receives is the outcome
    CoBRA reported, including ``applied`` -- which the sink deliberately never
    stores as a residual row, so the store alone cannot show it.
    """
    drained = []
    real = rule.pending_provider_observation

    def spy():
        observation = real()
        drained.append(observation)
        return observation

    with mock.patch.object(rule, "pending_provider_observation", side_effect=spy):
        yield drained


def _refusal_patches(case: str, instruction):
    if case == "unavailable":
        return [mock.patch.object(cobra_solve, "binding_available", return_value=False)]
    if case == "unchanged":
        return [
            mock.patch.object(
                cobra_solve, "solve_signature", return_value=SolveResult(SolveStatus.UNCHANGED)
            )
        ]
    if case == "accept_refusal":
        return [mock.patch.object(cobra_solve, "accept_rewrite", return_value=False)]
    if case == "refuted":
        return [mock.patch.object(cobra_solve, "prove_equivalent", return_value=ProofResult.REFUTED)]
    if case == "timeout":
        return [mock.patch.object(cobra_solve, "prove_equivalent", return_value=ProofResult.UNKNOWN)]
    if case == "reconstruction":
        return [
            mock.patch.object(
                cobra_solve,
                "build_replacement",
                side_effect=ReconstructionError("test reconstruction failure"),
            )
        ]
    if case == "rejected":
        # A replacement identical to the input: CoBRA reports an improvement,
        # and d810's outer optimizer, seeing no change, declines to apply it.
        return [
            mock.patch.object(
                cobra_solve,
                "build_replacement",
                side_effect=lambda *_args, **_kwargs: ida_hexrays.minsn_t(instruction),
            )
        ]
    raise AssertionError(case)


@pytest.mark.usefixtures("ida_database")
class TestCobraProviderPublication:
    """``mop_t``/``minsn_t`` construction segfaults without an open database."""

    binary_name = _get_default_binary()

    @pytest.mark.parametrize(
        ("case", "expected_status"),
        [
            ("unavailable", "unavailable"),
            ("unchanged", "unchanged"),
            ("accept_refusal", "unchanged"),
            ("refuted", "proof_failed"),
            ("timeout", "over_budget"),
            ("reconstruction", "reconstruction_failed"),
            ("rejected", "improved"),
        ],
    )
    def test_refused_outcome_publishes_one_attributed_attempt(
        self, tmp_path: Path, case: str, expected_status: str
    ) -> None:
        assert ida_hexrays.init_hexrays_plugin()
        instruction = _mba_instruction()
        # The sink owns the store and closes it on cleanup, so every store
        # assertion happens inside the activation.
        store = MbaDiscoveryStore(tmp_path / f"{case}.sqlite3")
        with _real_cobra_rule(store) as rule, contextlib.ExitStack() as patches:
            for patch in _refusal_patches(case, instruction):
                patches.enter_context(patch)
            optimizer = _Optimizer([RUNTIME_MATURITY], stats=None)
            optimizer.add_rule(rule)
            with _drained_observations(rule) as drained, native_mba_callback_scope():
                assert _manager(optimizer).optimize(_block(), instruction) is False

            assert len(drained) == 1
            assert drained[0].outcome.status.value == expected_status
            snapshots = store.provider_attempt_snapshots()
            assert len(snapshots) == 1
            attempt = snapshots[0].attempt
            assert attempt.outcome.status.value == expected_status
            assert attempt.outcome.provider.value == "coefficient_solver"
            assert attempt.context.plugin_identity.name == "cobra"
            assert attempt.context.plugin_identity.distribution == "d810-cobra"
            assert attempt.context.plugin_identity.version == COBRA_VERSION
            assert attempt.context.instruction_ea == INSTRUCTION_EA
            assert attempt.context.block_serial == BLOCK_SERIAL
            assert attempt.outcome.input_cost is not None

    def test_accepted_rewrite_is_applied_without_residual_row(self, tmp_path: Path) -> None:
        assert ida_hexrays.init_hexrays_plugin()
        instruction = _mba_instruction()
        before = instruction.dstr()
        store = MbaDiscoveryStore(tmp_path / "accepted.sqlite3")
        with _real_cobra_rule(store) as rule:
            optimizer = _Optimizer([RUNTIME_MATURITY], stats=None)
            optimizer.add_rule(rule)
            with _drained_observations(rule) as drained, native_mba_callback_scope():
                assert _manager(optimizer).optimize(_block(), instruction) is True

            assert len(drained) == 1
            assert drained[0].outcome.status.value == "applied"
            assert store.provider_attempt_snapshots() == ()
        assert instruction.dstr() != before
