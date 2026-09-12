"""IDA-runtime coverage for CoBRA's D810-owned residual publication seam."""

# ``ida_hexrays`` is intentionally imported before D810's IDA-coupled modules
# so local collection reports one skip when the native runtime is unavailable.
# ruff: noqa: E402

from __future__ import annotations

import dataclasses
import os
import platform
from collections import defaultdict
from types import SimpleNamespace
from unittest import mock

import pytest

ida_hexrays = pytest.importorskip("ida_hexrays")

from d810.capabilities.plugin_host import PluginHostCapabilityRegistry
from d810.core.function_execution_identity import (
    FunctionExecutionIdentity,
    MbaObservationContext,
)
from d810.core.plugins import (
    PluginActivationContext,
    PluginIdentity,
    PluginRuleServices,
)
from d810.mba.discovery_store import MbaDiscoveryStore
from d810.mba.extension_api import (
    D810_MBA_RESIDUAL_OBSERVATION_CAPABILITY,
    MbaResidualObservationSink,
    NativeMbaCandidate,
)
from d810.mba.island_profile import profile_typed_term
from d810_cobra.prove import ProofResult
from d810_cobra.solve import SolveResult, SolveStatus
from d810_cobra.convert import ReconstructionError
from d810.mba.semantic_canonicalization import canonicalize_mba_term
from d810.mba.residual_observation_sink import SqliteMbaResidualObservationSink
from d810.mba.typed_term import TypedBvTerm, term_cost, term_fingerprint
from d810.optimizers.microcode.instructions.handler import InstructionOptimizer
from d810.hexrays.hooks import optinsn_adapter
from d810.hexrays.hooks.optinsn_adapter import InstructionOptimizerManager

from d810_cobra.plugin import PLUGIN
from d810_cobra.rules import cobra_solve


def _get_default_binary() -> str:
    override = os.environ.get("D810_TEST_BINARY")
    if override:
        return override
    return (
        "libobfuscated.dylib" if platform.system() == "Darwin" else "libobfuscated.dll"
    )


class _Optimizer(InstructionOptimizer):
    RULE_CLASSES = [object]

    def add_rule(self, rule):
        self.rules.add(rule)
        return True


def _manager_for(optimizer):
    manager = InstructionOptimizerManager.__new__(InstructionOptimizerManager)
    manager.current_maturity = ida_hexrays.MMAT_PREOPTIMIZED
    manager._active_optimizers = [optimizer]
    manager._last_optimizer_tried = None
    manager._rewrite_seen = defaultdict(set)
    manager._cycle_quarantined_rule_names = defaultdict(set)
    manager._scheduled_implementation_names = frozenset()
    manager._resolve_active_instruction_rule_names = lambda _blk: None
    manager._residual_admission_cache_key = None
    manager._residual_admission_cache_value = False
    manager.analyzer = SimpleNamespace(analyze=lambda _blk, _ins: None)
    manager.stats = None
    manager.generate_z3_code = False
    manager.mba_observation_context = lambda _blk, _ins, identity: _context(identity)
    return manager


def _context(identity: PluginIdentity) -> MbaObservationContext:
    function_identity = FunctionExecutionIdentity(
        input_identity="idb-local:12345678-1234-5678-1234-567812345678",
        input_identity_provenance="current_idb",
        external_evidence_allowed=False,
        database_uuid="12345678-1234-5678-1234-567812345678",
        database_identity="cobra-task9",
        function_ea=0x401000,
        function_rva=0x1000,
        function_fingerprint="cobra-task9-function",
        decompilation_session_id="12345678-1234-5678-1234-567812345679",
        top_level_epoch=1,
        maturity="ir.canonical",
        evidence_generation=1,
    )
    return MbaObservationContext(
        function_identity=function_identity,
        plugin_identity=identity,
        instruction_ea=0x401002,
        block_serial=7,
        block_ea=0x401000,
    )


def _candidate():
    raw = TypedBvTerm(
        "sub",
        32,
        children=(
            TypedBvTerm(
                "or",
                32,
                children=(
                    TypedBvTerm(None, 32, leaf_key=("a",)),
                    TypedBvTerm(None, 32, leaf_key=("b",)),
                ),
            ),
            TypedBvTerm(
                "and",
                32,
                children=(
                    TypedBvTerm(None, 32, leaf_key=("a",)),
                    TypedBvTerm(None, 32, leaf_key=("b",)),
                ),
            ),
        ),
    )
    canonical = canonicalize_mba_term(raw).canonical_term
    profile = dataclasses.replace(
        profile_typed_term(raw), fingerprint=term_fingerprint(canonical)
    )
    return NativeMbaCandidate(
        destination_size=4,
        term=canonical,
        raw_term=raw,
        profile=profile,
        native_context=object(),
    )


class _Snapshot:
    size = 4


class _Builder:
    snapshots = {"a": _Snapshot(), "b": _Snapshot()}
    # Mirrors detect._TreeBuilder: every operand and the destination are 4
    # bytes, so the rule stays on its same-width path and never width-lifts.
    source_widths = {4}

    def instruction(self, _instruction):
        return {
            "kind": "bin",
            "op": "-",
            "a": {
                "kind": "bin",
                "op": "|",
                "a": {"kind": "var", "name": "a"},
                "b": {"kind": "var", "name": "b"},
            },
            "b": {
                "kind": "bin",
                "op": "&",
                "a": {"kind": "var", "name": "a"},
                "b": {"kind": "var", "name": "b"},
            },
        }


def _runtime_rule():
    store = MbaDiscoveryStore(":memory:")
    sink = SqliteMbaResidualObservationSink(store)
    host = PluginHostCapabilityRegistry()
    host.register(
        D810_MBA_RESIDUAL_OBSERVATION_CAPABILITY,
        MbaResidualObservationSink,
        sink,
        activation_binder=sink.bind_activation,
    )
    identity = PluginIdentity("cobra", "d810-cobra", "1.0", "task9-runtime")
    activation_host = host.view_for(
        (D810_MBA_RESIDUAL_OBSERVATION_CAPABILITY,), identity
    )
    activation = PLUGIN.activate(PluginActivationContext(identity, activation_host))
    rule = activation.create_implementation("cobra-solve")
    rule.bind_plugin_services(PluginRuleServices(identity, activation_host))
    candidate = _candidate()
    replacement = ida_hexrays.minsn_t(0x401002)
    replacement.opcode = ida_hexrays.m_mov
    rule._ensure_store = lambda: None
    optimizer = _Optimizer([ida_hexrays.MMAT_PREOPTIMIZED], stats=None)
    rule.maturities = [ida_hexrays.MMAT_PREOPTIMIZED]
    optimizer.add_rule(rule)
    block = SimpleNamespace(
        mba=SimpleNamespace(
            maturity=ida_hexrays.MMAT_PREOPTIMIZED,
            entry_ea=0x401000,
        ),
        serial=7,
    )
    instruction = ida_hexrays.minsn_t(0x401002)
    instruction.opcode = ida_hexrays.m_mov
    instruction.d.make_number(0, 4)
    return store, activation, rule, optimizer, block, instruction, identity, candidate, replacement


@pytest.mark.usefixtures("ida_database")
class TestCobraProviderPublication:
    """``mop_t``/``minsn_t`` construction segfaults without an open database."""

    binary_name = _get_default_binary()

    @pytest.mark.parametrize(
        ("case", "expected_status", "expected_rows"),
        [
            ("unavailable", "unavailable", 1),
            ("unchanged", "unchanged", 1),
            ("accept_refusal", "unchanged", 1),
            ("refuted", "proof_failed", 1),
            ("timeout", "over_budget", 1),
            ("reconstruction", "reconstruction_failed", 1),
            ("rejected", "improved", 1),
            ("accepted", None, 0),
        ],
    )
    def test_cobra_gates_publish_through_real_outer_lifecycle(self, 
        case, expected_status, expected_rows
    ):
        (
            store,
            activation,
            rule,
            optimizer,
            block,
            instruction,
            identity,
            candidate,
            replacement,
        ) = _runtime_rule()
        proof = ProofResult.PROVED
        solve_result = SolveResult(
            SolveStatus.SOLVED,
            tree={"kind": "var", "name": "a"},
        )
        binding = True
        accept = True
        if case == "unavailable":
            binding = False
        elif case == "unchanged":
            solve_result = SolveResult(SolveStatus.UNCHANGED)
        elif case == "accept_refusal":
            accept = False
        elif case == "refuted":
            proof = ProofResult.REFUTED
        elif case == "timeout":
            proof = ProofResult.UNKNOWN

        build = mock.patch.object(cobra_solve, "build_replacement", return_value=replacement)
        if case == "reconstruction":
            build = mock.patch.object(
                cobra_solve,
                "build_replacement",
                side_effect=ReconstructionError("test reconstruction failure"),
            )
        manager = _manager_for(optimizer)
        hash_values = iter((1, 1) if case == "rejected" else (1, 2))
        with mock.patch.object(cobra_solve, "_TreeBuilder", return_value=_Builder()), \
             mock.patch.object(cobra_solve, "binding_available", return_value=binding), \
             mock.patch.object(cobra_solve, "solve_signature", return_value=solve_result), \
             mock.patch.object(cobra_solve, "accept_rewrite", return_value=accept), \
             mock.patch.object(cobra_solve, "prove_equivalent", return_value=proof), \
             mock.patch.object(rule._mba_host, "capture_instruction", return_value=candidate), \
             build, \
             mock.patch.object(rule, "pending_provider_observation", wraps=rule.pending_provider_observation) as drain, \
             mock.patch.object(optinsn_adapter, "check_ins_mop_size_are_ok", return_value=True), \
             mock.patch.object(optinsn_adapter, "count_minsn_nodes", return_value=1), \
             mock.patch.object(optinsn_adapter, "hash_minsn", side_effect=lambda *_args: next(hash_values)):
            result = manager.optimize(block, instruction)
            if case == "rejected":
                assert result is False
            elif case == "accepted":
                assert result is True
            else:
                assert result is False
        assert drain.call_count == 1

        # No public store query exposes provider attribution; this test-only SQL
        # assertion is deliberately limited to the row emitted by the real sink.
        rows = store._connection.execute(
            """SELECT pa.provider, pa.plugin_name, pa.status,
                      pa.input_cost_ops, pa.input_cost_nodes,
                      t.canonical_fingerprint, rt.raw_fingerprint
                 FROM provider_attempts pa
                 JOIN terms t ON t.term_id = pa.term_id
                 JOIN raw_terms rt ON rt.raw_term_id = pa.raw_term_id"""
        ).fetchall()
        assert len(rows) == expected_rows
        if expected_rows:
            assert rows[0][:3] == ("coefficient_solver", "cobra", expected_status)
            assert rows[0][3:5] == term_cost(candidate.term)
            assert rows[0][5] == term_fingerprint(candidate.term)
            assert rows[0][6] == term_fingerprint(candidate.raw_term)

        activation.close()
        store.close()
