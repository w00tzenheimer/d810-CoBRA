"""IDA-runtime coverage for CoBRA's D810-owned residual publication seam."""

# ``ida_hexrays`` is intentionally imported before D810's IDA-coupled modules
# so local collection reports one skip when the native runtime is unavailable.
# ruff: noqa: E402

from __future__ import annotations

import dataclasses
from types import SimpleNamespace

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
from d810.mba.provider_outcome import ProviderOutcomeStatus
from d810.mba.semantic_canonicalization import canonicalize_mba_term
from d810.mba.residual_observation_sink import SqliteMbaResidualObservationSink
from d810.mba.typed_term import TypedBvTerm, term_fingerprint
from d810.optimizers.microcode.instructions.handler import InstructionOptimizer

from d810_cobra.plugin import PLUGIN


class _Optimizer(InstructionOptimizer):
    RULE_CLASSES = [object]

    def add_rule(self, rule):
        self.rules.add(rule)
        return True


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


def test_cobra_rejection_publishes_one_attributed_sqlite_attempt():
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
    candidate = NativeMbaCandidate(
        destination_size=4,
        term=canonical,
        raw_term=raw,
        profile=profile,
        native_context=object(),
    )
    replacement = ida_hexrays.minsn_t(0x401002)
    replacement.opcode = ida_hexrays.m_mov

    def provider_callback(_blk, _ins):
        rule._begin_attempt(candidate)
        rule._finish_attempt(ProviderOutcomeStatus.IMPROVED)
        return replacement

    rule._check_and_replace = provider_callback
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
    assert optimizer.get_optimized_instruction(
        block,
        instruction,
        observation_context_factory=lambda *_args: _context(identity),
    ) is replacement
    optimizer.record_mutation_rejected("outer_rejected")

    # No public store query exposes provider attribution; this test-only SQL
    # assertion is deliberately limited to the row emitted by the real sink.
    rows = store._connection.execute(
        "SELECT provider, plugin_name, status FROM provider_attempts"
    ).fetchall()
    assert rows == [("coefficient_solver", "cobra", "improved")]
    assert len(rows) == 1

    activation.close()
    store.close()
