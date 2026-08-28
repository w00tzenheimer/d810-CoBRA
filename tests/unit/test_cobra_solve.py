"""Solver-layer tests, including binding-vs-CLI parity.

The binding is the production path; cobra-cli is kept as an independent oracle.
Both are optional, so every test that needs one skips cleanly when it is
absent -- a machine without CoBRA must behave exactly like one where the
feature is off.
"""

from __future__ import annotations

import dataclasses
import unittest
from types import SimpleNamespace
from unittest import mock

import pytest

from d810_cobra.expr import (
    evaluate,
    node_count,
    parse_cobra_output,
    signature_of,
)
from d810_cobra.probe import find_cobra_cli
from d810_cobra.solve import (
    SolveResult,
    SolveStatus,
    binding_available,
    solve_expression,
    solve_signature,
)

try:
    from d810_cobra.rules import cobra_solve
    from d810_cobra.rules.cobra_solve import CobraSolveRule
    from d810.mba.extension_api import NativeMbaCandidate
    from d810.mba.island_profile import profile_typed_term
    from d810.mba.semantic_canonicalization import canonicalize_mba_term
    from d810.mba.typed_term import TypedBvTerm
except ModuleNotFoundError as exc:
    if exc.name != "ida_hexrays":
        raise
    cobra_solve = None
    CobraSolveRule = None

_MASK32 = 0xFFFFFFFF


def _tree(text: str, names: list[str]) -> dict:
    return parse_cobra_output(text, names)


class TestSignatureOf(unittest.TestCase):
    """The solver's actual input: no text, no AST marshalling."""

    def test_length_is_two_to_the_leaf_count(self):
        tree = _tree("x0 ^ x1", ["a", "b"])
        self.assertEqual(len(signature_of(tree, ["a", "b"], 32)), 4)

    def test_entries_are_the_expression_at_each_assignment(self):
        # x0 ^ x1 over (0,0) (1,0) (0,1) (1,1) -- bit i of the index is leaf i.
        self.assertEqual(signature_of(_tree("x0 ^ x1", ["a", "b"]), ["a", "b"], 32),
                         [0, 1, 1, 0])

    def test_entries_are_masked_to_bitwidth(self):
        tree = _tree("-x0", ["a"])
        self.assertEqual(signature_of(tree, ["a"], 8), [0, 0xFF])

    def test_solve_result_accepts_foreign_generation_status_by_value(self):
        """Reloaded D810/CoBRA enum classes must not require identity matches."""
        class ForeignStatus:
            value = SolveStatus.SOLVED.value

        self.assertTrue(SolveResult(ForeignStatus()).solved)


@unittest.skipUnless(binding_available(), "CoBRA binding not built")
class TestSolveSignature(unittest.TestCase):
    def test_solves_a_known_identity(self):
        tree = _tree("(x0 | x1) - (x0 & x1)", ["a", "b"])
        result = solve_signature(tree, ["a", "b"], 32)

        self.assertIs(result.status, SolveStatus.SOLVED)
        self.assertIsNotNone(result.tree)
        for a in (0, 1, 0x5A5A5A5A, _MASK32):
            for b in (0, 1, 0xA5A5A5A5, _MASK32):
                self.assertEqual(
                    evaluate(result.tree, {"a": a, "b": b}, _MASK32), a ^ b
                )

    def test_result_is_smaller_than_the_input(self):
        tree = _tree("(x0 | x1) - (x0 & x1)", ["a", "b"])
        result = solve_signature(tree, ["a", "b"], 32)
        self.assertLess(node_count(result.tree), node_count(tree))

    def test_identity_input_reports_unchanged_not_solved(self):
        # The solver only sees a signature, so it cannot judge "unchanged" --
        # it has no input to compare against, and returns Variable(0) here.
        # solve_signature compares for it; without that this looked SOLVED.
        tree = _tree("x0", ["a"])
        result = solve_signature(tree, ["a"], 32)
        self.assertIs(result.status, SolveStatus.UNCHANGED)
        self.assertIsNone(result.tree)

    def test_signature_length_cannot_mismatch(self):
        # solve_signature derives the signature from leaf_names itself, so the
        # binding's length check is unreachable through it. Naming more leaves
        # than the tree uses is legal: the extra ones are simply free.
        result = solve_signature(_tree("x0", ["a"]), ["a", "b"], 32)
        self.assertIn(result.status, (SolveStatus.SOLVED, SolveStatus.UNCHANGED))

    def test_unevaluable_tree_is_a_result_not_an_exception(self):
        # A leaf the caller did not declare: evaluation raises, and the layer
        # must turn that into a skip rather than let it reach the pipeline.
        orphan = {"kind": "var", "name": "never_declared"}
        result = solve_signature(orphan, ["a"], 32)
        self.assertIs(result.status, SolveStatus.FAILED)
        self.assertIn("could not evaluate", result.reason)

    def test_bad_bitwidth_is_a_result_not_an_exception(self):
        result = solve_signature(_tree("x0 ^ x1", ["a", "b"]), ["a", "b"], 7)
        self.assertIs(result.status, SolveStatus.FAILED)
        self.assertTrue(result.reason)


@unittest.skipUnless(
    binding_available() and find_cobra_cli().available,
    "needs both the binding and cobra-cli",
)
class TestBindingCliParity(unittest.TestCase):
    """cobra-cli is the independent oracle for the native path."""

    CASES = (
        ("(x0 | x1) - (x0 & x1)", ["a", "b"], 32),
        ("(x0 + x1) - (x0 & x1)", ["a", "b"], 32),
        ("(x0 ^ x1) + 2 * (x0 & x1)", ["a", "b"], 32),
        ("~(x0 | x1) + x0 + x1", ["a", "b"], 32),
    )

    def test_both_paths_agree_semantically(self):
        probe = find_cobra_cli()
        for text, names, bits in self.CASES:
            with self.subTest(expression=text):
                tree = _tree(text, names)

                native = solve_signature(tree, names, bits)
                cli = solve_expression(probe, text, bits, names)

                # They may print differently; they must not disagree on value.
                mask = (1 << bits) - 1
                for i in range(64):
                    values = {n: (i * 0x9E3779B9 + j) & mask
                              for j, n in enumerate(names)}
                    expected = evaluate(tree, values, mask)
                    if native.tree is not None:
                        self.assertEqual(
                            evaluate(native.tree, values, mask), expected
                        )
                    if cli.tree is not None:
                        self.assertEqual(evaluate(cli.tree, values, mask), expected)


@pytest.mark.skipif(CobraSolveRule is None, reason="IDA runtime is required")
class TestProviderOutcomePublication:
    def _rule(self):
        raw = TypedBvTerm(
            "sub",
            32,
            children=(
                TypedBvTerm("or", 32, children=(TypedBvTerm(None, 32, leaf_key=("a",)), TypedBvTerm(None, 32, leaf_key=("b",)))),
                TypedBvTerm("and", 32, children=(TypedBvTerm(None, 32, leaf_key=("a",)), TypedBvTerm(None, 32, leaf_key=("b",)))),
            ),
        )
        canonical = canonicalize_mba_term(raw).canonical_term
        profile = dataclasses.replace(
            profile_typed_term(raw),
            fingerprint=cobra_solve.term_fingerprint(canonical),
        )
        candidate = NativeMbaCandidate(
            destination_size=4,
            term=canonical,
            raw_term=raw,
            profile=profile,
            native_context=object(),
        )

        class Host:
            def capture_instruction(self, _ins):
                return candidate

        rule = CobraSolveRule()
        rule.bind_mba_host(Host())
        rule.require_proof = True
        rule._ensure_store = lambda: None
        return rule, SimpleNamespace(ea=0x401000)

    @staticmethod
    def _builder(*, unsupported=False, non_mba=False):
        tree = {"kind": "var", "name": "a"} if non_mba else {
            "kind": "bin",
            "op": "-",
            "a": {"kind": "bin", "op": "|", "a": {"kind": "var", "name": "a"}, "b": {"kind": "var", "name": "b"}},
            "b": {"kind": "bin", "op": "&", "a": {"kind": "var", "name": "a"}, "b": {"kind": "var", "name": "b"}},
        }

        class Snapshot:
            size = 4

        class Builder:
            snapshots = {"a": Snapshot(), "b": Snapshot()}

            def instruction(self, _ins):
                if unsupported:
                    raise cobra_solve.UnsupportedMicrocode
                return tree

        return Builder()

    def _run(self, result, *, accept=True, proof=None):
        rule, ins = self._rule()
        ins.d = SimpleNamespace(size=4)
        proof = proof or cobra_solve.ProofResult.PROVED
        with mock.patch.object(cobra_solve, "_TreeBuilder", return_value=self._builder()), \
             mock.patch.object(cobra_solve, "binding_available", return_value=True), \
             mock.patch.object(cobra_solve, "solve_signature", return_value=result), \
             mock.patch.object(cobra_solve, "accept_rewrite", return_value=accept), \
             mock.patch.object(cobra_solve, "prove_equivalent", return_value=proof), \
             mock.patch.object(cobra_solve, "build_replacement", return_value=object()):
            replacement = rule.check_and_replace(None, ins)
        return rule, replacement

    def test_unavailable_solver_is_one_terminal_attempt(self):
        rule, ins = self._rule()
        ins.d = SimpleNamespace(size=4)
        with mock.patch.object(cobra_solve, "_TreeBuilder", return_value=self._builder()), \
             mock.patch.object(cobra_solve, "binding_available", return_value=False):
            self.assertIsNone(rule.check_and_replace(None, ins))
        pending = rule.pending_provider_observation()
        assert pending is not None
        assert (
            pending.outcome.status.value
            == cobra_solve.ProviderOutcomeStatus.UNAVAILABLE.value
        )
        assert pending.outcome.refusal_reason == "solver_unavailable"
        assert rule.pending_provider_observation() is None

    @pytest.mark.parametrize(
        ("result", "accept", "proof", "status", "reason"),
        [
            (SolveResult(SolveStatus.UNCHANGED), True, None, "unchanged", "no_rewrite"),
            (SolveResult(SolveStatus.FAILED, reason="boom"), True, None, "error", "solver_failed"),
            (SolveResult(SolveStatus.SOLVED, tree={"kind": "var", "name": "leaf_0"}), False, None, "unchanged", "accept_refused"),
            (SolveResult(SolveStatus.SOLVED, tree={"kind": "var", "name": "leaf_0"}), True, "refuted", "proof_failed", "proof_refuted"),
            (SolveResult(SolveStatus.SOLVED, tree={"kind": "var", "name": "leaf_0"}), True, "unknown", "over_budget", "proof_timeout_escalated"),
        ],
    )
    def test_terminal_gate_is_published_once(self, result, accept, proof, status, reason):
        rule, _replacement = self._run(
            result,
            accept=accept,
            proof=(getattr(cobra_solve.ProofResult, proof.upper()) if proof else None),
        )
        pending = rule.pending_provider_observation()
        assert pending is not None
        assert pending.outcome.status.value == status
        assert pending.outcome.refusal_reason == reason
        assert rule.pending_provider_observation() is None

    def test_outer_acceptance_upgrades_improved_attempt_to_applied(self):
        rule, replacement = self._run(
            SolveResult(SolveStatus.SOLVED, tree={"kind": "var", "name": "leaf_0"}),
            proof=cobra_solve.ProofResult.PROVED,
        )
        assert replacement is not None
        rule.record_mutation_accepted()
        pending = rule.pending_provider_observation()
        assert pending is not None
        assert pending.outcome.status.value == "applied"

    def test_outer_rejection_retains_improvement_reason(self):
        rule, replacement = self._run(
            SolveResult(SolveStatus.SOLVED, tree={"kind": "var", "name": "leaf_0"}),
            proof=cobra_solve.ProofResult.PROVED,
        )
        assert replacement is not None
        rule.record_mutation_rejected("outer_rejected")
        pending = rule.pending_provider_observation()
        assert pending is not None
        assert pending.outcome.status.value == "improved"
        assert pending.outcome.refusal_reason == "outer_rejected"

    def test_unsupported_candidate_creates_no_attempt(self):
        rule, ins = self._rule()
        ins.d = SimpleNamespace(size=4)
        with mock.patch.object(cobra_solve, "_TreeBuilder", return_value=self._builder(unsupported=True)), \
             mock.patch.object(cobra_solve, "binding_available", return_value=False):
            assert rule.check_and_replace(None, ins) is None
        assert rule.pending_provider_observation() is None

    def test_captured_leaf_budget_refusal_is_published_and_drained(self):
        """Capture must own the attempt before local eligibility can refuse it."""
        rule, ins = self._rule()
        rule.max_leaves = 1
        ins.d = SimpleNamespace(size=4)
        with mock.patch.object(cobra_solve, "_TreeBuilder", return_value=self._builder()), \
             mock.patch.object(cobra_solve, "binding_available", return_value=False):
            assert rule.check_and_replace(None, ins) is None

        pending = rule.pending_provider_observation()
        assert pending is not None
        assert pending.outcome.status.value == "ineligible"
        assert pending.outcome.refusal_reason == "leaf_budget"
        assert pending.raw_term is not None
        assert pending.canonical_term is not None
        assert rule.pending_provider_observation() is None

    def test_non_mba_candidate_creates_no_attempt(self):
        rule, ins = self._rule()
        ins.d = SimpleNamespace(size=4)
        with mock.patch.object(cobra_solve, "_TreeBuilder", return_value=self._builder(non_mba=True)), \
             mock.patch.object(cobra_solve, "binding_available", return_value=False):
            assert rule.check_and_replace(None, ins) is None
        assert rule.pending_provider_observation() is None

    def test_existing_reconstruction_runs_once_without_native_host_prove(self):
        rule = CobraSolveRule()
        host = SimpleNamespace(prove=mock.Mock(side_effect=AssertionError("must not call")))
        rule.bind_mba_host(host)
        candidate = SimpleNamespace(node_count=3)
        ins = SimpleNamespace(ea=0x401000)
        rewrite = {"kind": "var", "name": "a"}
        expected = object()
        with mock.patch.object(cobra_solve, "build_replacement", return_value=expected) as build:
            assert rule._install(candidate, rewrite, ins) is expected
        build.assert_called_once_with(candidate, rewrite, ins)
        host.prove.assert_not_called()


if __name__ == "__main__":
    unittest.main()
