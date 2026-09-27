"""Proof-gated background solving without IDA or a compiled binding."""

from __future__ import annotations

import unittest
from unittest.mock import patch

from d810_cobra.deferred_solve import DeferredSolver
from d810_cobra.prove import ProofResult
from d810_cobra.solve import SolveResult, SolveStatus
from d810_cobra.table import Outcome, RewriteTable


def var(name: str) -> dict:
    return {"kind": "var", "name": name}


def binary(op: str, left: dict, right: dict) -> dict:
    return {"kind": "bin", "op": op, "a": left, "b": right}


TREE = binary(
    "+", binary("&", var("a"), var("b")), binary("|", var("a"), var("b"))
)
REWRITE = binary("+", var("a"), var("b"))


class TestDeferredSolver(unittest.TestCase):
    def setUp(self) -> None:
        self.table = RewriteTable()

    def test_worker_proves_before_recording_rewrite(self) -> None:
        worker = DeferredSolver(self.table)
        with (
            patch(
                "d810_cobra.deferred_solve.solve_signature",
                return_value=SolveResult(SolveStatus.SOLVED, tree=REWRITE),
            ) as solve,
            patch(
                "d810_cobra.deferred_solve.prove_equivalent",
                return_value=ProofResult.PROVED,
            ) as prove,
        ):
            worker.start()
            try:
                self.assertTrue(worker.submit(TREE, ("a", "b"), 32))
                worker._queue.join()
                entry = self.table.lookup(TREE, 32)
                self.assertIsNotNone(entry)
                self.assertIs(entry.outcome, Outcome.PROVED)
                self.assertTrue(entry.proof_verified)
                self.assertEqual(entry.rewrite, REWRITE)
                self.assertEqual(worker.take_settled(), 1)
                solve.assert_called_once()
                prove.assert_called_once()
            finally:
                worker.stop()

    def test_expired_result_remains_retryable(self) -> None:
        worker = DeferredSolver(self.table)
        with patch(
            "d810_cobra.deferred_solve.solve_signature",
            return_value=SolveResult(SolveStatus.EXPIRED, expired=True),
        ):
            worker.start()
            try:
                self.assertTrue(worker.submit(TREE, ("a", "b"), 32))
                worker._queue.join()
                self.assertIsNone(self.table.lookup(TREE, 32))
                self.assertTrue(worker.submit(TREE, ("a", "b"), 32))
                worker._queue.join()
                self.assertIsNone(self.table.lookup(TREE, 32))
            finally:
                worker.stop()
