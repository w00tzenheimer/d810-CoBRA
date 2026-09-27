"""Retry expired CoBRA simplifications on copied data outside Hex-Rays."""

from __future__ import annotations

import copy
import queue
import threading

from d810.core import getLogger
from d810_cobra.expr import accept_rewrite
from d810_cobra.prove import DEFAULT_TIMEOUT_MS, ProofResult, prove_equivalent
from d810_cobra.solve import SolveStatus, solve_signature
from d810_cobra.table import RewriteTable

logger = getLogger(__name__)

DEFAULT_MAX_QUEUE = 512
DEFAULT_SOLVE_TIMEOUT_MS = 30_000


class DeferredSolver:
    """Solve and prove expired expressions without touching IDA objects."""

    def __init__(
        self,
        table: RewriteTable,
        *,
        solve_timeout_ms: int = DEFAULT_SOLVE_TIMEOUT_MS,
        proof_timeout_ms: int = DEFAULT_TIMEOUT_MS,
        max_queue: int = DEFAULT_MAX_QUEUE,
    ) -> None:
        self._table = table
        self._solve_timeout_ms = solve_timeout_ms
        self._proof_timeout_ms = proof_timeout_ms
        self._queue: queue.Queue = queue.Queue(maxsize=max_queue)
        self._lock = threading.RLock()
        self._stopping = threading.Event()
        self._thread: threading.Thread | None = None
        self._settled = 0

    def start(self) -> None:
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._stopping.clear()
            self._thread = threading.Thread(
                target=self._run, name="cobra-deferred-solve", daemon=True
            )
            self._thread.start()

    def configure_timeout(self, timeout_ms: int) -> None:
        if type(timeout_ms) is not int or timeout_ms <= 0:
            raise ValueError("deferred solve timeout must be positive")
        with self._lock:
            self._solve_timeout_ms = timeout_ms

    def stop(self, timeout: float = 2.0) -> None:
        with self._lock:
            thread = self._thread
            if thread is None:
                return
            self._stopping.set()
            while True:
                try:
                    item = self._queue.get_nowait()
                except queue.Empty:
                    break
                if item is not None:
                    self._table.clear_pending(item[0], item[2])
                self._queue.task_done()
            if thread.is_alive():
                self._queue.put_nowait(None)
        thread.join(timeout)
        if thread.is_alive():
            logger.warning("CoBRA deferred solver still finishing a native pass")
        else:
            with self._lock:
                if self._thread is thread:
                    self._thread = None

    def submit(
        self,
        tree: dict,
        leaf_names: tuple[str, ...],
        bitwidth: int,
        *,
        max_vars: int = 16,
    ) -> bool:
        with self._lock:
            if (self._thread is None or not self._thread.is_alive()
                    or self._stopping.is_set() or self._queue.full()
                    or self._table.lookup(tree, bitwidth) is not None):
                return False
            owned = copy.deepcopy(tree)
            self._table.record_pending(owned, bitwidth)
            self._queue.put_nowait((owned, tuple(leaf_names), bitwidth, max_vars))
            return True

    def take_settled(self) -> int:
        """Return completions for a main-thread store flush."""
        with self._lock:
            result = self._settled
            self._settled = 0
            return result

    def _run(self) -> None:
        try:
            import z3
            context = z3.Context()
        except ImportError:
            context = None
        while True:
            item = self._queue.get()
            if item is None:
                self._queue.task_done()
                return
            tree, leaf_names, bitwidth, max_vars = item
            try:
                result = solve_signature(
                    tree, leaf_names, bitwidth, max_vars=max_vars,
                    time_limit_ms=self._solve_timeout_ms,
                )
                if self._stopping.is_set():
                    self._table.clear_pending(tree, bitwidth)
                elif (getattr(result.status, "value", None) == SolveStatus.SOLVED.value
                      and result.tree is not None
                      and accept_rewrite(tree, result.tree)):
                    kwargs = {"timeout_ms": self._proof_timeout_ms}
                    if context is not None:
                        kwargs["ctx"] = context
                    proof = prove_equivalent(
                        tree, result.tree, leaf_names, bitwidth, **kwargs
                    )
                    if (not self._stopping.is_set()
                            and getattr(proof, "value", None) == ProofResult.PROVED.value):
                        self._table.record_proved(
                            tree, bitwidth, result.tree, proof_verified=True
                        )
                        with self._lock:
                            self._settled += 1
                    else:
                        self._table.clear_pending(tree, bitwidth)
                elif (getattr(result.status, "value", None) == SolveStatus.UNCHANGED.value
                      and not result.expired):
                    self._table.record_no_rewrite(tree, bitwidth)
                    with self._lock:
                        self._settled += 1
                else:
                    self._table.clear_pending(tree, bitwidth)
            except Exception:
                logger.exception("CoBRA deferred solve failed")
                self._table.clear_pending(tree, bitwidth)
            finally:
                self._queue.task_done()


__all__ = ["DeferredSolver"]
