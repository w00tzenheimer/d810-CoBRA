"""D810 API-1 plugin adapter for CoBRA.

The manifest points here rather than at the solver module so discovery remains
cheap and lazy.  The IDA-bound native host and every rule instance are owned
by one activation.
"""

from __future__ import annotations

import builtins

from d810.core.plugins import BackendPlugin, PluginActivationContext


class _FallbackBaseExceptionGroup(BaseException):
    """Minimal BaseException-group compatibility for Python 3.10."""

    def __init__(self, message: str, exceptions: list[BaseException]) -> None:
        super().__init__(message)
        self.exceptions = tuple(exceptions)


_BASE_EXCEPTION_GROUP = getattr(
    builtins, "BaseExceptionGroup", _FallbackBaseExceptionGroup
)


def _native_host_services():
    """Resolve the IDA-bound composition facade only during activation."""

    from d810.backends.mba.extension_host import native_mba_host_services

    return native_mba_host_services()


def _load_rule_class():
    """Resolve the IDA-coupled rule only when an implementation is requested."""

    from d810_cobra.rules.cobra_solve import CobraSolveRule

    return CobraSolveRule


class _CobraActivation:
    def __init__(self, context: PluginActivationContext) -> None:
        self._context = context
        self._native_host = _native_host_services()
        self._rules: list[object] = []
        self._closed = False

    def create_implementation(self, implementation_id: str) -> object:
        if implementation_id != "cobra-solve":
            raise ValueError(f"unsupported CoBRA implementation: {implementation_id!r}")
        if self._closed:
            raise RuntimeError("CoBRA activation is closed")
        rule = _load_rule_class()()
        try:
            bind_host = getattr(rule, "bind_mba_host", None)
            if callable(bind_host):
                bind_host(self._native_host)
        except BaseException as error:
            cleanup_errors = self._cleanup_rule(rule)
            if cleanup_errors:
                raise _BASE_EXCEPTION_GROUP(
                    "CoBRA implementation construction and cleanup failed",
                    [error, *cleanup_errors],
                )
            raise
        self._rules.append(rule)
        return rule

    def capability_offers(self) -> tuple[object, ...]:
        return ()

    @staticmethod
    def _cleanup_rule(rule: object) -> list[BaseException]:
        errors: list[BaseException] = []
        for method_name in ("stop_escalator", "flush_store", "close_store"):
            try:
                method = getattr(rule, method_name, None)
            except BaseException as exc:
                errors.append(exc)
                continue
            if not callable(method):
                continue
            try:
                method()
            except BaseException as exc:
                errors.append(exc)
        return errors

    def release_implementation(self, implementation: object) -> None:
        """Release one rule without closing its shared activation."""
        if self._closed:
            return
        for index, rule in enumerate(self._rules):
            if rule is implementation:
                del self._rules[index]
                break
        else:
            return
        errors = self._cleanup_rule(implementation)
        if errors:
            raise _BASE_EXCEPTION_GROUP("CoBRA implementation release failed", errors)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        rules = tuple(self._rules)
        self._rules.clear()
        errors: list[BaseException] = []
        for rule in rules:
            errors.extend(self._cleanup_rule(rule))
        self._context = None
        self._native_host = None
        if errors:
            raise _BASE_EXCEPTION_GROUP("CoBRA plugin close failed", errors)


class _CobraPlugin:
    def d810_backend_probe(self) -> str | None:
        """Keep binding availability visible during backend discovery."""

        from d810_cobra.solve import d810_backend_probe

        return d810_backend_probe()

    def activate(self, context: PluginActivationContext) -> _CobraActivation:
        return _CobraActivation(context)


PLUGIN: BackendPlugin = _CobraPlugin()


__all__ = ["PLUGIN"]
