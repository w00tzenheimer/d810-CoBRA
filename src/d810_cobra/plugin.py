"""D810 API-1 plugin adapter for CoBRA.

The manifest points here rather than at the solver module so discovery remains
cheap and lazy.  The IDA-bound native host and every rule instance are owned
by one activation.
"""

from __future__ import annotations

from d810.core.plugins import BackendPlugin, PluginActivationContext


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
        bind_host = getattr(rule, "bind_mba_host", None)
        if callable(bind_host):
            bind_host(self._native_host)
        self._rules.append(rule)
        return rule

    def capability_offers(self) -> tuple[object, ...]:
        return ()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        for rule in tuple(self._rules):
            for method_name in ("stop_escalator", "flush_store", "close_store"):
                method = getattr(rule, method_name, None)
                if callable(method):
                    try:
                        method()
                    except Exception:
                        # One malformed cache or worker must not leak the rest
                        # of the activation's instances.
                        continue


class _CobraPlugin:
    def d810_backend_probe(self) -> str | None:
        """Keep binding availability visible during backend discovery."""

        from d810_cobra.solve import d810_backend_probe

        return d810_backend_probe()

    def activate(self, context: PluginActivationContext) -> _CobraActivation:
        return _CobraActivation(context)


PLUGIN: BackendPlugin = _CobraPlugin()


__all__ = ["PLUGIN"]
