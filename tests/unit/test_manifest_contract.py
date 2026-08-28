"""The contract d810 relies on, checked from this side of the boundary.

These moved out of d810's ``tests/unit/core/test_plugins.py`` when the backend
was extracted. d810 keeps the *generic* protocol tests (a probe that returns a
reason marks the backend unavailable, and so on) against fake backends; what
belongs here is whether THIS package satisfies that protocol.

Deliberately no import of ``d810.core.plugins``: the manifest must stay
readable by a d810 that predates the plugin protocol, so these assertions
describe its shape directly rather than round-tripping it through d810's
coercion.
"""

from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest import mock

import d810_cobra as pkg


class TestManifestShape(unittest.TestCase):
    def test_declares_the_three_required_fields(self):
        for key in ("name", "api_version", "provides"):
            self.assertIn(key, pkg.MANIFEST)

    def test_name_matches_the_entry_point(self):
        """pyproject registers `cobra = ...`; a mismatch here is invisible."""
        self.assertEqual(pkg.MANIFEST["name"], "cobra")

    def test_api_version_is_an_int(self):
        self.assertIsInstance(pkg.MANIFEST["api_version"], int)

    def test_provides_is_the_lazy_plugin_target(self):
        """A callable would be resolved eagerly during discovery.

        The point of the string form is that an incompatible d810 rejects this
        backend after reading three fields, without importing solve.py and
        therefore without loading the compiled extension.
        """
        self.assertEqual(pkg.MANIFEST["provides"], "d810_cobra.plugin:PLUGIN")

    def test_manifest_uses_api_one_declaration_without_rules(self):
        self.assertNotIn("rules", pkg.MANIFEST)
        self.assertEqual(
            pkg.MANIFEST["requires"],
            ("d810.mba.residual-observation.v1",),
        )
        self.assertEqual(pkg.MANIFEST["implements"], {"mba-solve": "cobra-solve"})


class TestPluginActivation(unittest.TestCase):
    def test_plugin_probe_preserves_binding_availability(self):
        plugin = __import__("d810_cobra.plugin", fromlist=["PLUGIN"])
        with mock.patch("d810_cobra.solve.d810_backend_probe", return_value="missing binding"):
            self.assertEqual(plugin.PLUGIN.d810_backend_probe(), "missing binding")

    def test_plugin_is_resolved_lazily_and_activation_creates_only_cobra_rule(self):
        plugin = __import__("d810_cobra.plugin", fromlist=["PLUGIN"])
        class FakeRule:
            pass

        context = SimpleNamespace(identity="identity", host="host")
        with mock.patch.object(plugin, "_load_rule_class", return_value=FakeRule), \
             mock.patch.object(plugin, "_native_host_services", return_value=object()):
            activation = plugin.PLUGIN.activate(context)
            first = activation.create_implementation("cobra-solve")
            second = activation.create_implementation("cobra-solve")

        self.assertIsInstance(first, FakeRule)
        self.assertIsInstance(second, FakeRule)
        self.assertIsNot(first, second)
        self.assertEqual(activation.capability_offers(), ())
        with self.assertRaises(ValueError):
            activation.create_implementation("other")

    def test_activation_close_is_idempotent_and_continues_after_failures(self):
        plugin = __import__("d810_cobra.plugin", fromlist=["PLUGIN"])
        calls = []

        class FakeEscalator:
            def stop(self):
                calls.append("stop")
                raise RuntimeError("stop failed")

        class FakeRule:
            def __init__(self):
                self.escalator = FakeEscalator()

            def bind_plugin_services(self, services):
                pass

            def stop_escalator(self):
                self.escalator.stop()

            def flush_store(self):
                calls.append("flush")

            def close_store(self):
                calls.append("close")

        context = SimpleNamespace(identity="identity", host="host")
        with mock.patch.object(plugin, "_load_rule_class", return_value=FakeRule), \
             mock.patch.object(plugin, "_native_host_services", return_value=object()):
            activation = plugin.PLUGIN.activate(context)
            activation.create_implementation("cobra-solve")
            activation.create_implementation("cobra-solve")
            activation.close()
            activation.close()

        self.assertEqual(calls, ["stop", "flush", "close", "stop", "flush", "close"])


if __name__ == "__main__":
    unittest.main()
