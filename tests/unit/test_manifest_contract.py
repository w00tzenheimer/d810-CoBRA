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
import threading
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
    def test_concurrent_exact_releases_do_not_orphan_or_double_clean(self):
        plugin = __import__("d810_cobra.plugin", fromlist=["PLUGIN"])
        cleaned = []

        class FakeRule:
            def __init__(self, name):
                self.name = name

            def close_store(self):
                cleaned.append(self)

        names = iter(("first", "second"))
        with mock.patch.object(
            plugin, "_load_rule_class", side_effect=lambda: lambda: FakeRule(next(names))
        ), mock.patch.object(plugin, "_native_host_services", return_value=object()):
            activation = plugin.PLUGIN.activate(
                SimpleNamespace(identity="identity", host="host")
            )
            first = activation.create_implementation("cobra-solve")
            second = activation.create_implementation("cobra-solve")

        class CoordinatedRules(list):
            def __init__(self, values):
                super().__init__(values)
                self.first_iteration = threading.Event()
                self.second_iteration = threading.Event()
                self.allow_first = threading.Event()
                self.allow_second = threading.Event()
                self._iteration_count = 0
                self._iteration_lock = threading.Lock()

            def __iter__(self):
                with self._iteration_lock:
                    self._iteration_count += 1
                    iteration = self._iteration_count
                if iteration == 1:
                    self.first_iteration.set()
                    self.allow_first.wait(2)
                elif iteration == 2:
                    self.second_iteration.set()
                    self.allow_second.wait(2)
                return super().__iter__()

        rules = CoordinatedRules([first, second])
        activation._rules = rules
        errors = []

        def release_second():
            try:
                activation.release_implementation(second)
            except BaseException as error:
                errors.append(error)

        def release_first():
            try:
                activation.release_implementation(first)
            except BaseException as error:
                errors.append(error)

        second_thread = threading.Thread(target=release_second)
        first_thread = threading.Thread(target=release_first)
        second_thread.start()
        self.assertTrue(rules.first_iteration.wait(2))
        first_thread.start()
        second_iteration_started = rules.second_iteration.wait(2)
        if second_iteration_started:
            rules.allow_second.set()
        rules.allow_first.set()
        rules.allow_second.set()
        second_thread.join(2)
        first_thread.join(2)

        self.assertFalse(second_thread.is_alive())
        self.assertFalse(first_thread.is_alive())
        self.assertEqual(errors, [])
        self.assertCountEqual(cleaned, [first, second])
        self.assertEqual(rules, [])

    def test_concurrent_create_and_close_drains_new_rule_once(self):
        plugin = __import__("d810_cobra.plugin", fromlist=["PLUGIN"])
        construction_started = threading.Event()
        allow_construction = threading.Event()
        close_reached_rules = threading.Event()
        cleaned = []

        class FakeRule:
            def close_store(self):
                cleaned.append(self)

        class Rules(list):
            def clear(self):
                close_reached_rules.set()
                super().clear()

        def load_rule_class():
            construction_started.set()
            self.assertTrue(allow_construction.wait(2))
            return FakeRule

        with mock.patch.object(
            plugin, "_load_rule_class", side_effect=load_rule_class
        ), mock.patch.object(plugin, "_native_host_services", return_value=object()):
            activation = plugin.PLUGIN.activate(
                SimpleNamespace(identity="identity", host="host")
            )
            activation._rules = Rules()
            errors = []
            created = []

            def create():
                try:
                    created.append(activation.create_implementation("cobra-solve"))
                except BaseException as error:
                    errors.append(error)

            def close():
                try:
                    activation.close()
                except BaseException as error:
                    errors.append(error)

            create_thread = threading.Thread(target=create)
            close_thread = threading.Thread(target=close)
            create_thread.start()
            self.assertTrue(construction_started.wait(2))
            close_thread.start()
            close_reached_rules.wait(0.2)
            allow_construction.set()
            create_thread.join(2)
            close_thread.join(2)

            self.assertFalse(create_thread.is_alive())
            self.assertFalse(close_thread.is_alive())
            self.assertEqual(errors, [])
            self.assertEqual(len(created), 1)
            self.assertEqual(cleaned, created)
            self.assertEqual(activation._rules, [])

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

    def test_release_implementation_uses_exact_identity_not_equality(self):
        plugin = __import__("d810_cobra.plugin", fromlist=["PLUGIN"])
        cleaned = []

        class EqualRule:
            def __init__(self):
                self.name = str(len(cleaned))

            def __eq__(self, _other):
                return True

            def close_store(self):
                cleaned.append(self)

        context = SimpleNamespace(identity="identity", host="host")
        with mock.patch.object(plugin, "_load_rule_class", return_value=EqualRule), \
             mock.patch.object(plugin, "_native_host_services", return_value=object()):
            activation = plugin.PLUGIN.activate(context)
            first = activation.create_implementation("cobra-solve")
            second = activation.create_implementation("cobra-solve")

        activation.release_implementation(second)

        self.assertEqual(len(cleaned), 1)
        self.assertIs(cleaned[0], second)
        self.assertEqual(len(activation._rules), 1)
        self.assertIs(activation._rules[0], first)

    def test_binding_failure_cleans_unpublished_rule(self):
        plugin = __import__("d810_cobra.plugin", fromlist=["PLUGIN"])
        calls = []

        class FailingRule:
            def bind_mba_host(self, _host):
                raise RuntimeError("bind failed")

            def stop_escalator(self):
                calls.append("stop")

            def flush_store(self):
                calls.append("flush")

            def close_store(self):
                calls.append("close")

        with mock.patch.object(plugin, "_load_rule_class", return_value=FailingRule), \
             mock.patch.object(plugin, "_native_host_services", return_value=object()):
            activation = plugin.PLUGIN.activate(
                SimpleNamespace(identity="identity", host="host")
            )
            with self.assertRaisesRegex(RuntimeError, "bind failed"):
                activation.create_implementation("cobra-solve")

        self.assertEqual(calls, ["stop", "flush", "close"])
        self.assertEqual(activation._rules, [])

    def test_binding_and_cleanup_failures_are_aggregated(self):
        plugin = __import__("d810_cobra.plugin", fromlist=["PLUGIN"])

        class FailingRule:
            def bind_mba_host(self, _host):
                raise KeyboardInterrupt("bind failed")

            def close_store(self):
                raise SystemExit("cleanup failed")

        with mock.patch.object(plugin, "_load_rule_class", return_value=FailingRule), \
             mock.patch.object(plugin, "_native_host_services", return_value=object()):
            activation = plugin.PLUGIN.activate(
                SimpleNamespace(identity="identity", host="host")
            )
            with self.assertRaises(BaseException) as raised:
                activation.create_implementation("cobra-solve")

        self.assertIsInstance(raised.exception.exceptions[0], KeyboardInterrupt)
        self.assertIsInstance(raised.exception.exceptions[1], SystemExit)
        self.assertEqual(activation._rules, [])

    def test_cleanup_lookup_failure_is_aggregated_and_remaining_steps_run(self):
        plugin = __import__("d810_cobra.plugin", fromlist=["PLUGIN"])
        calls = []

        class FailingRule:
            def __getattribute__(self, name):
                if name == "stop_escalator":
                    raise RuntimeError("cleanup lookup failed")
                return super().__getattribute__(name)

            def bind_mba_host(self, _host):
                raise KeyboardInterrupt("bind failed")

            def flush_store(self):
                calls.append("flush")

        with mock.patch.object(plugin, "_load_rule_class", return_value=FailingRule), \
             mock.patch.object(plugin, "_native_host_services", return_value=object()):
            activation = plugin.PLUGIN.activate(
                SimpleNamespace(identity="identity", host="host")
            )
            with self.assertRaises(BaseException) as raised:
                activation.create_implementation("cobra-solve")

        self.assertIsInstance(raised.exception.exceptions[0], KeyboardInterrupt)
        self.assertIn("cleanup lookup failed", str(raised.exception.exceptions[1]))
        self.assertEqual(calls, ["flush"])

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
            with self.assertRaises(BaseException):
                activation.close()
            activation.close()

        self.assertEqual(calls, ["stop", "flush", "close", "stop", "flush", "close"])

    def test_activation_close_aggregates_base_exceptions_and_clears_ownership(self):
        plugin = __import__("d810_cobra.plugin", fromlist=["PLUGIN"])
        calls = []

        class FatalStop(BaseException):
            pass

        class FailingRule:
            def stop_escalator(self):
                calls.append("stop")
                raise FatalStop("stop failed")

            def flush_store(self):
                calls.append("flush")
                raise SystemExit("flush failed")

            def close_store(self):
                calls.append("close")
                raise RuntimeError("close failed")

        context = SimpleNamespace(identity="identity", host="host")
        with mock.patch.object(plugin, "_load_rule_class", return_value=FailingRule), \
             mock.patch.object(plugin, "_native_host_services", return_value=object()):
            activation = plugin.PLUGIN.activate(context)
            rule = activation.create_implementation("cobra-solve")
            with self.assertRaises(BaseException) as raised:
                activation.close()
            self.assertIsInstance(raised.exception.exceptions[0], FatalStop)
            self.assertIsInstance(raised.exception.exceptions[1], SystemExit)

            activation.release_implementation(rule)

        self.assertEqual(calls, ["stop", "flush", "close"])


if __name__ == "__main__":
    unittest.main()
