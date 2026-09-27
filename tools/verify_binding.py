"""Prove a built wheel actually solves, not merely that it imports.

Run by ``CIBW_TEST_COMMAND`` against every wheel cibuildwheel produces. This is
the only check separating a working wheel from one that installs cleanly and
simplifies nothing -- the failure this package exists to refuse.

Two things it deliberately does NOT do:

* It does not import ``d810_cobra.solve``. That module imports ``d810``, and
  the wheel is installed with ``PIP_NO_DEPS=1`` because this package requires
  ``d810-ng>=0.7.0``, which is not released yet. Testing through ``solve``
  would make the gate fail on a missing *runtime* dependency and say nothing
  about the binding.
* It does not check ``binding_available()``, a boolean that reports whether an
  import succeeded. A compiled extension can import and still be wrong; running
  a known-answer solve is what proves the C++ side is wired up.

The identity below is the smallest one that exercises the full path -- signature
evaluation, tree marshalling across the C ABI, the solver, and the result
decode. ``(x | y) - (x & y)`` is ``x ^ y`` for all inputs.
"""

from __future__ import annotations

import sys


def main() -> int:
    try:
        from d810_cobra import _cobra
    except ImportError as exc:
        # The whole point of the gate. Print the reason: "missing" and
        # "present but unloadable" are different bugs with different fixes,
        # and CI logs are the only place that evidence survives.
        print(f"FAIL: the compiled binding did not import: {exc}", file=sys.stderr)
        return 1

    print(f"binding: {_cobra.__file__}")

    def var(name: str) -> dict:
        return {"kind": "var", "name": name}

    tree = {
        "kind": "bin",
        "op": "-",
        "a": {"kind": "bin", "op": "|", "a": var("x"), "b": var("y")},
        "b": {"kind": "bin", "op": "&", "a": var("x"), "b": var("y")},
    }
    signature = [(x | y) - (x & y) for y in (0, 1) for x in (0, 1)]

    result = _cobra.simplify(signature, ["x", "y"], 64, tree)
    if result is None:
        print("FAIL: solver returned None for a solvable identity", file=sys.stderr)
        return 1

    got = (result.get("op"), result.get("a", {}).get("name"), result.get("b", {}).get("name"))
    if got != ("^", "x", "y"):
        print(f"FAIL: (x|y)-(x&y) should solve to x^y, got {result}", file=sys.stderr)
        return 1

    budgeted, expired = _cobra.simplify_budgeted(
        signature, ["x", "y"], 64, tree, time_limit_ms=1000
    )
    if budgeted != result or not isinstance(expired, bool):
        print(
            f"FAIL: budgeted binding returned {budgeted!r}, expired={expired!r}",
            file=sys.stderr,
        )
        return 1

    print("solved: (x|y) - (x&y) -> x ^ y")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
