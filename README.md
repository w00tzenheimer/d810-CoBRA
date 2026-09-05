# d810-cobra

[![ci](https://github.com/w00tzenheimer/d810-CoBRA/actions/workflows/ci.yml/badge.svg)](https://github.com/w00tzenheimer/d810-CoBRA/actions/workflows/ci.yml)
[![python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue.svg)](pyproject.toml)
[![license](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![d810-ng](https://img.shields.io/badge/d810--ng-backend-8A2BE2.svg)](https://github.com/w00tzenheimer/d810-ng)

CoBRA MBA-solver backend for [d810](https://github.com/w00tzenheimer/d810-ng) —
the `mba-solve` pass.

```console
pip install d810-cobra
```

That is the whole installation. d810 discovers this package automatically; no
configuration, no `COBRA_ROOT`, no CMake, no C++23 toolchain on the user's
machine.

> **Requires `d810-ng >= 1.0.0b0`, which is not released yet.**
> v1.0.0 is d810-ng's cutover release, the first to carry the plugin seam this
> package plugs into; betas carry it until then, which is why the floor is
> `1.0.0b0` rather than `1.0.0` — a pre-release sorts *before* its final, so
> `>=1.0.0` would reject every beta. Discovery depends on `d810.core.plugins`
> and the
> `d810.backends` entry-point group; d810-ng 0.6.6 ships neither, so pip will
> refuse to install this package against it — deliberately. Version 0.1.0
> declared `>=0.6.6`, which pip accepted, and the result was a package that
> installed, built its binding, and was then never discovered: `mba-solve`
> simply absent, indistinguishable from a pass that ran and matched nothing.
> A loud version error beats a silent no-op.

## Why it is a separate package

d810's 203 `mba-simplify` transforms are pattern-matched identities. On
coefficient-based linear MBA they fire zero times — measured, not assumed.
[CoBRA](https://github.com/trailofbits/CoBRA) is a signature-driven solver that
closes exactly that gap.

Shipping it inside d810 meant every d810 wheel carried a C++23 build of abseil,
highway and cobra-core, and CoBRA's version was pinned to a d810 commit. Split
out, d810's wheel stays pure and the two version independently.

## How d810 finds it

One entry point, in the unversioned `d810.backends` group:

```toml
[project.entry-points."d810.backends"]
cobra = "d810_cobra:MANIFEST"
```

```python
MANIFEST = {
    "name": "cobra",
    "api_version": 1,
    "provides": "d810_cobra.plugin:PLUGIN",
    "requires": ("d810.mba.residual-observation.v1",),
    "implements": {"mba-solve": "cobra-solve"},
}
```

`MANIFEST` is a plain dict — deliberately not d810's `BackendManifest`. The
package depends on d810 at runtime, but the *manifest* must not: importing
`BackendManifest` would turn "this d810 predates the plugin protocol" from a
clean "backend not discovered" into an ImportError during d810 startup.

Its `provides` is a *string*, resolved lazily, so a version-incompatible d810
rejects this backend after reading the manifest — without importing `plugin.py`
or `solve.py`, and therefore without loading the compiled extension.

The remaining manifest fields describe the explicit API-1 activation contract:

- **`requires`** — the host capability needed by the implementation. d810
  validates `d810.mba.residual-observation.v1` before activating CoBRA, and
  passes the resulting host view to the activation and its rule services.
- **`implements`** — the pass-to-implementation declaration. The value
  `cobra-solve` is an opaque implementation ID owned by this package; d810
  does not import or hardcode `CobraSolveRule`.

There is intentionally no `rules` field. d810 discovers the manifest, resolves
`PLUGIN`, and calls `PLUGIN.activate(PluginActivationContext(...))`. The
activation creates the implementation only when the selected pass requests
`create_implementation("cobra-solve")`; that factory may then lazily import
the IDA-coupled rule. This keeps discovery cheap and makes activation and
cleanup explicit rather than relying on a package-path scan.

API-1 capability factories, when a backend offers one, are invoked once per
function with a `PluginFunctionContext` containing the live source, plugin
function-execution identity (`FunctionExecutionIdentity`), and host capability
view. They must use that context for function-scoped services such as residual
observation and must not retain callback-local state across functions or
reloads. CoBRA's `mba-solve`
implementation is created through the opaque implementation ID above; it does
not need a separate capability offer.

d810 itself is a hard dependency (`solve.py` uses `d810.core.getLogger`,
`table.py` uses `d810.core.cache`, `convert.py`/`detect.py` use
`d810.hexrays.*`). Some of those are d810 internals rather than a published
API, so a d810 refactor can break this package without either side bumping a
major version.

d810 ships no MBA solver of its own — `cobra` is not one of its builtin
backends — so this package supplies the `mba-solve` implementation rather than
overriding one:

```
cobra   available   d810-cobra 0.1.5
```

Check it with `d810cli backends`. Without this package installed, d810's
`mba-solve` pass resolves no implementation and contributes no stages.

## Building from source

```console
git clone --recursive https://github.com/w00tzenheimer/d810-CoBRA
cd d810-CoBRA
python tools/build_cobra.py     # abseil + highway + cobra-core (CMake + Ninja)
pip install -e .
```

`tools/build_cobra.py` needs CMake and Ninja, and a C++23 compiler. On Windows
it pins MSVC (`cl`) explicitly: `-G Ninja` with no compiler pinned picks
whatever is first in `PATH`, and a MinGW build produces `libabsl_*.a` archives
that an MSVC-built `.pyd` can neither `/WHOLEARCHIVE:` nor safely link against.

The build **fails loudly** rather than producing a package without the binding.
A wheel that installs cleanly and simplifies nothing is the failure mode this
package exists to make impossible.

## Layout

| path | what |
|---|---|
| `src/d810_cobra/expr.py` | parse/evaluate/accept — pure data, no IDA |
| `src/d810_cobra/probe.py` | locate `cobra-cli`, or report a structured skip |
| `src/d810_cobra/solve.py` | the backend entry point d810 resolves |
| `src/d810_cobra/_cobra.pyx` | Cython binding over `cobra_shim.cpp` |
| `src/d810_cobra/rules/` | the `mba-solve` peephole rule (needs d810 + Hex-Rays) |
| `src/include/cobra_shim.h` | C ABI the binding compiles against |
| `src/cpp/cobra_shim.cpp` | C++ shim over cobra-core |
| `third_party/cobra` | pinned CoBRA submodule |

Headers and the C++ shim sit outside the package, mirroring d810's own
`src/include`. They are build inputs, so the wheel ships only what is
importable; `MANIFEST.in` is what carries them into the sdist. Note that
setuptools auto-includes a declared Extension *source* but never an
`include_dirs` header — drop `MANIFEST.in` and the sdist still contains
`cobra_shim.cpp` while silently losing `cobra_shim.h`.

Everything that touches `ida_hexrays` lives under `rules/`, so the solver core
stays unit-testable without IDA.

## License

MIT. CoBRA itself is vendored as a submodule under its own license.
