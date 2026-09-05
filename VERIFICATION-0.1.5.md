# d810-cobra 0.1.5 — wheel verification report

Two CPython 3.13 manylinux wheels, built with the repository's own
`cibuildwheel` configuration and verified twice: once by the in-build gate, and
once again after installing the finished artifact in a container that has none
of the build toolchain present.

## Artifacts

| | aarch64 | x86-64 |
|---|---|---|
| **Wheel** | `d810_cobra-0.1.5-cp313-cp313-manylinux_2_26_aarch64.manylinux_2_28_aarch64.whl` | `d810_cobra-0.1.5-cp313-cp313-manylinux_2_27_x86_64.manylinux_2_28_x86_64.whl` |
| **SHA-256** | `b71d40e45146004a968a96a1b17493b16ac04f2a98e41c12a1f87a38ddf3ab25` | `c642e6a6d61f8b841d97df78375c6e1da43fc05a56c3b68218230ed23beaa762` |
| **Size** | 2 093 472 bytes (2.00 MiB) | 2 215 083 bytes (2.11 MiB) |
| **Python tag** | `cp313` | `cp313` |
| **ABI tag** | `cp313` | `cp313` |
| **Platform tag** | `manylinux_2_26_aarch64.manylinux_2_28_aarch64` | `manylinux_2_27_x86_64.manylinux_2_28_x86_64` |
| **Extension** | `d810_cobra/_cobra.cpython-313-aarch64-linux-gnu.so` | `d810_cobra/_cobra.cpython-313-x86_64-linux-gnu.so` |
| **Build time** | 3m06s (native) | 6m26s (Rosetta) |

Both wheels are in `dist/`.

Each SHA-256 was computed three times independently and agrees each time:
cibuildwheel's own report, a `hashlib` pass over the finished file, and
`shasum -a 256` on macOS.

## Provenance

| | |
|---|---|
| **Parent commit** | `3b3c406270f1efd8e222f0b05040ae4e074b27d5` (`build: publish corrected CoBRA dependency pin`) |
| **Release commit** | `55540ab84d95bde080a5c1223f034b61fb483492` (`build: release 0.1.5`) |
| **Tree built** | `db5cac138c825e308dd5b275cb43561c6dbab9d9` |
| **`third_party/cobra`** | `72f616f822f538a0cfbea3c880f9d1e68bb9a8f1` (`v1.3.0-13-g72f616f`) |
| **Worktree** | `.claude/worktrees/cobra-wheels-0.1.5`, branch `worktree-cobra-wheels-0.1.5` |

The release commit changes two lines — `version` in `pyproject.toml` and the
matching sample output in `README.md`. Nothing under `src/` differs from the
parent commit, and `d810` was not touched.

The working tree was clean at `55540ab` when the wheels were produced, so the
tree above is the exact input to both builds. cibuildwheel copies the project
into its container rather than bind-mounting it, so neither build wrote into the
checkout: `third_party/cobra` still has no `build/` or `build-deps/` afterwards
and remains a pristine 43 MB checkout of `72f616f`.

## Build environment

| | aarch64 | x86-64 |
|---|---|---|
| Image | `quay.io/pypa/manylinux_2_28_aarch64:2025.08.15-1` | `quay.io/pypa/manylinux_2_28_x86_64:2025.08.15-1` |
| Digest | `sha256:52bb58d1da822eb682d7d4e6c0d61383e9388a7195ae1bde904f2f4a7b33c983` | `sha256:6f42f4382bc73e9584206e6722e001922c0d4846c932fccaa04c0e35903b717d` |
| Execution | native (Apple Silicon) | `linux/amd64` under Rosetta |

cibuildwheel 3.1.4, matching `pypa/cibuildwheel@v3.1` in `deploy.yml`. The build
used that workflow's environment verbatim, narrowing only `CIBW_BUILD` to
`cp313-*` and `CIBW_ARCHS_LINUX` to one architecture per run. In particular
`CIBW_BEFORE_ALL_LINUX` built abseil, highway and `cobra-core` **inside** each
container, so every wheel links against the same toolchain and libstdc++ that
will later load it.

## Verification

**1. The binding is in the wheel.** Read as a zip, without installing: each
wheel contains exactly one `d810_cobra/_cobra.*.so`, of the right machine type
(`AArch64` / `Advanced Micro Devices X86-64`).

**2. `tools/verify_binding.py` passes in-build.** cibuildwheel's
`CIBW_TEST_COMMAND` ran it against each repaired wheel:

```
binding: .../d810_cobra/_cobra.cpython-313-aarch64-linux-gnu.so
solved: (x|y) - (x&y) -> x ^ y

binding: .../d810_cobra/_cobra.cpython-313-x86_64-linux-gnu.so
solved: (x|y) - (x&y) -> x ^ y
```

**3. `--no-deps` install and known-answer solve, per architecture.** Repeated
outside cibuildwheel in a stock `python:3.13-slim` container of each wheel's own
architecture — no compiler, no CMake, no CoBRA source, no `d810`. `pip list`
confirmed `d810-cobra==0.1.5` and `pip` were the only distributions present, so
the solve is running against the wheel alone. Both solved
`(x|y) - (x&y) -> x ^ y`.

**4. The wheel is self-contained.** `auditwheel` vendored nothing; `DT_NEEDED`
is only `libstdc++.so.6`, `libm.so.6`, `libgcc_s.so.1`, `libpthread.so.0`,
`libc.so.6` and the loader — all in the manylinux allowlist. `cobra-core`,
abseil and highway are linked statically. Highest versioned symbols required, on
both wheels: `GLIBC_2.25`, `GLIBCXX_3.4.21`, `CXXABI_1.3.11`.

**5. API-1 manifest behaviour preserved.** Read back through
`importlib.metadata` from the installed wheel, exactly as d810's
`BackendRegistry` reads it:

```
entry point: cobra -> d810_cobra:MANIFEST
MANIFEST: {'name': 'cobra', 'api_version': 1,
           'provides': 'd810_cobra.plugin:PLUGIN',
           'requires': ('d810.mba.residual-observation.v1',),
           'implements': {'mba-solve': 'cobra-solve'}}
```

`api_version` is 1, `implements` is `{"mba-solve": "cobra-solve"}`, and
`provides` is still a string, so an incompatible d810 can reject this package
after reading three fields without importing the IDA-coupled rule module.
`Requires-Dist: d810-ng>=1.0.0b0` is carried through unchanged.

## One thing that is not clean, and was not caused by this change

`pytest tests/unit` at the parent commit gives **106 passed, 21 skipped, 11
failed**. Every failure is one cause:

```
ModuleNotFoundError: No module named 'd810.core.plugins'
```

`pyproject.toml` sets the floor at `d810-ng>=1.0.0b0` precisely because
`d810.core.plugins` does not exist before then, and no release satisfies that
floor yet — PyPI has `0.4.0, 0.6.1, 0.6.4, 0.6.5, 0.6.6`. `ci.yml` installs
`d810-ng>=0.6.6`, which resolves to 0.6.6, so those 11 tests cannot pass in any
environment reachable from PyPI today. This is pre-existing at `3b3c406` and
orthogonal to the wheels: `verify_binding.py` deliberately never imports
`d810`, which is why the binding could be proven at all.

Worth fixing separately — `ci.yml`'s test job is currently red for a reason
unrelated to whatever a PR changes.

## Reproducing

```console
git checkout 55540ab84d95bde080a5c1223f034b61fb483492
git submodule update --init --recursive        # -> 72f616f

export CIBW_PLATFORM=linux
export CIBW_ARCHS_LINUX=aarch64                # or x86_64
export CIBW_BUILD='cp313-*'
export CIBW_SKIP='*-win32 *-musllinux_*'
export CIBW_ENVIRONMENT='COBRA_ROOT=/project/third_party/cobra'
export CIBW_BEFORE_BUILD='pip install Cython>=3.0.0'
export CIBW_BEFORE_ALL_LINUX='pip install cmake ninja && python tools/build_cobra.py'
export CIBW_TEST_ENVIRONMENT='PIP_NO_DEPS=1'
export CIBW_TEST_COMMAND='python {project}/tools/verify_binding.py'

cibuildwheel --output-dir wheelhouse .
```

Then, against the built wheel:

```console
docker run --rm --platform linux/arm64 -v "$PWD/wheelhouse":/wheels:ro \
    -v "$PWD/tools/verify_binding.py":/verify_binding.py:ro python:3.13-slim \
    sh -c 'pip install --no-deps --no-index /wheels/*.whl && python /verify_binding.py'
```

The build is not bit-for-bit reproducible: `SOURCE_DATE_EPOCH` is unset, and
every zip entry in both wheels carries the build wall-clock time
(`2026-09-05 17:38:18` and `17:41:58` UTC respectively — one distinct timestamp
per wheel). A rebuild from the same source will therefore produce a different
SHA-256. The hashes above identify these artifacts; they are not a
reproducibility claim.
