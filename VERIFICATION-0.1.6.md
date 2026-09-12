# d810-cobra 0.1.6 — verification record

Built and published by `deploy.yml` run
[34719758785](https://github.com/w00tzenheimer/d810-CoBRA/actions/runs/34719758785)
on the `v0.1.6` release. All five platform legs, the sdist, `publish` and
`release_assets` succeeded. PyPI upload at 2026-09-12T21:29Z.

## Provenance

| | |
|---|---|
| **Release commit (tag `v0.1.6`)** | `d2926d0ae5389fa2c928cf9f4875a40f4323f11e` |
| **Width fix shipped** | `032e422468527e9671c7ac6c6382ff8fce28b3db` |
| **`third_party/cobra`** | `72f616f822f538a0cfbea3c880f9d1e68bb9a8f1` |
| **d810 tested (GitHub)** | `cfg-recon-mainline` @ `c850b96e36150af266d39f55c3feb23ed2349a90` (1.0.0b2) |
| **d810 tested (local checkout)** | `cfg-recon-mainline` @ `15588124351fdb8f4eca199ac8e504bd66cabcf5` (1.0.0b2, not on GitHub) |

## Artifacts

PyPI lists 16 files for 0.1.6: cp311, cp312 and cp313 wheels for manylinux
aarch64, manylinux x86-64, Windows amd64, macOS arm64 and macOS x86-64, plus the
sdist. cp310 is no longer built. The GitHub release carries the same 16 files
plus `SHA256SUMS`.

For all 16 files, PyPI's recorded digest equals the release's `SHA256SUMS`
line. The three wheels below were also downloaded and hashed locally, and each
contains exactly one compiled extension.

| Wheel | SHA-256 | Extension |
|---|---|---|
| `d810_cobra-0.1.6-cp313-cp313-manylinux_2_26_aarch64.manylinux_2_28_aarch64.whl` | `1fdeb814919dc4e48552fdca2fee5f8ef23720809263c7ddb8fcca4354ee6ead` | `_cobra.cpython-313-aarch64-linux-gnu.so` |
| `d810_cobra-0.1.6-cp313-cp313-manylinux_2_27_x86_64.manylinux_2_28_x86_64.whl` | `55c1602d9f11ef0b02d330a256d7cd87334a2a666d92333f5495af0597c8bf1d` | `_cobra.cpython-313-x86_64-linux-gnu.so` |
| `d810_cobra-0.1.6-cp313-cp313-win_amd64.whl` | `b0322f0c7e294847a5095caef981cffe2ccd0ca4d563ab859d7cb275935f0e0c` | `_cobra.cp313-win_amd64.pyd` |

Every wheel also passed `tools/verify_binding.py` (a real known-answer solve)
inside `deploy.yml` on its own native runner, Windows included.

## CI against d810

`ci.yml` now installs d810 from `cfg-recon-mainline`, pinned by SHA. Run
[34719679044](https://github.com/w00tzenheimer/d810-CoBRA/actions/runs/34719679044)
on `d2926d0`: 140 passed, 21 skipped, 0 failed on both Python 3.11 and 3.13. The
same job reproduced in clean `python:3.13-slim` containers gives the same result
on both linux/amd64 and linux/arm64. Leaving out `z3-solver` gives 11 failures.

## Inside IDA (arm64)

Image `idapro-9.4-speedups:ci`
(`sha256:a60b5ccbd800319ccbfb959bf88c980f9c32029032263bb38a42cb7af3e7b082`,
linux/arm64, no baked CoBRA). The run uses the published aarch64 wheel,
installed `--no-deps` after its SHA-256 was checked, on top of the local d810
checkout. d810's native Cython speedups were built and confirmed loaded, as the
Docker runner's default `D810_NO_CYTHON=0` requires.

| Check | Result |
|---|---|
| Known-answer solve and Z3 proof through d810 | `(x0 \| x1) - (x0 & x1)` solved and PROVED |
| d810 `test_plugin_provider_publication.py` | 46 passed |
| d810 acceptance: real CoBRA attempt attributed through the outer optimizer | passed |
| d810 acceptance: live CoBRA outcome persisted by ordinary decompilation | passed when run alone; fails when run with the whole file (see below) |
| CoBRA `test_cobra_detect_convert.py` | 13 passed |
| CoBRA `test_cobra_width_lift.py` (at `bc803e9`) | 35 passed, 3 skipped |
| CoBRA `test_cobra_provider_publication.py` (at `dc6762b`, rewritten onto d810's real registry) | 8 passed |

The same run with the published **0.1.5** aarch64 wheel gave the same d810
results. It also segfaulted in `test_cobra_provider_publication.py` before the
test fixes, so none of the in-IDA problems were 0.1.6 regressions.

### Open items

- **`test_cobra_provider_publication.py` was rewritten (`dc6762b`).** The old
  version imitated d810's optimizer and mutation lifecycle by hand, and failed
  against 1.0.0b2 in a different d810 internal after each fix. It now activates
  cobra-solve through d810's real registry, host capability registry and
  pipeline-v2 schedule, with a real native instruction and the real mutation
  commit. Only CoBRA's own seams are patched.
  - The accepted case runs a real solve, proof and commit:
    `add (zf.4+sf.4), (#0xFFFFFFFE.4*(zf.4 & sf.4)), cc^2.4` becomes
    `xor zf.4, sf.4, cc^2.4`.
  - Two deliberately broken copies (a wrong expected status, and a forced
    unavailable binding) were both reported as failures.
- **Three width-lift cases skip.** They need a `native_mba` fixture, meaning an
  `mba_t` for the binary whose EAs `0x18F557265BF`, `0x18F55734E71` and
  `0x18F5575CD50` they hardcode. No conftest in d810 or here defines it.
- **d810-side test issues** (reported, not changed here):
  - `test_real_accepted_rewrite_is_applied_without_residual_row` and the
    `mba-egraph` case of the live-decompilation test require `d810-egglog` but
    are not skip-gated.
  - `_activate_real_provider` registers the host capability lease before an
    activation that can raise. When it raises, the lease is never released, and
    the next test fails with `capability ID 'd810.mba.residual-observation.v1'
    is already registered`. That is why the live CoBRA test fails only when the
    whole file runs.
  - The Docker runner's `docker/cobra-bake/published_identity` still records
    0.1.5, so the runner will refuse the 0.1.6 wheel until d810 records it.
- **Not verified here:**
  - x86-64 inside IDA;
  - running the Windows wheel beyond `deploy.yml`'s `verify_binding.py` gate.

## Reproducibility

The build is not bit-for-bit reproducible (`SOURCE_DATE_EPOCH` is unset). The
hashes above identify these specific artifacts. Check downloads against PyPI's
digests or the release's `SHA256SUMS`.
