"""CoBRA backend: solve linear MBA that d810's pattern catalogue cannot match.

d810's 203 ``mba-simplify`` transforms are pattern-matched identities.  On
coefficient-based linear MBA they fire zero times -- measured, not assumed.
CoBRA (github.com/trailofbits/CoBRA) is a signature-driven solver that closes
exactly that gap.

Layout mirrors what each piece needs:

* ``expr``   -- parse/evaluate/accept.  Pure data, no IDA, unit-testable.
* ``probe``  -- locate the cobra-cli binary, or report a structured skip.

Everything that touches ``ida_hexrays`` (candidate detection, microcode
reconstruction) lives outside this pure core so that unit tests can exercise
the logic without IDA, per the import-linter contract.

Design and measurements:
``docs/plans/2026-08-06-cobra-mba-solve-integration.md``
"""

from __future__ import annotations

from d810_cobra.expr import (
    ExprParseError,
    accept_rewrite,
    evaluate,
    node_count,
    parse_cobra_output,
)
from d810_cobra.probe import CobraProbe, CobraStatus, find_cobra_cli

#: What d810's BackendRegistry reads to decide whether to load us.
#:
#: Deliberately a plain dict rather than ``d810.core.plugins.BackendManifest``:
#: importing that would make d810 a hard import-time dependency of this
#: package, and would turn a d810 that predates the plugin protocol from
#: "backend not discovered" into a bare ImportError at startup. ``manifest_of``
#: accepts any mapping carrying these three keys.
#:
#: ``provides`` is a string, so it is resolved LAZILY -- a version-incompatible
#: d810 rejects us after reading three fields, without ever importing the
#: IDA-coupled rule module.
MANIFEST = {
    "name": "cobra",
    "api_version": 1,
    "provides": "d810_cobra.plugin:PLUGIN",
    "requires": ("d810.mba.residual-observation.v1",),
    "implements": {"mba-solve": "cobra-solve"},
}

__all__ = [
    "MANIFEST",
    "CobraProbe",
    "CobraStatus",
    "ExprParseError",
    "accept_rewrite",
    "evaluate",
    "find_cobra_cli",
    "node_count",
    "parse_cobra_output",
]
