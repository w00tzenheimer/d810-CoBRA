"""Optimizer rules contributed to d810 by this backend.

The API-1 plugin adapter loads the concrete rule lazily when an activated host
requests the opaque ``cobra-solve`` implementation ID.  The package manifest
does not enumerate rule modules: d810 resolves ``provides`` to ``PLUGIN``,
validates ``requires``, and owns activation, host-service binding, and
implementation cleanup explicitly.
"""
