"""Bounded, stage-checked proof of the single-variable linear Boolean domain."""
import pytest

from d810_cobra.expr import parse_cobra_output
from d810_cobra.prove import ProofResult
from d810_cobra.width_prove import prove_width_equivalent


def tree(text):
    return parse_cobra_output(text, ['x'])


def test_complement_partition_identity_is_proved():
    assert prove_width_equivalent(tree('3*(~x0&255)+3*(x0&255)'), tree('765'),
                                  ('x',), 64, timeout_ms=1500) == ProofResult.PROVED


@pytest.mark.parametrize('candidate', ['x0+12', 'x0+12-16*(x0&18446744069414584320)',
                                     'x0+12-18*(x0&4294967296)'])
def test_wrong_high_bits_are_refuted(candidate):
    source = tree('(x0&4294967295)+12-17*(x0&18446744069414584320)')
    assert prove_width_equivalent(source, tree(candidate), ('x',), 64,
                                  timeout_ms=1500) == ProofResult.REFUTED


def test_weighted_sign_bit_modulus_is_preserved():
    source = tree('(x0&4294967295)+12-17*(x0&18446744069414584320)')
    candidate = tree('x0-18*(x0&9223372032559808512)+12')
    assert prove_width_equivalent(source, candidate, ('x',), 64,
                                  timeout_ms=1500) == ProofResult.PROVED


@pytest.mark.parametrize('source', ['(x0+1)&255', 'x0*x0'])
def test_unsupported_grammar_fails_closed(source):
    assert prove_width_equivalent(tree(source), tree(source), ('x',), 64,
                                  timeout_ms=1500) != ProofResult.PROVED


def test_exhausted_shared_budget_is_not_proof():
    assert prove_width_equivalent(tree('x0+1'), tree('x0+1'), ('x',), 64,
                                  timeout_ms=0) == ProofResult.UNKNOWN


def test_node_and_depth_budget_refuses_before_recursion_error():
    source = tree('x0')
    for _ in range(100):
        source = {'kind':'un', 'op':'~', 'a':source}
    assert prove_width_equivalent(source, source, ('x',), 64,
                                  timeout_ms=1500) != ProofResult.PROVED


@pytest.mark.parametrize('corruption', ['kernel_constant', 'kernel_coefficient',
                                      'drop_kernel', 'collection', 'modular'])
def test_every_transformation_stage_is_bound_to_original(monkeypatch, corruption):
    from d810_cobra import width_prove as module
    original = module._prepare
    def corrupt(*args):
        parts, sides = original(*args)
        source = sides[0]
        if corruption == 'kernel_constant':
            source['kernels'][0]['constant'] ^= 1
        elif corruption == 'kernel_coefficient':
            source['kernels'][0]['coefficients'][0] ^= 1
        elif corruption == 'drop_kernel':
            source['kernels'].pop()
        elif corruption == 'collection':
            source['raw_coefficients'][0] ^= 1
        else:
            source['coefficients'][0] ^= 1
        return parts, sides
    monkeypatch.setattr(module, '_prepare', corrupt)
    source = tree('3*(x0&255)+7*(~x0&255)')
    assert module.prove_width_equivalent(source, source, ('x',), 64,
                                         timeout_ms=1500) == ProofResult.UNKNOWN


def test_terminal_extra_cycle_is_rejected_by_input_validation():
    import time
    from d810_cobra import width_prove as module
    source = tree('x0')
    source['a'] = source
    with pytest.raises(module._Unsupported):
        module._validate(source, 64, time.perf_counter()+1)


def test_multiple_or_unbound_variables_refuse():
    other = {'kind':'var', 'name':'y'}
    assert prove_width_equivalent(tree('x0+1'), other, ('x', 'y'), 64) != ProofResult.PROVED
    assert prove_width_equivalent(tree('x0+1'), tree('x0+1'), ('other',), 64) != ProofResult.PROVED


def test_shift_opcode_refuses():
    source = {'kind':'bin', 'op':'<<', 'a':tree('x0'), 'b':tree('1')}
    assert prove_width_equivalent(source, source, ('x',), 64) != ProofResult.PROVED


@pytest.mark.parametrize('limit', ['MAX_NODES', 'MAX_DEPTH', 'MAX_KERNELS',
                                 'MAX_PARTITIONS', 'MAX_OBLIGATIONS'])
def test_each_resource_cap_abstains(monkeypatch, limit):
    from d810_cobra import width_prove as module
    monkeypatch.setattr(module, limit, 0)
    assert module.prove_width_equivalent(tree('x0+1'), tree('x0+1'), ('x',), 64) != ProofResult.PROVED


def test_shared_deadline_exhausts_after_first_check(monkeypatch):
    from types import SimpleNamespace
    from d810_cobra import width_prove as module
    assert module.prove.z3_available()
    actual_solver = module.prove.z3.Solver
    now, calls = [0.0], []
    class Solver:
        def __init__(self): self.solver = actual_solver()
        def __getattr__(self, name): return getattr(self.solver, name)
        def check(self):
            result = self.solver.check()
            calls.append(1); now[0] = 2.0
            return result
    monkeypatch.setattr(module, 'time', SimpleNamespace(perf_counter=lambda: now[0]))
    monkeypatch.setattr(module.prove.z3, 'Solver', Solver)
    assert module.prove_width_equivalent(tree('x0+1'), tree('x0+1'), ('x',), 64,
                                         timeout_ms=1500) == ProofResult.UNKNOWN
    assert calls == [1]
