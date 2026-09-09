"""Real native operands: fixed-width lifting and owned reconstruction contracts."""
import ida_hexrays as hx
import pytest

from d810_cobra import detect
from d810_cobra.expr import evaluate


def reg(location, size, version=1):
    operand = hx.mop_t()
    operand.make_reg(location, size)
    operand.valnum = version
    return operand


def instruction(opcode, left, right=None, size=8):
    ins = hx.minsn_t(0x1000)
    ins.opcode = opcode
    ins.l.assign(left)
    if right is not None:
        ins.r.assign(right)
    ins.d.size = size
    return ins


def builder(size=8):
    factory = getattr(detect, '_WidthTreeBuilder', None)
    return factory(size) if factory else detect._TreeBuilder()


@pytest.mark.parametrize('opcode,left,right,expected', [
    (hx.m_add, 255, 1, 0), (hx.m_mul, 128, 2, 0),
    (hx.m_neg, 1, None, 255), (hx.m_bnot, 0, None, 255),
])
def test_narrow_node_truncates_before_wide_use(opcode, left, right, expected):
    capture = builder()
    tree = capture.instruction(instruction(opcode, reg(8, 1),
                               reg(16, 1) if right is not None else None, size=1))
    values = {name: left if snap.reg == 8 else right
              for name, snap in capture.snapshots.items()}
    assert evaluate(tree, values, (1 << 64)-1) == expected


def test_same_register_version_uses_existing_widest_binding():
    capture = builder()
    capture.instruction(instruction(hx.m_xor, reg(8, 1, 66), reg(8, 4, 66)))
    assert len(capture.snapshots) == 1
    assert next(iter(capture.snapshots.values())).size == 4


@pytest.mark.parametrize('location,version', [(16, 66), (8, 67), (8, 0), (8, 65535)])
def test_alias_requires_same_location_and_known_version(location, version):
    capture = builder()
    capture.instruction(instruction(hx.m_xor, reg(8, 1, 66), reg(location, 4, version)))
    assert len(capture.snapshots) == 2


def test_reconstruction_extends_without_widening_read():
    from d810_cobra.convert import tree_to_ast
    from d810.hexrays.ir.mop_snapshot import MopSnapshot
    snapshot = MopSnapshot.from_mop(reg(8, 1, 66))
    ast = tree_to_ast({'kind': 'var', 'name': 'x'}, {'x': snapshot}, 8)
    result = ast.create_mop(0x1000)
    assert result.t == hx.mop_d
    assert result.d.opcode == hx.m_xdu
    assert result.size == 8 and result.d.l.size == 1
    assert snapshot.size == 1


@pytest.mark.parametrize('opcode', [hx.m_xds, hx.m_shl, hx.m_shr])
def test_unneeded_casts_and_shifts_refuse(opcode):
    with pytest.raises(detect.UnsupportedMicrocode):
        builder().instruction(instruction(opcode, reg(8, 1), reg(16, 1)))


def test_source_wider_than_root_refuses():
    with pytest.raises(detect.UnsupportedMicrocode):
        builder(4).instruction(instruction(hx.m_mov, reg(8, 8), size=4))


def test_nested_operand_and_result_width_mismatch_refuses():
    nested = hx.mop_t()
    nested.create_from_insn(instruction(hx.m_neg, reg(8, 4), size=4))
    nested.size = 1
    with pytest.raises(detect.UnsupportedMicrocode):
        builder().instruction(instruction(hx.m_xdu, nested))


def test_builder_cannot_be_reused_across_callbacks():
    capture = builder()
    ins = instruction(hx.m_xor, reg(8, 4), reg(16, 4))
    capture.instruction(ins)
    with pytest.raises(detect.UnsupportedMicrocode):
        capture.instruction(ins)


def test_maximum_uint16_is_valid_version_not_unknown():
    capture = builder()
    capture.instruction(instruction(hx.m_xor, reg(8, 1, 65535), reg(8, 4, 65535)))
    # Pinned SDK hexrays.hpp:2624-2627: only zero means unknown.
    assert len(capture.snapshots) == 1


@pytest.mark.parametrize('kind', ['global', 'stack'])
def test_narrow_nonregister_read_is_preserved(kind, native_mba):
    from d810_cobra.convert import tree_to_ast
    from d810.hexrays.ir.mop_snapshot import MopSnapshot
    source = hx.mop_t()
    if kind == 'global':
        source.make_gvar(0x18F5575CD50)
    else:
        source.make_stkvar(native_mba, 0)
    source.size = 1
    snapshot = MopSnapshot.from_mop(source)
    before = snapshot.to_mop().dstr()
    result = tree_to_ast({'kind': 'var', 'name': 'x'}, {'x': snapshot}, 8).create_mop(0x1000)
    assert result.d.opcode == hx.m_xdu and result.size == 8
    assert result.d.l.size == 1 and result.d.l.t == source.t
    assert result.d.l.dstr() == before
    assert snapshot.size == 1 and snapshot.to_mop().dstr() == before


def mixed_candidate():
    constant = hx.mop_t(); constant.make_number(1, 1)
    byte = hx.mop_t()
    byte.create_from_insn(instruction(hx.m_xor, reg(8, 1, 66), constant, size=1))
    extended = hx.mop_t()
    extended.create_from_insn(instruction(hx.m_xdu, byte, size=8))
    number = hx.mop_t(); number.make_number(2, 8)
    return instruction(hx.m_add, extended, number)


@pytest.mark.parametrize('proof', ['proved', 'unknown', 'unavailable', 'refuted'])
def test_new_width_domain_requires_real_proof_even_when_disabled(monkeypatch, proof):
    from d810_cobra.rules import cobra_solve as module
    from d810_cobra.solve import SolveResult, SolveStatus
    from d810_cobra.prove import ProofResult
    rule = module.CobraSolveRule(); rule.require_proof = False
    calls = []
    monkeypatch.setattr(module, 'binding_available', lambda: True)
    def solve(tree, names, width):
        return SolveResult(SolveStatus.SOLVED, {'kind': 'bin', 'op': '+',
             'a': {'kind': 'var', 'name': names[0]}, 'b': {'kind': 'const', 'value': 1}})
    def prove(*args, **kwargs):
        calls.append(1)
        return ProofResult(proof)
    monkeypatch.setattr(module, 'solve_signature', solve)
    monkeypatch.setattr(module, 'prove_width_equivalent', prove)
    result = rule._check_and_replace(None, mixed_candidate())
    assert calls == [1]
    assert (result is not None) == (proof == 'proved')


def test_legacy_proved_cache_cannot_authorize_width_lift(monkeypatch):
    from d810_cobra.rules import cobra_solve as module
    from d810_cobra.solve import SolveResult, SolveStatus
    rule = module.CobraSolveRule(); rule.require_proof = False
    ins = mixed_candidate()
    capture = builder(); tree = capture.instruction(ins)
    poisoned = {'kind': 'const', 'value': 0}
    rule.table.record_proved(tree, 64, poisoned)
    calls = []
    monkeypatch.setattr(module, 'binding_available', lambda: True)
    def solve(*args, **kwargs):
        calls.append(1)
        return SolveResult(SolveStatus.UNCHANGED)
    monkeypatch.setattr(module, 'solve_signature', solve)
    assert rule._check_and_replace(None, ins) is None
    assert calls == [1]


def test_narrow_interior_requires_width_domain_with_wide_leaves(monkeypatch):
    from d810_cobra.rules import cobra_solve as module
    from d810_cobra.solve import SolveResult, SolveStatus
    from d810_cobra.prove import ProofResult
    a = hx.mop_t(); a.make_number(0xffffffff, 4)
    b = hx.mop_t(); b.make_number(1, 4)
    narrow = hx.mop_t(); narrow.create_from_insn(instruction(hx.m_add, a, b, size=4))
    extended = hx.mop_t(); extended.create_from_insn(instruction(hx.m_xdu, narrow))
    ins = instruction(hx.m_xor, reg(8, 8), extended)
    rule = module.CobraSolveRule(); rule.require_proof = False
    calls = []
    monkeypatch.setattr(module, 'binding_available', lambda: True)
    monkeypatch.setattr(module, 'solve_signature', lambda tree, names, width:
        SolveResult(SolveStatus.SOLVED, {'kind': 'bin', 'op': '+',
            'a': {'kind': 'var', 'name': names[0]}, 'b': {'kind': 'const', 'value': 0}}))
    def prove(*args, **kwargs):
        calls.append(1); return ProofResult.PROVED
    monkeypatch.setattr(module, 'prove_width_equivalent', prove)
    assert rule._check_and_replace(None, ins) is not None
    assert calls == [1]


@pytest.mark.parametrize('proof,expected_status', [('unknown', 'over_budget'),
    ('unavailable', 'unavailable'), ('refuted', 'proof_failed')])
def test_width_proof_abstention_keeps_reason_on_cache_hit(monkeypatch, proof, expected_status):
    from d810_cobra.rules import cobra_solve as module
    from d810_cobra.solve import SolveResult, SolveStatus
    from d810_cobra.prove import ProofResult
    rule = module.CobraSolveRule(); rule.require_proof = False
    calls, terminals = [], []
    monkeypatch.setattr(module, 'binding_available', lambda: True)
    monkeypatch.setattr(module, 'solve_signature', lambda tree, names, width:
        SolveResult(SolveStatus.SOLVED, {'kind': 'bin', 'op': '+',
            'a': {'kind': 'var', 'name': names[0]}, 'b': {'kind': 'const', 'value': 0}}))
    def prove(*args, **kwargs):
        calls.append(1); return ProofResult(proof)
    monkeypatch.setattr(module, 'prove_width_equivalent', prove)
    monkeypatch.setattr(rule, '_finish_attempt', lambda status, reason=None, **kw:
                        terminals.append((status.value, reason)))
    ins = mixed_candidate()
    assert rule._check_and_replace(None, ins) is None
    assert rule._check_and_replace(None, ins) is None
    assert calls == [1]
    assert [status for status, reason in terminals] == [expected_status] * 2
    assert all(proof in reason for status, reason in terminals)


def test_saved_roots_python_cython_snapshot_and_ast_parity(monkeypatch, native_mba):
    from d810_cobra import convert
    from d810.hexrays.ir.mop_snapshot import PythonMopSnapshot
    from d810.hexrays.expr import p_ast
    native_snapshot = detect.MopSnapshot
    native_node, native_leaf = convert.AstNode, convert.AstLeaf
    assert 'speedups' in native_node.__module__
    assert 'speedups' in native_snapshot.__module__
    class Find(hx.minsn_visitor_t):
        def __init__(self): super().__init__(); self.roots = []
        def visit_minsn(self):
            ins = self.curins
            if (ins.ea, ins.opcode, ins.d.size) in (
                (0x18F557265BF, hx.m_mul, 8), (0x18F55734E71, hx.m_add, 8)):
                self.roots.append(hx.minsn_t(ins))
            return 0
    roots = []
    for serial in range(native_mba.qty):
        ins = native_mba.get_mblock(serial).head
        while ins is not None:
            visitor = Find(); ins.for_all_insns(visitor); roots.extend(visitor.roots)
            ins = ins.next
    assert len(roots) == 2
    for root in roots:
        reference = None
        for snapshot_type in (native_snapshot, PythonMopSnapshot):
            for node_type, leaf_type in ((native_node, native_leaf), (p_ast.AstNode, p_ast.AstLeaf)):
                with monkeypatch.context() as patch:
                    patch.setattr(detect, 'MopSnapshot', snapshot_type)
                    patch.setattr(convert, 'AstNode', node_type)
                    patch.setattr(convert, 'AstLeaf', leaf_type)
                    capture = builder(); normalized = capture.instruction(root)
                    candidate = detect.MbaCandidate(root.ea, 0, normalized,
                        tuple(capture.snapshots), capture.snapshots, 8)
                    rebuilt = convert.build_replacement(candidate, normalized, root)
                    actual = (normalized, rebuilt.dstr(),
                              [(s.size, s.reg, s.valnum) for s in capture.snapshots.values()])
                    if reference is None: reference = actual
                    assert actual == reference


def test_width_solver_failure_keeps_error_on_cache_hit(monkeypatch):
    from d810_cobra.rules import cobra_solve as module
    from d810_cobra.solve import SolveResult, SolveStatus
    from d810_cobra.table import canonical_key
    rule = module.CobraSolveRule(); calls, terminals = [], []
    monkeypatch.setattr(module, 'binding_available', lambda: True)
    def fail(*args, **kwargs):
        calls.append(1)
        return SolveResult(SolveStatus.FAILED, reason='synthetic failure')
    monkeypatch.setattr(module, 'solve_signature', fail)
    monkeypatch.setattr(rule, '_finish_attempt', lambda status, reason=None, **kw:
                        terminals.append((status.value, reason)))
    ins = mixed_candidate()
    assert rule._check_and_replace(None, ins) is None
    assert rule._check_and_replace(None, ins) is None
    assert calls == [1]
    assert terminals == [('error', 'solver_failed')] * 2
    capture = builder(); tree = capture.instruction(ins)
    assert rule._width_lift_table.lookup(tree, 64) is None


def _balanced_width_input(leaves, narrow=False):
    def nested(ins):
        op = hx.mop_t(); op.create_from_insn(ins); return op
    if leaves == 1:
        leaf = reg(8, 1 if narrow else 8)
        return nested(instruction(hx.m_xdu, leaf)) if narrow else leaf
    left = leaves // 2
    return nested(instruction(hx.m_add,
        _balanced_width_input(left, narrow),
        _balanced_width_input(leaves-left, narrow)))


@pytest.mark.parametrize('narrow,leaves', [(False, 100), (True, 50)])
@pytest.mark.parametrize('extra_nodes', [0, 1, 2])
def test_width_expanded_node_budget_boundary(narrow, leaves, extra_nodes):
    from d810_cobra.expr import node_count
    op = _balanced_width_input(leaves, narrow)
    for _ in range(extra_nodes):
        outer = instruction(hx.m_neg, op)
        op = hx.mop_t(); op.create_from_insn(outer)
    capture = builder()
    if extra_nodes == 2:
        with pytest.raises(detect.UnsupportedMicrocode, match='width_lift_node_budget'):
            capture.instruction(instruction(hx.m_mov, op))
    else:
        tree = capture.instruction(instruction(hx.m_mov, op))
        assert node_count(tree) == 199 + extra_nodes


def test_width_wide_tree_stops_materializing_at_budget():
    capture = builder()
    with pytest.raises(detect.UnsupportedMicrocode, match='width_lift_node_budget'):
        capture.instruction(instruction(hx.m_mov, _balanced_width_input(1024)))
    assert capture._nodes == 200


def test_width_deep_tree_reports_depth_budget():
    op = reg(8, 8)
    for _ in range(30):
        # create_from_insn folds MOV operands; NEG retains a real native level.
        ins = instruction(hx.m_neg, op)
        op = hx.mop_t(); op.create_from_insn(ins)
    with pytest.raises(detect.UnsupportedMicrocode, match='width_lift_depth_budget'):
        builder().instruction(ins)
