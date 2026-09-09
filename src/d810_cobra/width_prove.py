"""Bounded Z3 stage proofs for one-variable linear Boolean width lifts.

Normalization is not authority: original outer structure, every Boolean
kernel, coefficient collection, modular reductions and final equality must
all be proved. Unsupported grammar and an exhausted shared deadline abstain.
"""
from __future__ import annotations

import json
import time

from d810_cobra import prove
from d810_cobra.prove import ProofResult

MAX_NODES = 200
MAX_DEPTH = 24
MAX_KERNELS = 32
MAX_PARTITIONS = 64
MAX_OBLIGATIONS = 128


class _Unsupported(ValueError):
    pass


def _validate(tree, width, deadline):
    pending = [(tree, 1)]
    count = 0
    names = set()
    while pending:
        if time.perf_counter() >= deadline:
            raise TimeoutError
        node, depth = pending.pop()
        count += 1
        if count > MAX_NODES or depth > MAX_DEPTH or not isinstance(node, dict):
            raise _Unsupported('input budget')
        kind = node.get('kind')
        fields = {'const': {'kind', 'value'}, 'var': {'kind', 'name'},
                  'un': {'kind', 'op', 'a'}, 'bin': {'kind', 'op', 'a', 'b'}}
        if kind not in fields or set(node) != fields[kind]:
            raise _Unsupported('unexpected node fields')
        if kind == 'const':
            value = node.get('value')
            if type(value) is not int or value.bit_length() > width:
                raise _Unsupported('constant')
        elif kind == 'var':
            name = node.get('name')
            if not isinstance(name, str) or len(name) > 256:
                raise _Unsupported('variable')
            names.add(name)
        elif kind == 'un' and node.get('op') in ('~', '-'):
            pending.append((node['a'], depth + 1))
        elif kind == 'bin' and node.get('op') in ('+', '-', '*', '&', '|', '^'):
            pending.extend(((node['a'], depth + 1), (node['b'], depth + 1)))
        else:
            raise _Unsupported('opcode')
    return names


def _boolean(tree):
    kind = tree['kind']
    if kind in ('var', 'const'):
        return True
    if kind == 'un':
        return tree['op'] == '~' and _boolean(tree['a'])
    return tree['op'] in ('&', '|', '^') and _boolean(tree['a']) and _boolean(tree['b'])


def _linearize(tree, mask, coefficient=1):
    coefficient &= mask
    if _boolean(tree):
        return [(coefficient, tree)]
    kind, op = tree['kind'], tree['op']
    if kind == 'un' and op == '-':
        return _linearize(tree['a'], mask, -coefficient)
    if kind == 'bin' and op in ('+', '-'):
        return (_linearize(tree['a'], mask, coefficient)
                + _linearize(tree['b'], mask, coefficient if op == '+' else -coefficient))
    if kind == 'bin' and op == '*':
        a, b = tree['a'], tree['b']
        if a['kind'] == 'const':
            return _linearize(b, mask, coefficient * a['value'])
        if b['kind'] == 'const':
            return _linearize(a, mask, coefficient * b['value'])
    raise _Unsupported('nonlinear or arithmetic under Boolean operation')


def _bit_value(tree, bit, variable_bit):
    kind = tree['kind']
    if kind == 'var':
        return variable_bit
    if kind == 'const':
        return (tree['value'] >> bit) & 1
    a = _bit_value(tree['a'], bit, variable_bit)
    if kind == 'un':
        return 1 - a
    b = _bit_value(tree['b'], bit, variable_bit)
    return {'&': a & b, '|': a | b, '^': a ^ b}[tree['op']]


def _prepare(source, candidate, width):
    mask = (1 << width) - 1
    pairs = [_linearize(source, mask), _linearize(candidate, mask)]
    if any(len(entries) > MAX_KERNELS for entries in pairs):
        raise _Unsupported('kernel budget')
    constants = set()
    pending = [source, candidate]
    while pending:
        node = pending.pop()
        if node['kind'] == 'const':
            constants.add(node['value'] & mask)
        for slot in ('a', 'b'):
            if slot in node:
                pending.append(node[slot])
    constants = sorted(constants)
    parts, previous = [], None
    for bit in range(width):
        signature = tuple((value >> bit) & 1 for value in constants)
        if signature != previous:
            parts.append({'low_bit': bit, 'mask': 0})
        parts[-1]['mask'] |= 1 << bit
        previous = signature
    if len(parts) > MAX_PARTITIONS:
        raise _Unsupported('partition budget')
    if 5 + sum(map(len, pairs)) + 2 * len(parts) > MAX_OBLIGATIONS:
        raise _Unsupported('obligation budget')
    sides = []
    for entries in pairs:
        constant, coefficients, kernels = 0, [0] * len(parts), []
        for weight, kernel in entries:
            c, cs = 0, []
            for part in parts:
                zero = _bit_value(kernel, part['low_bit'], 0)
                one = _bit_value(kernel, part['low_bit'], 1)
                c = (c + zero * part['mask']) & mask
                cs.append((one - zero) & mask)
            kernels.append({'weight': weight, 'tree': kernel, 'constant': c, 'coefficients': cs})
            constant = (constant + weight * c) & mask
            coefficients = [(a + weight * b) & mask for a, b in zip(coefficients, cs)]
        sides.append({'constant': constant, 'raw_coefficients': coefficients,
                      'coefficients': [value % (1 << (width-part['low_bit']))
                                       for value, part in zip(coefficients, parts)],
                      'kernels': kernels})
    return parts, sides


def prove_width_equivalent(source, candidate, leaf_names, bitwidth, *, timeout_ms=1500):
    """Return PROVED only after the full independently checked stage chain."""
    deadline = time.perf_counter() + max(0, timeout_ms) / 1000
    try:
        if bitwidth not in (8, 16, 32, 64):
            raise _Unsupported('width')
        names = _validate(source, bitwidth, deadline) | _validate(candidate, bitwidth, deadline)
        if len(names) != 1 or set(leaf_names) != names:
            raise _Unsupported('requires one exact symbolic variable')
        parts, sides = _prepare(source, candidate, bitwidth)
        if time.perf_counter() >= deadline:
            return ProofResult.UNKNOWN
        if not prove.z3_available():
            return ProofResult.UNAVAILABLE
        z3 = prove.z3
        x = z3.BitVec(next(iter(names)), bitwidth)
        atoms = [x & part['mask'] for part in parts]
        checks = 0

        def check(lhs, rhs, *, final=False):
            nonlocal checks
            checks += 1
            remaining = int((deadline - time.perf_counter()) * 1000)
            if remaining <= 0 or checks > MAX_OBLIGATIONS:
                raise TimeoutError
            solver = z3.Solver()
            solver.add(lhs != rhs)
            remaining = int((deadline - time.perf_counter()) * 1000)
            if remaining <= 0:
                raise TimeoutError
            solver.set(timeout=remaining)
            result = solver.check()
            if result == z3.sat:
                if final:
                    raise _Refuted
                raise _Unsupported('normalization stage counterexample')
            if result != z3.unsat or time.perf_counter() >= deadline:
                raise TimeoutError

        def summ(constant, coefficients, symbols):
            result = z3.BitVecVal(constant, bitwidth)
            for coefficient, symbol in zip(coefficients, symbols):
                result = result + coefficient * symbol
            return result

        def key(tree):
            return json.dumps(tree, sort_keys=True)

        for original, data in zip((source, candidate), sides):
            entries = [(kernel['weight'], kernel['tree']) for kernel in data['kernels']]
            env = {key(kernel): z3.FreshConst(z3.BitVecSort(bitwidth)) for _, kernel in entries}

            def skeleton(tree):
                if _boolean(tree):
                    return env[key(tree)]
                if tree['kind'] == 'un':
                    return -skeleton(tree['a'])
                if tree['op'] == '*':
                    if tree['a']['kind'] == 'const':
                        return tree['a']['value'] * skeleton(tree['b'])
                    return skeleton(tree['a']) * tree['b']['value']
                if tree['op'] == '+':
                    return skeleton(tree['a']) + skeleton(tree['b'])
                return skeleton(tree['a']) - skeleton(tree['b'])

            # Stage 1 is independently derived from the original outer tree.
            check(skeleton(original), sum((weight * env[key(kernel)] for weight, kernel in entries),
                                          z3.BitVecVal(0, bitwidth)))
            for kernel in data['kernels']:
                # Stage 2 uses the original kernel, never its normalized stand-in.
                check(prove._to_z3(kernel['tree'], {next(iter(names)): x}, bitwidth),
                      summ(kernel['constant'], kernel['coefficients'], atoms))
            symbols = [z3.FreshConst(z3.BitVecSort(bitwidth)) for _ in parts]
            weighted = z3.BitVecVal(0, bitwidth)
            for kernel in data['kernels']:
                weighted += kernel['weight'] * summ(kernel['constant'], kernel['coefficients'], symbols)
            # Independent partition symbols avoid assuming the final identity.
            check(weighted, summ(data['constant'], data['raw_coefficients'], symbols))
            for raw, reduced, atom in zip(data['raw_coefficients'], data['coefficients'], atoms):
                check(raw * atom, reduced * atom)
        check(summ(sides[0]['constant'], sides[0]['coefficients'], atoms),
              summ(sides[1]['constant'], sides[1]['coefficients'], atoms), final=True)
        return ProofResult.PROVED
    except _Refuted:
        return ProofResult.REFUTED
    except (TimeoutError, _Unsupported, KeyError, TypeError, ValueError):
        return ProofResult.UNKNOWN


class _Refuted(Exception):
    pass
