"""Frozen Unicode14 C*/Zl/Zp exclusion contract shared with the HTTPS client.

Generated once with CPython Unicode 14.0.0. All C categories (including Cn,
private use and surrogates) remain forbidden, even if later UCDs assign them.
LF is an independent explicit single/multiline exception, never in this table.
"""
from bisect import bisect_right
import hashlib
import json
from pathlib import Path

_VERSION = 'unicode-14.0.0-C-Zl-Zp-v1'
_SHA256 = 'e83baed34ac406005cd17ef0433d0bee688fa67f6a3e6e807998555b7849acba'
_raw = Path(__file__).with_name('unicode14_forbidden.json').read_bytes().rstrip(b'\n')
if hashlib.sha256(_raw).hexdigest() != _SHA256:
    raise RuntimeError('invalid Unicode contract artifact')
_contract = json.loads(_raw)
_ranges = tuple(tuple(pair) for pair in _contract['forbidden_ranges'])
_starts = tuple(lo for lo, hi in _ranges)


def public_contract():
    """Fresh containers: session serialization cannot mutate server policy."""
    return {'version': _VERSION, 'forbidden_ranges': [list(pair) for pair in _ranges]}


def validate_contract(value):
    # JSON canonical identity also rejects booleans/floats posing as code points.
    if json.dumps(value, sort_keys=True, separators=(',', ':')) != _raw.decode('ascii'):
        raise ValueError('invalid Unicode contract')


def accepts_scalar(cp):
    if type(cp) is not int or not 0 <= cp <= 0x10ffff:
        return False
    i = bisect_right(_starts, cp) - 1
    return i < 0 or cp > _ranges[i][1]
