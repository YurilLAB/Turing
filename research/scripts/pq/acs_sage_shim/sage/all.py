"""acs_sage_shim/sage/all.py - a minimal stand-in for the parts of SageMath that the
lattice-estimator imports, so that the estimator can be run on a machine without SageMath.

WHAT THIS IS
  The lattice-estimator (github.com/malb/lattice-estimator, commit 53da598, 2026-08-19,
  LGPLv3+; clone kept in the scratch dir, not in this repository) is a SageMath module: every
  file does `from sage.all import ...`. SageMath is not installed on this machine. This file
  provides the ~35 names the estimator's LWE code imports, built on mpmath and scipy:

    numbers   RR, RealField, RDF, ZZ, QQ, parent, oo, pi, e, euler_gamma
    functions log, exp, sqrt, ceil, floor, round, binomial, erf, zeta, coth, tanh, prod
    tools     cached_function, find_root, RealDistribution, line (stub), PowerSeriesRing (stub)

  Real numbers are mpmath mpf at 53 bits of precision, like Sage's RR (MPFR, 53 bits), and like
  MPFR they have an unbounded exponent range (no float overflow at 2^1024). The Sage methods the
  estimator calls on numbers (.log(b), .n(), .sqrt(), .round(), .prec(), .str()) are attached
  to mpf.

WHAT THIS IS NOT
  It is not SageMath. Symbolic expressions do not exist here: every "symbolic" constant is a
  53-bit number. PowerSeriesRing (used only by the Arora-Groebner estimate) is not provided.
  The shim is trusted ONLY as far as research/scripts/pq/acs_estimator_run.py validates it,
  by reproducing the estimator's own published outputs (README and docs at commit 53da598).

Deterministic; no network; used only by acs_estimator_run.py.
"""
import builtins
import fractions
import functools
import math

import mpmath
import scipy.optimize
import scipy.stats

mpmath.mp.prec = 53
_mpf = mpmath.mpf


def _to_mpf(x):
    if isinstance(x, _mpf):
        return x
    if isinstance(x, fractions.Fraction):
        return _mpf(x.numerator) / x.denominator
    return _mpf(x)


def _is_integral(x):
    if isinstance(x, (bool, int)):
        return True
    if isinstance(x, fractions.Fraction):
        return x.denominator == 1
    try:
        v = _to_mpf(x)
    except (TypeError, ValueError):
        return False
    return (not mpmath.isinf(v)) and (not mpmath.isnan(v)) and v == mpmath.floor(v)


# ---------------------------------------------------------------- MPFR division semantics
# Sage's RR follows MPFR: x / 0 is +-infinity (NaN for 0/0), not an exception. The estimator
# relies on this in prob.amplify: when log(1 - 4 eps^2) is 0 even at 2048 bits, Sage returns an
# infinite trial count, ceil() of it raises ValueError, and amplify() returns oo.
_orig_div = _mpf.__truediv__
_orig_rdiv = _mpf.__rtruediv__


def _div(self, other):
    try:
        return _orig_div(self, other)
    except ZeroDivisionError:
        return mpmath.nan if self == 0 else (mpmath.inf if self > 0 else -mpmath.inf)


def _rdiv(self, other):
    try:
        return _orig_rdiv(self, other)
    except ZeroDivisionError:
        o = _to_mpf(other)
        return mpmath.nan if o == 0 else (mpmath.inf if o > 0 else -mpmath.inf)


_mpf.__truediv__ = _div
_mpf.__rtruediv__ = _rdiv
if hasattr(_mpf, "__div__"):
    _mpf.__div__ = _div
    _mpf.__rdiv__ = _rdiv


# ---------------------------------------------------------------- numbers
class _mpfHP(_mpf):
    """An element of RealField(p) with p > 53 bits: arithmetic, log, exp and sqrt on it run
    at p bits (mpmath.workprec), as Sage's RealField(p) elements do. The estimator needs this
    in prob.amplify, where log(1 - 4 eps^2) with eps ~ 2^-40 is 0 at 53 bits."""

    __slots__ = ("_p",)


def _wrap(r, p):
    if isinstance(r, _mpf) and not isinstance(r, mpmath.mpc):
        v = object.__new__(_mpfHP)
        v._mpf_ = r._mpf_
        v._p = p
        return v
    return r


def _hp_binop(name):
    base = getattr(_mpf, name)

    def op(self, other):
        p = self._p
        if isinstance(other, _mpfHP):
            p = max(p, other._p)
        with mpmath.workprec(p):
            r = base(self, other)
        return _wrap(r, p) if r is not NotImplemented else r
    return op


for _name in ("__add__", "__radd__", "__sub__", "__rsub__", "__mul__", "__rmul__",
              "__truediv__", "__rtruediv__", "__pow__", "__rpow__"):
    setattr(_mpfHP, _name, _hp_binop(_name))
_mpfHP.__neg__ = lambda self: _wrap(_mpf.__neg__(self), self._p)
_mpfHP.__pos__ = lambda self: self
_mpfHP.__abs__ = lambda self: _wrap(_mpf.__abs__(self), self._p)
_mpfHP.prec = lambda self: self._p


def _hp_call(fn, x):
    """Evaluate an mpmath function at x's precision when x is a RealField(p > 53) element."""
    if isinstance(x, _mpfHP):
        with mpmath.workprec(x._p):
            return _wrap(fn(x), x._p)
    return fn(x)


class _RealField:
    """RR / RealField(prec): RR (53 bits) gives plain mpf; RealField(p > 53) gives _mpfHP
    elements whose arithmetic runs at p bits."""

    def __init__(self, prec=53):
        self._prec = int(prec)

    def __call__(self, x=0):
        if self._prec > 53:
            with mpmath.workprec(self._prec):
                v = _mpf(x) if isinstance(x, str) else _to_mpf(+x if isinstance(x, _mpf) else x)
            return _wrap(v, self._prec)
        if isinstance(x, str):
            return _mpf(x)
        if isinstance(x, _Infinity):
            return _mpf(float(x))
        return _to_mpf(x)

    def prec(self):
        return self._prec

    def pi(self):
        return +mpmath.pi

    def __repr__(self):
        return f"Real Field with {self._prec} bits of precision (acs_sage_shim)"


RR = _RealField(53)


def RealField(prec=53):
    return _RealField(prec)


class _RDF:
    def __call__(self, x):
        return float(x)

    def pi(self):
        return math.pi


RDF = _RDF()


def parent(x):
    return RR


class Integer(int):
    """ZZ element. Like Sage's Integer, true division never overflows: a / b is computed as an
    mpf (unbounded exponent) instead of Python's float, which overflows above 2^1024 (seen in
    the estimator's coded-BKW sample count q^b / 2). Integer results stay Integers."""

    def __truediv__(self, other):
        return _to_mpf(int(self)) / (other if not isinstance(other, int) else _mpf(int(other)))

    def __rtruediv__(self, other):
        return (_to_mpf(other) if not isinstance(other, int) else _mpf(int(other))) / _mpf(int(self))

    def __repr__(self):
        return int.__repr__(self)


def _int_op(name):
    base = getattr(int, name)

    def op(self, *args):
        r = base(self, *args)
        return Integer(r) if (type(r) is int) else r
    return op


for _name in ("__add__", "__radd__", "__sub__", "__rsub__", "__mul__", "__rmul__", "__floordiv__",
              "__rfloordiv__", "__mod__", "__rmod__", "__pow__", "__neg__", "__abs__", "__pos__"):
    setattr(Integer, _name, _int_op(_name))


class _ZZ:
    def __call__(self, x):
        if isinstance(x, bool):
            return Integer(int(x))
        if isinstance(x, int):
            return Integer(x)
        if _is_integral(x):
            if isinstance(x, fractions.Fraction):
                return Integer(x.numerator)
            return Integer(int(_to_mpf(x)))
        raise TypeError(f"acs_sage_shim: {x!r} is not an integer")

    def __repr__(self):
        return "Integer Ring (acs_sage_shim)"


ZZ = _ZZ()


class _Rational(fractions.Fraction):
    """QQ element; arithmetic between rationals stays in QQ (as in Sage), so .round() exists."""

    def round(self, mode="away"):
        if mode == "down":
            return math.floor(self)
        if mode == "up":
            return math.ceil(self)
        if mode == "toward":
            return math.trunc(self)
        return round(self)


def _rat_op(name):
    base = getattr(fractions.Fraction, name)

    def op(self, *args):
        r = base(self, *args)
        return _Rational(r) if isinstance(r, fractions.Fraction) else r
    return op


for _name in ("__add__", "__radd__", "__sub__", "__rsub__", "__mul__", "__rmul__", "__truediv__",
              "__rtruediv__", "__pow__", "__neg__", "__abs__", "__pos__"):
    setattr(_Rational, _name, _rat_op(_name))


def QQ(x):
    if isinstance(x, _mpf):
        return _Rational(float(x))
    return _Rational(x)


# ---------------------------------------------------------------- Sage's symbolic infinity
class _Infinity(_mpf):
    """Sage's oo / -oo. Arithmetic that stays infinite stays symbolic, and ceil/floor/round
    return it unchanged, whereas a NUMERICAL infinity (an RR value such as x / 0) makes
    ceil/floor/round raise ValueError, as Sage's RealNumber.ceil() does. The estimator relies on
    that ValueError (prob.amplify returns oo when it is raised)."""

    __slots__ = ()


def _mk_inf(neg=False):
    v = object.__new__(_Infinity)
    v._mpf_ = (-mpmath.inf if neg else mpmath.inf)._mpf_
    return v


def _inf_op(name):
    base = getattr(_mpf, name)

    def op(self, *args):
        r = base(self, *args)
        if isinstance(r, _mpf) and mpmath.isinf(r):
            return _mk_inf(r < 0)
        return r
    return op


for _name in ("__add__", "__radd__", "__sub__", "__rsub__", "__mul__", "__rmul__", "__truediv__",
              "__rtruediv__", "__pow__", "__rpow__"):
    setattr(_Infinity, _name, _inf_op(_name))
_Infinity.__neg__ = lambda self: _mk_inf(not (self < 0))
_Infinity.__pos__ = lambda self: self
_Infinity.__abs__ = lambda self: _mk_inf(False)

oo = _mk_inf(False)
pi = +mpmath.pi
e = +mpmath.e
euler_gamma = +mpmath.euler


# ---------------------------------------------------------------- mpf methods Sage code calls
def _m_log(self, base=None):
    if base is None:
        return _hp_call(mpmath.log, self)
    return _hp_call(lambda y: mpmath.log(y, base), self)


_mpf.log = _m_log
_mpf.n = lambda self, *a, **k: self
_mpf.sqrt = lambda self: _hp_call(mpmath.sqrt, self)
_mpf.exp = lambda self: _hp_call(mpmath.exp, self)
_mpf.round = lambda self, *a: round(self)
_mpf.prec = lambda self: getattr(self, '_p', 53)
_mpf.str = lambda self, *a, **k: mpmath.nstr(self, 15)
_mpf.is_infinity = lambda self: bool(mpmath.isinf(self))
_mpf.is_infinite = lambda self: bool(mpmath.isinf(self))
_mpf.is_NaN = lambda self: bool(mpmath.isnan(self))
_mpf.abs = lambda self: abs(self)


def _m_array(self, dtype=None, copy=None):
    import numpy
    return numpy.asarray(float(self), dtype=dtype if dtype is not None else float)


_mpf.__array__ = _m_array   # numpy sees a float (Sage's RealNumber also converts to float)


# ---------------------------------------------------------------- functions
def _numeric_inf_check(v, what):
    """Sage: symbolic oo passes through ceil/floor/round; a numerical RR infinity or NaN raises
    ValueError ('Calling ceil() on infinity or NaN')."""
    if isinstance(v, _Infinity):
        return True
    if mpmath.isinf(v) or mpmath.isnan(v):
        raise ValueError(f"Calling {what}() on infinity or NaN")
    return False


def log(x, base=None):
    if isinstance(x, _Infinity) and x > 0:
        return oo
    if not isinstance(x, (mpmath.mpc,)):
        x = _to_mpf(x)
    if base is None:
        return _hp_call(mpmath.log, x)
    return _hp_call(lambda y: mpmath.log(y, base), x)


def exp(x):
    if isinstance(x, _Infinity):
        return oo if x > 0 else _mpf(0)
    return _hp_call(mpmath.exp, _to_mpf(x) if not isinstance(x, mpmath.mpc) else x)


def sqrt(x):
    if isinstance(x, _Infinity) and x > 0:
        return oo
    return _hp_call(mpmath.sqrt, _to_mpf(x))


def ceil(x):
    if isinstance(x, int):
        return x
    v = _to_mpf(x)
    if _numeric_inf_check(v, "ceil"):
        return v
    return int(mpmath.ceil(v))


def floor(x):
    if isinstance(x, int):
        return x
    v = _to_mpf(x)
    if _numeric_inf_check(v, "floor"):
        return v
    return int(mpmath.floor(v))


def round(x, ndigits=None):
    """Sage's round: nearest integer, halves away from zero; with ndigits, a real."""
    if ndigits is not None:
        return _mpf(builtins.round(float(x), ndigits))
    if isinstance(x, int):
        return x
    v = _to_mpf(x)
    if _numeric_inf_check(v, "round"):
        return v
    if v >= 0:
        return int(mpmath.floor(v + _mpf(0.5)))
    return -int(mpmath.floor(-v + _mpf(0.5)))


def binomial(n, k):
    if _is_integral(n) and _is_integral(k):
        n, k = int(_to_mpf(n)), int(_to_mpf(k))
        if k < 0:
            return 0
        if n >= 0:
            return math.comb(n, k) if k <= n else 0
    return mpmath.binomial(_to_mpf(n), _to_mpf(k))


def erf(x):
    return mpmath.erf(_to_mpf(x))


def zeta(x):
    return mpmath.zeta(_to_mpf(x))


def coth(x):
    return mpmath.coth(_to_mpf(x))


def tanh(x):
    return mpmath.tanh(_to_mpf(x))


def prod(it):
    r = 1
    for x in it:
        r = r * x
    return r


# ---------------------------------------------------------------- tools
def cached_function(f):
    """functools-style memoisation; unhashable arguments are simply not cached."""
    cache = {}

    @functools.wraps(f)
    def g(*args, **kwargs):
        try:
            key = (args, tuple(sorted(kwargs.items())))
            hash(key)
        except TypeError:
            return f(*args, **kwargs)
        if key not in cache:
            cache[key] = f(*args, **kwargs)
        return cache[key]

    g.cache = cache
    return g


def find_root(f, a, b, **kwargs):
    """Sage's find_root(f, a, b) also brackets with scipy's brentq."""
    return _mpf(scipy.optimize.brentq(lambda x: float(f(x)), float(a), float(b)))


class RealDistribution:
    def __init__(self, kind, params):
        if kind == "chisquared":
            self._d = scipy.stats.chi2(float(params))
        elif kind == "beta":
            a, b = params
            self._d = scipy.stats.beta(float(a), float(b))
        elif kind == "gaussian":
            self._d = scipy.stats.norm(scale=float(params))
        else:
            raise NotImplementedError(f"acs_sage_shim: RealDistribution({kind!r})")

    def cum_distribution_function(self, x):
        return float(self._d.cdf(float(x)))

    def cum_distribution_function_inv(self, x):
        return float(self._d.ppf(float(x)))

    def distribution_function(self, x):
        return float(self._d.pdf(float(x)))


def line(*args, **kwargs):
    raise NotImplementedError("acs_sage_shim: plotting is not provided")


def PowerSeriesRing(*args, **kwargs):
    raise NotImplementedError("acs_sage_shim: PowerSeriesRing (Arora-Groebner) is not provided")


def var(*args, **kwargs):
    raise NotImplementedError("acs_sage_shim: symbolic variables are not provided")


def find_fit(*args, **kwargs):
    raise NotImplementedError("acs_sage_shim: find_fit is not provided")
