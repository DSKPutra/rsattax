"""
rsakit.py — Pure-Python cryptanalysis toolkit.
Replaces PyCryptodome (Crypto.Util.number), gmpy2, and the SageMath helpers
(LLL + Coppersmith) used by the RSA-Attacks repository, so the attacks can run
in a fully offline environment (no external packages, no SageMath).
"""
import math
import random
from fractions import Fraction

# ----------------------------------------------------------------------------
# Basic number theory
# ----------------------------------------------------------------------------
def gcd(a, b):
    return math.gcd(int(a), int(b))

def egcd(a, b):
    if b == 0:
        return (a, 1, 0)
    g, x, y = egcd(b, a % b)
    return (g, y, x - (a // b) * y)

def inverse(a, m):
    return pow(int(a) % int(m), -1, int(m))

def isqrt(n):
    return math.isqrt(int(n))

def iroot(x, n):
    """Integer n-th root; returns (root, is_exact) like gmpy2.iroot."""
    x = int(x); n = int(n)
    if x < 0:
        raise ValueError("negative")
    if x == 0:
        return (0, True)
    if n == 1:
        return (x, True)
    hi = 1
    while hi ** n <= x:
        hi <<= 1
    lo = hi >> 1
    while lo < hi:
        mid = (lo + hi) // 2
        if mid ** n <= x:
            lo = mid + 1
        else:
            hi = mid
    r = lo - 1
    return (r, r ** n == x)

# Miller-Rabin primality
_SMALL_PRIMES = [2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97]

def isPrime(n):
    n = int(n)
    if n < 2:
        return False
    for p in _SMALL_PRIMES:
        if n % p == 0:
            return n == p
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for a in _SMALL_PRIMES:
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True

def next_prime(n):
    n = int(n) + 1
    if n <= 2:
        return 2
    if n % 2 == 0:
        n += 1
    while not isPrime(n):
        n += 2
    return n

def getRandomNBitInteger(nbit):
    return random.getrandbits(nbit) | (1 << (nbit - 1))

def getPrime(nbit):
    while True:
        cand = getRandomNBitInteger(nbit) | 1
        if isPrime(cand):
            return cand

# byte <-> int
def bytes_to_long(b):
    return int.from_bytes(b, "big")

def long_to_bytes(n, blocksize=0):
    n = int(n)
    length = (n.bit_length() + 7) // 8
    if length == 0:
        length = 1
    b = n.to_bytes(length, "big")
    return b

# sieve of small primes (Crypto.Util.number.sieve_base)
def sieve(limit):
    bs = bytearray([1]) * (limit + 1)
    bs[0] = bs[1] = 0
    for i in range(2, isqrt(limit) + 1):
        if bs[i]:
            bs[i*i::i] = bytearray(len(bs[i*i::i]))
    return [i for i in range(limit + 1) if bs[i]]

sieve_base = sieve(100000)

# Chinese Remainder Theorem
def crt(residues, moduli):
    from functools import reduce
    N = reduce(lambda a, b: a * b, moduli)
    x = 0
    for a, m in zip(residues, moduli):
        Ni = N // m
        x += a * Ni * inverse(Ni, m)
    return x % N

# ----------------------------------------------------------------------------
# Exact LLL lattice reduction (integer input, rational Gram-Schmidt)
# ----------------------------------------------------------------------------
def LLL(B, delta=Fraction(3, 4)):
    """LLL reduction of the rows of integer matrix B (list of lists).
    Exact arithmetic with Fraction. Returns reduced basis (list of lists of int)."""
    B = [[Fraction(int(x)) for x in row] for row in B]
    n = len(B)
    if n == 0:
        return []
    m = len(B[0])

    def dot(u, v):
        return sum(a * b for a, b in zip(u, v))

    # Gram-Schmidt
    Bstar = [[Fraction(0)] * m for _ in range(n)]
    mu = [[Fraction(0)] * n for _ in range(n)]

    def gram_schmidt():
        for i in range(n):
            Bstar[i] = list(B[i])
            for j in range(i):
                denom = dot(Bstar[j], Bstar[j])
                mu[i][j] = dot(B[i], Bstar[j]) / denom if denom != 0 else Fraction(0)
                for k in range(m):
                    Bstar[i][k] -= mu[i][j] * Bstar[j][k]

    gram_schmidt()
    k = 1
    while k < n:
        for j in range(k - 1, -1, -1):
            if abs(mu[k][j]) > Fraction(1, 2):
                q = (mu[k][j] + Fraction(1, 2)).__floor__()  # round to nearest
                for idx in range(m):
                    B[k][idx] -= q * B[j][idx]
                gram_schmidt()
        Bk = dot(Bstar[k], Bstar[k])
        Bk1 = dot(Bstar[k - 1], Bstar[k - 1])
        if Bk >= (delta - mu[k][k - 1] ** 2) * Bk1:
            k += 1
        else:
            B[k], B[k - 1] = B[k - 1], B[k]
            gram_schmidt()
            k = max(k - 1, 1)
    return [[int(x) for x in row] for row in B]

# ----------------------------------------------------------------------------
# Integer LLL (Cohen, "A Course in Computational Algebraic Number Theory",
# Algorithm 2.6.3). Exact integer arithmetic with incremental Gram data —
# far faster than naive rational Gram-Schmidt for Coppersmith lattices.
# ----------------------------------------------------------------------------
def LLL_int(basis):
    b = [list(map(int, row)) for row in basis]
    n = len(b)
    if n == 0:
        return []
    def dot(u, v):
        return sum(x * y for x, y in zip(u, v))
    d = [0] * (n + 1)
    d[0] = 1
    lam = [[0] * (n + 1) for _ in range(n + 1)]  # 1-indexed
    d[1] = dot(b[0], b[0])
    k = 2
    kmax = 1

    def REDI(k, l):
        if 2 * abs(lam[k][l]) <= d[l]:
            return
        q = (2 * lam[k][l] + d[l]) // (2 * d[l])  # nearest integer round
        bk = b[k - 1]; bl = b[l - 1]
        for i in range(len(bk)):
            bk[i] -= q * bl[i]
        lam[k][l] -= q * d[l]
        for i in range(1, l):
            lam[k][i] -= q * lam[l][i]

    def SWAPI(k):
        b[k - 1], b[k - 2] = b[k - 2], b[k - 1]
        if k > 2:
            for j in range(1, k - 1):
                lam[k][j], lam[k - 1][j] = lam[k - 1][j], lam[k][j]
        lmb = lam[k][k - 1]
        B = (d[k - 2] * d[k] + lmb * lmb) // d[k - 1]
        for i in range(k + 1, kmax + 1):
            t = lam[i][k]
            lam[i][k] = (d[k] * lam[i][k - 1] - lmb * t) // d[k - 1]
            lam[i][k - 1] = (B * t + lmb * lam[i][k]) // d[k]
        d[k - 1] = B

    while k <= n:
        if k > kmax:
            kmax = k
            for j in range(1, k + 1):
                u = dot(b[k - 1], b[j - 1])
                for i in range(1, j):
                    u = (d[i] * u - lam[k][i] * lam[j][i]) // d[i - 1]
                if j < k:
                    lam[k][j] = u
                else:
                    d[k] = u
        while True:
            REDI(k, k - 1)
            if 4 * d[k] * d[k - 2] < 3 * d[k - 1] * d[k - 1] - 4 * lam[k][k - 1] * lam[k][k - 1]:
                SWAPI(k)
                k = max(2, k - 1)
            else:
                for l in range(k - 2, 0, -1):
                    REDI(k, l)
                k += 1
                break
    return b

# ----------------------------------------------------------------------------
# Univariate polynomial helpers (dense coefficient lists, low->high degree)
# ----------------------------------------------------------------------------
def poly_trim(p):
    while len(p) > 1 and p[-1] == 0:
        p.pop()
    return p

def poly_mul(a, b):
    r = [0] * (len(a) + len(b) - 1)
    for i, ai in enumerate(a):
        if ai:
            for j, bj in enumerate(b):
                r[i + j] += ai * bj
    return poly_trim(r)

def poly_eval(p, x):
    r = 0
    for c in reversed(p):
        r = r * x + c
    return r

# integer roots of a univariate polynomial (coeffs low->high) via rational root
# + refinement; used to factor the Coppersmith output polynomial over Z.
def poly_roots_int(coeffs, bound=None):
    coeffs = poly_trim([int(c) for c in coeffs])
    roots = set()
    if len(coeffs) == 1:
        return []
    # try small integer / divisor-based roots
    a0 = coeffs[0]
    an = coeffs[-1]
    if a0 == 0:
        roots.add(0)
    # candidate divisors of a0/an (rational root theorem, integer roots only)
    def divisors(x):
        x = abs(int(x))
        if x == 0:
            return []
        ds = set()
        i = 1
        while i * i <= x:
            if x % i == 0:
                ds.add(i); ds.add(x // i)
            i += 1
        return ds
    cands = set()
    for p in divisors(a0):
        cands.add(p); cands.add(-p)
    # Newton / bisection fallback for large roots
    for c in list(cands):
        if poly_eval(coeffs, c) == 0:
            roots.add(c)
    # Also attempt find real roots numerically then verify integer nearby
    # (handles large roots not covered by divisor search)
    try:
        approx = _real_roots_numeric(coeffs)
        for r in approx:
            ri = round(r)
            for cand in (ri - 1, ri, ri + 1):
                if poly_eval(coeffs, cand) == 0:
                    roots.add(cand)
    except Exception:
        pass
    if bound is not None:
        roots = {r for r in roots if abs(r) <= bound}
    return sorted(roots)

def _real_roots_numeric(coeffs):
    """Rough real roots via numpy-free companion-matrix-free approach:
    use float Durand-Kerner. coeffs low->high."""
    deg = len(coeffs) - 1
    if deg <= 0:
        return []
    lead = coeffs[-1]
    c = [Fraction(x, lead) for x in coeffs]
    # scale down huge numbers using floats carefully via logs is complex;
    # fall back to float with mpmath-like Durand-Kerner in Python floats.
    cf = [float(x) for x in c]
    import cmath
    roots = [cmath.exp(2j * cmath.pi * k / deg) * (0.4 + 0.9j) for k in range(deg)]
    def f(x):
        r = 0
        for coef in reversed(cf):
            r = r * x + coef
        return r
    for _ in range(500):
        newr = []
        for i in range(deg):
            xi = roots[i]
            denom = 1
            for j in range(deg):
                if j != i:
                    denom *= (xi - roots[j])
            if denom == 0:
                newr.append(xi)
            else:
                newr.append(xi - f(xi) / denom)
        roots = newr
    return [r.real for r in roots if abs(r.imag) < 1e-6]

# ----------------------------------------------------------------------------
# Coppersmith (Howgrave-Graham), univariate — mirrors sage_functions.py
# finds x0 with |x0|<XX and gcd(f(x0), N) >= N^beta
# ----------------------------------------------------------------------------
def ipow_beta(N, beta):
    """floor(N**beta) for possibly-huge integer N and float beta, exactly enough."""
    N = int(N)
    if beta >= 1:
        return N
    if abs(beta - 0.5) < 1e-12:
        return isqrt(N)
    from decimal import Decimal, getcontext
    getcontext().prec = len(str(N)) + 20
    val = (Decimal(N).ln() * Decimal(str(beta))).exp()
    return int(val)

def coppersmith_howgrave_univariate(pol, modulus, beta, mm, tt, XX):
    """pol: coefficient list low->high, MONIC (leading coeff == 1)."""
    pol = poly_trim([int(c) for c in pol])
    dd = len(pol) - 1
    nn = dd * mm + tt
    assert pol[-1] == 1, "polynomial must be monic"

    # polZ(x*XX) as a coeff list in x: coeff_i * XX^i
    def scaled(p):
        return [p[i] * (XX ** i) for i in range(len(p))]

    polX = scaled(pol)  # polZ(x*XX)

    gg = []
    for ii in range(mm):
        # (x*XX)^jj * N^(mm-ii) * polX^ii
        base = [1]
        for _ in range(ii):
            base = poly_mul(base, polX)
        Nfac = modulus ** (mm - ii)
        base = [c * Nfac for c in base]
        for jj in range(dd):
            shift = [0] * jj + [XX ** jj]
            gg.append(poly_mul(shift, base))
    polXm = [1]
    for _ in range(mm):
        polXm = poly_mul(polXm, polX)
    for ii in range(tt):
        shift = [0] * ii + [XX ** ii]
        gg.append(poly_mul(shift, polXm))

    # Build lower-triangular lattice (nn x nn)
    BB = [[0] * nn for _ in range(nn)]
    for i in range(nn):
        row = gg[i]
        for j in range(min(len(row), nn)):
            BB[i][j] = row[j]

    BB = LLL_int(BB)

    # Convert several short vectors into integer polynomials (coeff_i / XX^i),
    # then take their GCD over Q -> collapses to the linear factor (x - x0).
    polys = []
    for r in range(min(nn, 6)):
        vec = []
        ok = True
        for ii in range(nn):
            v = BB[r][ii]
            if v % (XX ** ii) != 0:
                ok = False
                break
            vec.append(v // (XX ** ii))
        if ok:
            vec = poly_trim(vec)
            if len(vec) > 1:
                polys.append([Fraction(x) for x in vec])

    thresh = ipow_beta(modulus, beta)
    roots = set()

    def qgcd(a, b):
        a = list(a); b = list(b)
        while poly_trim_q(b):
            _, r = poly_divmod_q(a, b)
            a, b = b, poly_trim_q(r)
        # make monic
        if a and a[-1] != 0:
            lead = a[-1]
            a = [c / lead for c in a]
        return a

    def int_roots_of_lowdeg(g):
        """integer roots of a rational poly of degree 1 or 2."""
        g = poly_trim_q(g)
        out = []
        if len(g) == 2:
            c0, c1 = g[0], g[1]
            if c1 != 0:
                v = -c0 / c1
                if v.denominator == 1:
                    out.append(int(v))
        elif len(g) == 3:
            c0, c1, c2 = g[0], g[1], g[2]
            disc = c1 * c1 - 4 * c2 * c0
            if disc >= 0:
                s = isqrt(int(disc.numerator)) if disc.denominator == 1 else None
                # disc must be a perfect-square rational
                num = disc.numerator; den = disc.denominator
                sn = isqrt(num); sd = isqrt(den)
                if sn * sn == num and sd * sd == den:
                    sq = Fraction(sn, sd)
                    for v in ((-c1 + sq) / (2 * c2), (-c1 - sq) / (2 * c2)):
                        if v.denominator == 1:
                            out.append(int(v))
        return out

    cand = set()
    # pairwise GCDs — only polynomials sharing the root give a common factor
    L = len(polys)
    for i in range(L):
        # a lone linear poly already gives the root
        if len(polys[i]) <= 3:
            for r in int_roots_of_lowdeg([c / polys[i][-1] for c in polys[i]]):
                cand.add(r)
        for j in range(i + 1, L):
            g = qgcd(polys[i], polys[j])
            if 2 <= len(g) <= 3:
                for r in int_roots_of_lowdeg(g):
                    cand.add(r)
    if not cand and polys:
        try:
            cand.update(_roots_scaled_numeric(polys[0], XX))
        except Exception:
            pass

    for r in cand:
        if abs(r) <= XX:
            result = poly_eval(pol, r)
            g = gcd(modulus, result)
            # accept a nontrivial factor (>=thresh, or any >1 for the smaller
            # prime just below n^0.5) or a full-modulus root (g==modulus)
            if g >= thresh or 1 < g <= modulus:
                roots.add(r)
    return sorted(roots)

def poly_trim_q(p):
    p = list(p)
    while len(p) > 0 and p[-1] == 0:
        p.pop()
    return p

def poly_divmod_q(a, b):
    a = [Fraction(x) for x in a]; b = [Fraction(x) for x in b]
    b = poly_trim_q(b)
    q = [Fraction(0)] * max(1, len(a) - len(b) + 1)
    r = list(a)
    while len(poly_trim_q(r)) >= len(b):
        r = poly_trim_q(r)
        if len(r) < len(b):
            break
        coef = r[-1] / b[-1]
        shift = len(r) - len(b)
        q[shift] = coef
        for i in range(len(b)):
            r[shift + i] -= coef * b[i]
        r = poly_trim_q(r)
    return q, r

def _roots_scaled_numeric(coeffs, XX):
    """Find integer roots near real roots by rescaling x = XX*u so coeffs stay
    moderate, then Durand-Kerner in floats. coeffs may be Fraction/int."""
    coeffs = [Fraction(c) for c in coeffs]
    deg = len(coeffs) - 1
    if deg <= 0:
        return []
    # substitute x = XX*u : coeff_i * XX^i, then normalize by max magnitude
    scaled = [coeffs[i] * (XX ** i) for i in range(len(coeffs))]
    mx = max((abs(x) for x in scaled), default=Fraction(1))
    if mx == 0:
        return []
    scaledf = []
    for x in scaled:
        r = x / mx  # |r| <= 1, float-safe
        scaledf.append(float(r))
    rts = _real_roots_numeric([Fraction(v).limit_denominator(10**9) for v in scaledf])
    out = []
    for u in rts:
        xr = u * XX
        ri = round(xr)
        for cand in range(ri - 3, ri + 4):
            out.append(int(cand))
    return out

# small_roots wrapper mirroring the sage defund/coppersmith style used in
# Partial-p / Stereotyped attacks: f monic over Zmod(n), find |x|<X with
# gcd(f(x), n) >= n^beta. Auto-picks m,t.
def small_roots_univariate(pol, N, X, beta=1.0, m=None):
    pol = poly_trim([int(c) % N for c in pol])
    # make monic
    lead = pol[-1]
    inv = inverse(lead, N)
    pol = [(c * inv) % N for c in pol]
    delta = len(pol) - 1
    if m is None:
        # epsilon = beta^2/delta - log_N(2X)
        eps = beta * beta / delta - (math.log(2 * X) / math.log(N))
        if eps <= 0:
            m = 4
        else:
            m = max(math.ceil(beta * beta / (delta * eps)), math.ceil(7 * beta / delta))
    t = int(math.floor(delta * m * (1.0 / beta - 1)))
    if t < 0:
        t = 0
    return coppersmith_howgrave_univariate(pol, N, beta, m, t, X)

# ----------------------------------------------------------------------------
# Polynomial GCD over Z/n (for Franklin-Reiter / Short Pad final step)
# coeffs low->high, arithmetic mod n. Returns monic gcd or raises on zero-div
# (which would actually reveal a factor of n).
# ----------------------------------------------------------------------------
class ZnPolyError(Exception):
    def __init__(self, factor):
        self.factor = factor

def _znpoly_monic(p, n):
    p = [c % n for c in p]
    while len(p) > 1 and p[-1] == 0:
        p.pop()
    if p == [0]:
        return p
    lead = p[-1]
    g = gcd(lead, n)
    if 1 < g < n:
        raise ZnPolyError(g)
    inv = inverse(lead, n)
    return [(c * inv) % n for c in p]

def _znpoly_divmod(a, b, n):
    a = [c % n for c in a]
    b = [c % n for c in b]
    while len(b) > 1 and b[-1] == 0:
        b.pop()
    lead = b[-1]
    g = gcd(lead, n)
    if 1 < g < n:
        raise ZnPolyError(g)
    invlead = inverse(lead, n)
    q = [0] * max(1, len(a) - len(b) + 1)
    r = list(a)
    while len(r) >= len(b) and not (len(r) == 1 and r[0] == 0):
        deg_r = len(r) - 1
        deg_b = len(b) - 1
        if deg_r < deg_b:
            break
        coef = (r[-1] * invlead) % n
        shift = deg_r - deg_b
        q[shift] = coef
        for i in range(len(b)):
            r[shift + i] = (r[shift + i] - coef * b[i]) % n
        while len(r) > 1 and r[-1] == 0:
            r.pop()
    return q, r

def znpoly_gcd(a, b, n):
    a = [c % n for c in a]
    b = [c % n for c in b]
    while True:
        while len(b) > 1 and b[-1] == 0:
            b.pop()
        if len(b) == 1 and b[0] == 0:
            return _znpoly_monic(a, n)
        _, r = _znpoly_divmod(a, b, n)
        a, b = b, r
