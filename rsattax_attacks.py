"""
rsattax_attacks.py — Browser-friendly RSA attack runners for RSAttax.

Each attack is self-contained: it builds a vulnerable RSA instance that matches
the attack's precondition, encrypts the user's message, then recovers it using
only the public data an attacker would have. Returns a JSON-friendly dict.

Adapted from run_final.py (Dea Saka Kurnia Putra) to run fully client-side under
Pyodide — no file/flag dependencies, key sizes tuned for interactive speed.
"""
import time, math, random
import rsakit as k

E_DEFAULT = 0x10001


def _msg_int(message):
    b = message.encode("utf-8")
    return int.from_bytes(b, "big"), b


def _res(no, name, success, recovered, method, precond, t, extra="", public=None):
    return {
        "no": no,
        "name": name,
        "success": bool(success),
        "recovered": recovered,
        "method": method,
        "precondition": precond,
        "time_s": round(t, 3),
        "extra": extra,
        "public": public or {},
    }


def _shorten(n, head=18, tail=8):
    s = str(n)
    if len(s) <= head + tail + 3:
        return s
    return f"{s[:head]}…{s[-tail:]}  ({len(s)} digits)"


# ============================================================ 1. Fermat
def fermat(message, bits=512):
    t = time.time()
    M, FLAG = _msg_int(message)
    p = k.next_prime(2 ** (bits - 1) + random.randrange(2 ** 40))
    q = k.next_prime(p + random.randrange(2 ** 20))
    n = p * q; e = E_DEFAULT
    if M >= n:
        return _res(1, "Fermat Factorization", False, "pesan terlalu besar untuk modulus ini",
                    "b=sqrt(a^2-N)", "p,q berdekatan", time.time() - t)
    c = pow(M, e, n)
    a = k.isqrt(n)
    if a * a < n:
        a += 1
    while True:
        b2 = a * a - n; b = k.isqrt(b2)
        if b * b == b2:
            break
        a += 1
    pp, qq = a + b, a - b
    d = k.inverse(e, (pp - 1) * (qq - 1)); m = pow(c, d, n)
    ok = k.long_to_bytes(m) == FLAG
    return _res(1, "Fermat Factorization", ok, k.long_to_bytes(m).decode(errors="replace"),
                "b=√(a²−N), iterasi a dari ⌈√N⌉", "p, q berdekatan (|p−q| kecil)",
                time.time() - t, f"|p−q| = {abs(pp - qq)}",
                {"n": _shorten(n), "e": e, "c": _shorten(c)})


# ============================================================ 2. ECM (Lenstra)
def ecm(message, bits=40):
    t = time.time()
    M, FLAG = _msg_int(message)

    def ecm_factor(n, B1=2000, curves=300):
        if n % 2 == 0:
            return 2
        for _ in range(curves):
            x0 = random.randrange(2, n); y0 = random.randrange(2, n); A = random.randrange(1, n)

            def add_pt(P, Q):
                if P is None: return Q
                if Q is None: return P
                x1, y1 = P; x2, y2 = Q
                if x1 == x2 and (y1 + y2) % n == 0: return None
                if P == Q:
                    num = (3 * x1 * x1 + A) % n; den = (2 * y1) % n
                else:
                    num = (y2 - y1) % n; den = (x2 - x1) % n
                g = math.gcd(den, n)
                if 1 < g < n: raise ValueError(g)
                lam = num * pow(den, -1, n) % n
                x3 = (lam * lam - x1 - x2) % n
                return (x3, (lam * (x1 - x3) - y1) % n)

            def mul(P, mm):
                Rr = None
                while mm:
                    if mm & 1: Rr = add_pt(Rr, P)
                    P = add_pt(P, P); mm >>= 1
                return Rr
            try:
                P = (x0, y0)
                for pr in k.sieve_base:
                    if pr > B1: break
                    pk = pr
                    while pk * pr <= B1: pk *= pr
                    P = mul(P, pk)
                    if P is None: break
            except ValueError as ex:
                g = int(ex.args[0])
                if 1 < g < n: return g
        return None

    pe = k.getPrime(bits); qe = k.getPrime(bits); ne = pe * qe
    while math.gcd(ne, 6) != 1:
        pe = k.getPrime(bits); qe = k.getPrime(bits); ne = pe * qe
    f = ecm_factor(ne)
    ok = f is not None and ne % f == 0
    return _res(2, "Elliptic Curve Method (Lenstra)", ok,
                f"{f} × {ne // f}" if f else "gagal",
                "Kurva eliptik acak mod n, kalikan titik dengan B!-smooth, gcd denominator",
                "n punya faktor prima berukuran sedang", time.time() - t,
                f"n = {ne}", {"n": str(ne)})


# ============================================================ 3. Small public exponent (low e, no pad)
def small_e(message, bits=1024):
    t = time.time()
    M, FLAG = _msg_int(message)
    p = k.getPrime(bits); q = k.getPrime(bits); n = p * q; e = 3
    c = pow(M, e, n)
    if M ** e >= n:
        return _res(3, "Small Public Exponent Attack", False,
                    "m^e ≥ n — akar integer tak berlaku (perlu pesan lebih pendek / n lebih besar)",
                    "akar pangkat-e integer", "e kecil & m^e < n", time.time() - t)
    m = k.iroot(c, e)[0]
    ok = k.long_to_bytes(m) == FLAG
    return _res(3, "Small Public Exponent Attack", ok, k.long_to_bytes(m).decode(errors="replace"),
                "c = m^e tanpa reduksi mod n ⇒ m = ⁿ√c (akar integer)",
                "e kecil (3) dan pesan tak dipadding sehingga m^e < n",
                time.time() - t, "e = 3", {"n": _shorten(n), "e": 3, "c": _shorten(c)})


# ============================================================ 4. Common modulus
def common_modulus(message, bits=512):
    t = time.time()
    M, FLAG = _msg_int(message)
    p = k.getPrime(bits); q = k.getPrime(bits); n = p * q
    e1 = k.getPrime(bits // 2); e2 = k.getPrime(bits // 2)
    while math.gcd(e1, e2) != 1:
        e2 = k.getPrime(bits // 2)
    c1 = pow(M, e1, n); c2 = pow(M, e2, n)
    g, x, y = k.egcd(e1, e2)

    def spow(c, ex):
        return pow(c, ex, n) if ex >= 0 else pow(pow(c, -1, n), -ex, n)
    m = (spow(c1, x) * spow(c2, y)) % n
    ok = k.long_to_bytes(m) == FLAG
    return _res(4, "Common Modulus Attack", ok, k.long_to_bytes(m).decode(errors="replace"),
                "Identitas Bézout: m = c1^x · c2^y mod n", "modulus n sama, gcd(e1,e2)=1",
                time.time() - t, "", {"n": _shorten(n), "e1": _shorten(e1), "e2": _shorten(e2)})


# ============================================================ 5. Håstad broadcast
def hastad(message, e=17, bits=512):
    t = time.time()
    M, FLAG = _msg_int(message)
    Ns = []; Cs = []
    for _ in range(e):
        a = k.getPrime(bits); b = k.getPrime(bits); N = a * b
        Ns.append(N); Cs.append(pow(M, e, N))
    crtv = k.crt(Cs, Ns); m, exact = k.iroot(crtv, e)
    ok = exact and k.long_to_bytes(m) == FLAG
    return _res(5, "Håstad's Broadcast Attack", ok, k.long_to_bytes(m).decode(errors="replace"),
                "CRT atas e ciphertext ⇒ M^e mod ∏N, lalu akar pangkat-e",
                f"pesan sama dikirim ke ≥ e={e} penerima, e kecil, tanpa padding",
                time.time() - t, f"e = {e}, {e} penerima", {"e": e, "receivers": e})


# ============================================================ 6. Franklin-Reiter
def franklin_reiter(message, bits=1024):
    t = time.time()
    M, FLAG = _msg_int(message)
    p = k.getPrime(bits); q = k.getPrime(bits); n = p * q; e = 3
    # known linear relation m2 = m1 + delta (attacker knows delta, not m1/m2)
    delta = random.randrange(2 ** 64) | 1
    m2 = M + delta
    if M >= n or m2 >= n:
        return _res(6, "Franklin-Reiter Related Message", False, "pesan terlalu besar untuk modulus",
                    "gcd polinomial", "dua pesan berelasi linier, e kecil", time.time() - t)
    c1 = pow(M, e, n); c2 = pow(m2, e, n)

    def pmul(a, b):
        r = [0] * (len(a) + len(b) - 1)
        for i, ai in enumerate(a):
            for j, bj in enumerate(b):
                r[i + j] = (r[i + j] + ai * bj) % n
        return r
    # g2(x) = (x + delta)^e - c2
    lin = [delta % n, 1]; f2 = [1]
    for _ in range(e):
        f2 = pmul(f2, lin)
    f2[0] = (f2[0] - c2) % n
    # g1(x) = x^e - c1
    f1 = [(-c1) % n, 0, 0, 1]
    g = k.znpoly_gcd(f1, f2, n); mrec = (-g[0]) % n
    ok = k.long_to_bytes(mrec) == FLAG
    return _res(6, "Franklin-Reiter Related Message", ok, k.long_to_bytes(mrec).decode(errors="replace"),
                "gcd(x^e − c1, (x+δ)^e − c2) mod n ⇒ faktor linier (x − m)",
                "dua pesan berelasi linier (selisih δ diketahui), e kecil", time.time() - t,
                f"δ diketahui, e = {e}", {"n": _shorten(n), "e": 3})


# ============================================================ 8. Partial p exposure (Coppersmith)
def partial_p(message, bits=512, unknown=180):
    t = time.time()
    M, FLAG = _msg_int(message)
    p = k.getPrime(bits); q = k.getPrime(bits); n = p * q; e = k.getPrime(64); c = pow(M, e, n)
    leak = p >> unknown
    pol = [(leak * 2 ** unknown) % n, 1]; X = 2 ** unknown
    ok = False; rec = "gagal"
    for (mm, tt) in [(3, 3), (4, 4)]:
        roots = k.coppersmith_howgrave_univariate(pol, n, 0.5, mm, tt, X)
        if roots:
            pr = leak * 2 ** unknown + roots[0]
            if n % pr == 0 and 1 < pr < n:
                d = k.inverse(e, (pr - 1) * (n // pr - 1)); m = pow(c, d, n)
                rec = k.long_to_bytes(m).decode(errors="replace"); ok = (k.long_to_bytes(m) == FLAG)
                break
    return _res(8, "Partial Key Exposure (Coppersmith)", ok, rec,
                "Coppersmith / Howgrave-Graham: akar kecil f(x)=leak·2^u + x mod p",
                f"MSB p bocor ({bits - unknown} dari {bits} bit), sisa {unknown} bit dicari",
                time.time() - t, f"unknown = {unknown} bit", {"n": _shorten(n)})


# ============================================================ 20. self-test hook
def _selftest(message="RSAttax"):
    out = {}
    for aid in ATTACKS:
        r = run(aid, message)
        out[aid] = (r["success"], round(r["time_s"], 2))
    return out


# ============================================================ 10. Small private exponent (brute)
def small_d(message, bits=1024, d=2003):
    t = time.time()
    M, FLAG = _msg_int(message)
    p = k.getPrime(bits); q = k.getPrime(bits); n = p * q
    e = k.inverse(d, (p - 1) * (q - 1)); c = pow(M, e, n)
    found = None
    for dd in range(1, d + 1):
        m = pow(c, dd, n); b = k.long_to_bytes(m)
        try:
            b.decode()
            if b == FLAG:
                found = dd; break
        except UnicodeDecodeError:
            pass
    ok = found is not None
    return _res(10, "Small Private Exponent (brute)", ok,
                k.long_to_bytes(pow(c, found, n)).decode(errors="replace") if found else "gagal",
                "brute-force d kecil / dekripsi langsung", "d sangat kecil",
                time.time() - t, f"d = {found}", {"n": _shorten(n)})


# ============================================================ 11. Wiener
def wiener(message, bits=1024):
    t = time.time()
    M, FLAG = _msg_int(message)
    while True:
        p = k.getPrime(bits); q = k.getPrime(bits); n = p * q; phi = (p - 1) * (q - 1)
        d = k.getPrime(bits // 2 - 2)
        if math.gcd(d, phi) == 1:
            break
    e = k.inverse(d, phi); c = pow(M, e, n)

    def cf(a, b):
        r = []
        while b:
            r.append(a // b); a, b = b, a % b
        return r

    def convs(a):
        P = [0, 1]; Q = [1, 0]
        for it in a:
            P.append(P[-1] * it + P[-2]); Q.append(Q[-1] * it + Q[-2])
        return P, Q
    num, den = convs(cf(e, n)); dfound = None
    for kk, dd in zip(num, den):
        if kk == 0 or (e * dd - 1) % kk:
            continue
        ph = (e * dd - 1) // kk; bb = n - ph + 1; disc = bb * bb - 4 * n
        if disc < 0:
            continue
        s = k.isqrt(disc)
        if s * s == disc and ((bb + s) // 2) * ((bb - s) // 2) == n:
            dfound = dd; break
    ok = dfound is not None
    return _res(11, "Wiener's Attack", ok,
                k.long_to_bytes(pow(c, dfound, n)).decode(errors="replace") if dfound else "gagal",
                "pecahan kontinu e/n ⇒ konvergen k/d ⇒ faktorisasi", "d < ⅓·N^¼",
                time.time() - t, f"d = {d.bit_length()} bit", {"n": _shorten(n), "e": _shorten(e)})


# ============================================================ 13. Pollard p-1
def pollard_p1(message, bits=256, B=50000):
    t = time.time()
    M, FLAG = _msg_int(message)
    small = [pp for pp in k.sieve_base if pp < B]

    # build p with (p-1) B-smooth: p = 2*∏(small primes) + 1
    def smooth_prime(nbits):
        while True:
            f = 2
            while f.bit_length() < nbits:
                f *= random.choice(small)
            cand = f + 1
            if cand.bit_length() <= nbits + 2 and k.isPrime(cand):
                return cand
    p = smooth_prime(bits)
    q = k.getPrime(bits)
    while q == p:
        q = k.getPrime(bits)
    n = p * q; e = E_DEFAULT; c = pow(M % n, e, n)
    a = 2; g = 1
    for pr in small:
        pk = pr
        while pk * pr <= B: pk *= pr
        a = pow(a, pk, n); g = math.gcd(a - 1, n)
        if 1 < g < n: break
    ok = 1 < g < n
    rec = "gagal"
    if ok:
        pp = g; qq = n // pp
        if M < n:
            d = k.inverse(e, (pp - 1) * (qq - 1)); m = pow(c, d, n)
            rec = k.long_to_bytes(m).decode(errors="replace")
            ok = k.long_to_bytes(m) == FLAG
        else:
            rec = f"{pp} × {qq}"
    return _res(13, "Pollard's p−1 Method", ok, rec,
                "a^(∏ prime powers ≤ B) − 1 lalu gcd dengan n", "p−1 halus (B-smooth)",
                time.time() - t, f"B = {B}", {"n": _shorten(n)})


# ============================================================ 16. Blind signature / malleability
def blind_signature(message, bits=1024):
    t = time.time()
    M, FLAG = _msg_int(message)
    p = k.getPrime(bits); q = k.getPrime(bits); n = p * q; e = E_DEFAULT
    if M >= n:
        return _res(16, "Blind Signature Attack", False, "pesan terlalu besar",
                    "blinding", "akses oracle dekripsi", time.time() - t)
    d = k.inverse(e, (p - 1) * (q - 1))

    def oracle(ct):
        pt = pow(ct, d, n)
        return None if pt == M else pt
    fe = pow(M, e, n); fake = (fe * pow(2, e, n)) % n
    fd = oracle(fake); mrec = (fd * pow(2, -1, n)) % n
    ok = k.long_to_bytes(mrec) == FLAG
    return _res(16, "Blind Signature Attack", ok, k.long_to_bytes(mrec).decode(errors="replace"),
                "blinding c·2^e ⇒ oracle dekripsi ⇒ bagi 2", "akses oracle dekripsi (RSA malleable)",
                time.time() - t, "", {"n": _shorten(n), "e": e})


# ============================================================ 19. Stereotyped message (Coppersmith)
def stereotyped(message, bits=1024):
    t = time.time()
    M, FLAG = _msg_int(message)
    known = b"Merry Christmas and Happy New Year! I won't talk to you that the flag is: "
    plain = known + FLAG
    p = k.getPrime(bits); q = k.getPrime(bits); n = p * q; e = 3
    if int.from_bytes(plain, "big") ** 1 >= n and int.from_bytes(plain, "big") >= n:
        return _res(19, "Stereotyped Message Attack", False, "plaintext terlalu besar",
                    "Coppersmith univariat", "sebagian besar plaintext diketahui, e kecil",
                    time.time() - t)
    c = pow(int.from_bytes(plain, "big"), e, n)
    ki = int.from_bytes(known, "big"); Xb = len(FLAG) * 8 if len(FLAG) < 20 else 17 * 8
    base = [(ki * 2 ** Xb) % n, 1]

    def pmul2(a, b):
        r = [0] * (len(a) + len(b) - 1)
        for i, ai in enumerate(a):
            for j, bj in enumerate(b):
                r[i + j] = (r[i + j] + ai * bj) % n
        return r
    f = [1]
    for _ in range(3):
        f = pmul2(f, base)
    f[0] = (f[0] - c) % n
    pol = k.poly_trim([(x * k.inverse(f[-1], n)) % n for x in f])
    roots = k.coppersmith_howgrave_univariate(pol, n, 0.5, 1, 2, 2 ** Xb)
    ok = False; rec = "gagal"
    if roots:
        rb = k.long_to_bytes(ki * 2 ** Xb + roots[0])
        if rb == plain:
            rec = FLAG.decode(errors="replace"); ok = True
    return _res(19, "Stereotyped Message Attack", ok, rec,
                "Coppersmith univariat: akar kecil (known·2^k + x)^e − c mod n",
                "sebagian besar plaintext diketahui, bagian rahasia kecil, e kecil",
                time.time() - t, f"rahasia = {len(FLAG)} byte", {"n": _shorten(n), "e": 3})


# ============================================================ registry / dispatcher
ATTACKS = {
    "fermat": fermat,
    "ecm": ecm,
    "small_e": small_e,
    "common_modulus": common_modulus,
    "hastad": hastad,
    "franklin_reiter": franklin_reiter,
    "partial_p": partial_p,
    "small_d": small_d,
    "wiener": wiener,
    "pollard_p1": pollard_p1,
    "blind_signature": blind_signature,
    "stereotyped": stereotyped,
}


def run(attack_id, message):
    fn = ATTACKS.get(attack_id)
    if fn is None:
        return {"success": False, "recovered": f"unknown attack: {attack_id}", "name": attack_id}
    try:
        return fn(message)
    except Exception as ex:
        return {"no": 0, "name": attack_id, "success": False,
                "recovered": f"error: {type(ex).__name__}: {ex}", "method": "",
                "precondition": "", "time_s": 0, "extra": "", "public": {}}
