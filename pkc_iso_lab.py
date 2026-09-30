#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pkc_iso_lab.py
==============
Toolkit EDUKASI untuk pelatihan Cryptographic Analyst.

Bagian A -- PENGUJIAN (conformance / validation) kunci publik, dipetakan ke ISO/IEC.
Bagian B -- KRIPTANALISIS klasik terhadap parameter yang SENGAJA dibuat lemah,
            hanya pada kunci lab buatan sendiri, untuk memahami mengapa standar
            menetapkan syarat parameter tertentu.

Catatan penting:
  * Serangan di bawah hanya berhasil pada kunci lemah berukuran mainan (toy keys).
    Kunci produksi yang memenuhi ISO/IEC 18033-2 / FIPS 186-5 kebal terhadapnya.
  * Hanya memakai Python standard library (Python >= 3.8). Tidak ada dependensi luar.
  * Jalankan: python3 pkc_iso_lab.py

Pemetaan standar (ringkas):
  [18032]     Uji & pembangkitan bilangan prima (Miller-Rabin)
  [18033-2]   Validasi parameter/kunci publik RSA
  [15946-1]   Validasi kunci publik kurva eliptik (contoh: P-256)
  [19790/24759] Known-Answer Test (KAT) & pairwise consistency test
"""

from __future__ import annotations
import secrets
import hashlib
import math
from math import gcd, isqrt


# ==========================================================================
# BAGIAN A -- PENGUJIAN / VALIDASI (sesuai ISO/IEC)
# ==========================================================================

# --------------------------------------------------------------------------
# [ISO/IEC 18032] Uji primalitas Miller-Rabin + pembangkitan prima
# --------------------------------------------------------------------------
def miller_rabin(n: int, rounds: int = 40) -> bool:
    """Uji primalitas probabilistik Miller-Rabin.

    ISO/IEC 18032 mensyaratkan jumlah ronde cukup agar probabilitas
    kesalahan <= 2^-100 untuk ukuran kunci kriptografi.
    """
    if n < 2:
        return False
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    for p in small_primes:
        if n % p == 0:
            return n == p
    # tulis n-1 = d * 2^s dengan d ganjil
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2  # 2 <= a <= n-2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False  # komposit
    return True  # prima (probabilistik)


def generate_prime(bits: int) -> int:
    """Bangkitkan prima acak sepanjang `bits` bit (untuk demo)."""
    while True:
        # set dua bit tertinggi -> jaminan hasil kali dua prima tepat 2*bits bit
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | (1 << (bits - 2)) | 1
        if miller_rabin(candidate):
            return candidate


# --------------------------------------------------------------------------
# [ISO/IEC 18033-2] Validasi kunci publik RSA
# --------------------------------------------------------------------------
def validate_rsa_public_key(n: int, e: int, min_modulus_bits: int = 2048) -> dict:
    """Cek kesesuaian kunci publik RSA terhadap syarat keamanan.

    Yang diperiksa:
      1. Panjang modulus n memenuhi minimum (>= 2048 bit direkomendasikan).
      2. Eksponen publik e ganjil dan dalam rentang aman (umumnya 65537).
      3. gcd(e, ...) benar (e tidak boleh 1).
      4. n bukan bilangan genap / bukan prima (harus hasil kali dua prima).
    """
    report = {}
    bits = n.bit_length()
    report["modulus_bits"] = bits
    report["modulus_ok"] = bits >= min_modulus_bits
    report["e_odd"] = (e % 2 == 1)
    report["e_in_range"] = (3 <= e < n)
    report["e_recommended_65537"] = (e == 65537)
    report["n_not_even"] = (n % 2 == 1)
    report["n_not_prime"] = not miller_rabin(n)  # n harus komposit (p*q)
    report["PASS"] = all([
        report["modulus_ok"], report["e_odd"],
        report["e_in_range"], report["n_not_even"], report["n_not_prime"],
    ])
    return report


# --------------------------------------------------------------------------
# [ISO/IEC 15946-1] Validasi kunci publik kurva eliptik (kurva P-256 / NIST)
# --------------------------------------------------------------------------
# Parameter kurva P-256 (secp256r1) -- standar publik.
P256_P  = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
P256_A  = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
P256_B  = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
P256_N  = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
P256_GX = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
P256_GY = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5


def ec_is_on_curve(x: int, y: int,
                   p: int = P256_P, a: int = P256_A, b: int = P256_B) -> bool:
    """Cek apakah titik (x, y) memenuhi y^2 = x^3 + a*x + b (mod p)."""
    return (y * y - (x * x * x + a * x + b)) % p == 0


def validate_ec_public_key(x: int, y: int) -> dict:
    """Validasi kunci publik EC (ISO/IEC 15946-1 / SEC 1).

    Langkah wajib:
      1. Titik bukan titik tak-hingga.
      2. Koordinat dalam [0, p-1].
      3. Titik benar-benar berada di kurva (mencegah invalid-curve attack).
    """
    report = {}
    report["not_infinity"] = not (x is None or y is None)
    report["x_in_field"] = (0 <= x < P256_P)
    report["y_in_field"] = (0 <= y < P256_P)
    report["on_curve"] = ec_is_on_curve(x, y)
    report["PASS"] = all(report.values())
    return report


# --------------------------------------------------------------------------
# [ISO/IEC 19790 / 24759] Known-Answer Test & Pairwise Consistency Test
# --------------------------------------------------------------------------
def rsa_pairwise_consistency_test(n: int, e: int, d: int) -> bool:
    """Pairwise consistency test RSA: enkripsi lalu dekripsi harus kembali.

    Modul kripto (ISO/IEC 19790) wajib menjalankan uji ini tiap kali
    pasangan kunci baru dibangkitkan, sebelum kunci dipakai.
    """
    m = secrets.randbelow(n - 2) + 1
    c = pow(m, e, n)
    m2 = pow(c, d, n)
    return m == m2


def sha256_known_answer_test() -> bool:
    """KAT sederhana untuk fungsi hash (baseline self-test modul)."""
    expected = ("e3b0c44298fc1c149afbf4c8996fb924"
                "27ae41e4649b934ca495991b7852b855")  # SHA-256("")
    return hashlib.sha256(b"").hexdigest() == expected


# ==========================================================================
# BAGIAN B -- KRIPTANALISIS PADA PARAMETER LEMAH (toy keys buatan sendiri)
# ==========================================================================

# --------------------------------------------------------------------------
# B1. Faktorisasi RSA modulus kecil (mengapa 18033-2 minta >= 2048 bit)
#     Metode: trial division + Fermat + Pollard's rho.
# --------------------------------------------------------------------------
def fermat_factor(n: int, max_iter: int = 1_000_000):
    """Faktorisasi Fermat: efektif jika p dan q berdekatan (kesalahan generasi)."""
    a = isqrt(n)
    if a * a < n:
        a += 1
    for _ in range(max_iter):
        b2 = a * a - n
        b = isqrt(b2)
        if b * b == b2:
            return (a - b, a + b)
        a += 1
    return None


def pollards_rho(n: int):
    """Pollard's rho -- faktorisasi cepat untuk faktor kecil/menengah."""
    if n % 2 == 0:
        return 2
    x = secrets.randbelow(n - 2) + 2
    y = x
    c = secrets.randbelow(n - 1) + 1
    d = 1
    while d == 1:
        x = (x * x + c) % n
        y = (y * y + c) % n
        y = (y * y + c) % n
        d = gcd(abs(x - y), n)
    return None if d == n else d


def attack_factor_rsa(n: int):
    """Coba faktorkan n dengan beberapa metode; kembalikan (p, q) atau None."""
    # 1) trial division untuk faktor sangat kecil
    for p in range(2, 100000):
        if n % p == 0:
            return (p, n // p)
    # 2) Fermat (p,q berdekatan)
    f = fermat_factor(n, max_iter=200000)
    if f:
        return f
    # 3) Pollard's rho
    for _ in range(20):
        d = pollards_rho(n)
        if d and 1 < d < n:
            return (d, n // d)
    return None


# --------------------------------------------------------------------------
# B2. Serangan Wiener -- private exponent d terlalu kecil (d < n^0.25 / 3)
# --------------------------------------------------------------------------
def continued_fraction(numerator: int, denominator: int):
    """Ekspansi pecahan kontinu dari numerator/denominator."""
    cf = []
    while denominator:
        cf.append(numerator // denominator)
        numerator, denominator = denominator, numerator % denominator
    return cf


def convergents(cf):
    """Hasilkan konvergen (h/k) dari daftar pecahan kontinu."""
    h_prev, h_cur = 0, 1
    k_prev, k_cur = 1, 0
    for a in cf:
        h_prev, h_cur = h_cur, a * h_cur + h_prev
        k_prev, k_cur = k_cur, a * k_cur + k_prev
        yield h_cur, k_cur


def wiener_attack(e: int, n: int):
    """Pulihkan d bila d kecil (Wiener). Kembalikan d atau None."""
    for k, d in convergents(continued_fraction(e, n)):
        if k == 0:
            continue
        if (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        # selesaikan x^2 - (n - phi + 1)x + n = 0 -> akar = p, q
        b = n - phi + 1
        disc = b * b - 4 * n
        if disc >= 0:
            sq = isqrt(disc)
            if sq * sq == disc and (b + sq) % 2 == 0:
                return d
    return None


# --------------------------------------------------------------------------
# B3. Common-modulus attack -- dua pengguna berbagi n dengan e1, e2 koprima
# --------------------------------------------------------------------------
def egcd(a: int, b: int):
    if b == 0:
        return (a, 1, 0)
    g, x, y = egcd(b, a % b)
    return (g, y, x - (a // b) * y)


def common_modulus_attack(c1: int, c2: int, e1: int, e2: int, n: int):
    """Pulihkan m bila pesan sama dienkripsi dengan (e1,n) dan (e2,n), gcd(e1,e2)=1."""
    g, s1, s2 = egcd(e1, e2)
    if g != 1:
        return None
    # m = c1^s1 * c2^s2 mod n  (tangani eksponen negatif via invers)
    if s1 < 0:
        c1 = pow(c1, -1, n)
        s1 = -s1
    if s2 < 0:
        c2 = pow(c2, -1, n)
        s2 = -s2
    return (pow(c1, s1, n) * pow(c2, s2, n)) % n


# --------------------------------------------------------------------------
# B4. Håstad broadcast -- e kecil (mis. e=3) tanpa padding, dikirim ke >= e pihak
# --------------------------------------------------------------------------
def crt(residues, moduli):
    """Chinese Remainder Theorem."""
    N = 1
    for m in moduli:
        N *= m
    x = 0
    for r, m in zip(residues, moduli):
        Ni = N // m
        x += r * Ni * pow(Ni, -1, m)
    return x % N, N


def integer_nth_root(x: int, nth: int):
    """Akar-n bulat eksak (untuk mencabut m dari m^e)."""
    if x < 0:
        return None
    lo, hi = 0, 1 << ((x.bit_length() // nth) + 2)
    while lo < hi:
        mid = (lo + hi) // 2
        if mid ** nth < x:
            lo = mid + 1
        else:
            hi = mid
    return lo if lo ** nth == x else None


def hastad_broadcast_attack(ciphertexts, moduli, e: int):
    """Pulihkan m bila m^e dikirim (tanpa padding) ke e penerima berbeda."""
    x, _ = crt(ciphertexts, moduli)  # x = m^e (karena m^e < prod(moduli))
    return integer_nth_root(x, e)


# ==========================================================================
# DEMO -- pembangkitan kunci lab + jalankan pengujian & serangan
# ==========================================================================
def _int_to_bytes(i: int) -> bytes:
    return i.to_bytes((i.bit_length() + 7) // 8 or 1, "big")


def demo():
    line = "=" * 70
    print(line)
    print(" BAGIAN A -- PENGUJIAN / VALIDASI (ISO/IEC)")
    print(line)

    # --- [18032] Miller-Rabin ---
    print("\n[18032] Uji primalitas Miller-Rabin:")
    print("  97 prima?    ->", miller_rabin(97))
    print("  561 prima?   ->", miller_rabin(561), "(Carmichael, harus False)")

    # Kunci RSA 'benar' 2048-bit untuk validasi (butuh beberapa detik)
    print("\n[18033-2] Membangkitkan RSA-2048 untuk validasi kunci publik...")
    p = generate_prime(1024)
    q = generate_prime(1024)
    n = p * q
    e = 65537
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    rep = validate_rsa_public_key(n, e)
    for k, v in rep.items():
        print(f"    {k:22s}: {v}")

    # --- [19790/24759] KAT & pairwise consistency ---
    print("\n[19790/24759] Self-test modul kripto:")
    print("  SHA-256 KAT             ->", sha256_known_answer_test())
    print("  RSA pairwise consistency->", rsa_pairwise_consistency_test(n, e, d))

    # --- [15946-1] Validasi titik EC ---
    print("\n[15946-1] Validasi kunci publik EC (generator P-256):")
    rep_ec = validate_ec_public_key(P256_GX, P256_GY)
    for k, v in rep_ec.items():
        print(f"    {k:14s}: {v}")
    print("  Titik palsu (Gx, Gy+1)  ->",
          validate_ec_public_key(P256_GX, P256_GY + 1)["PASS"], "(harus False)")

    print("\n" + line)
    print(" BAGIAN B -- KRIPTANALISIS PADA KUNCI LEMAH (toy keys)")
    print(line)

    # --- B1. Faktorisasi modulus kecil ---
    print("\n[B1] Faktorisasi RSA modulus kecil:")
    p_s, q_s = generate_prime(32), generate_prime(32)
    n_s = p_s * q_s
    print(f"  n = {n_s} ({n_s.bit_length()} bit)")
    fac = attack_factor_rsa(n_s)
    print(f"  Hasil faktorisasi -> {fac}")
    print(f"  Benar?            -> {fac and fac[0] * fac[1] == n_s}")

    # --- B2. Serangan Wiener (d kecil) ---
    print("\n[B2] Serangan Wiener (private exponent kecil):")
    pw, qw = generate_prime(256), generate_prime(256)
    nw = pw * qw
    phiw = (pw - 1) * (qw - 1)
    # pilih d kecil lalu e = d^-1 mod phi (kondisi rentan Wiener)
    d_small = 3
    while gcd(d_small, phiw) != 1:
        d_small += 2
    ew = pow(d_small, -1, phiw)
    recovered = wiener_attack(ew, nw)
    print(f"  d asli    = {d_small}")
    print(f"  d pulih   = {recovered}")
    print(f"  Berhasil? -> {recovered == d_small}")

    # --- B3. Common-modulus attack ---
    print("\n[B3] Common-modulus attack:")
    m = int.from_bytes(b"RAHASIA", "big")
    e1, e2 = 3, 65537  # gcd(3, 65537) = 1
    c1, c2 = pow(m, e1, n), pow(m, e2, n)
    m_rec = common_modulus_attack(c1, c2, e1, e2, n)
    print(f"  m asli  = {m}")
    print(f"  m pulih = {m_rec}")
    print(f"  Pesan   -> {_int_to_bytes(m_rec) if m_rec else None}")

    # --- B4. Håstad broadcast (e=3, tanpa padding) ---
    print("\n[B4] Hastad broadcast attack (e=3, tanpa padding):")
    e_b = 3
    msg = int.from_bytes(b"HALO", "big")
    mods, cts = [], []
    for _ in range(e_b):
        pa, qa = generate_prime(256), generate_prime(256)
        na = pa * qa
        mods.append(na)
        cts.append(pow(msg, e_b, na))
    m_b = hastad_broadcast_attack(cts, mods, e_b)
    print(f"  m asli  = {msg}")
    print(f"  m pulih = {m_b}")
    print(f"  Pesan   -> {_int_to_bytes(m_b) if m_b else None}")

    print("\n" + line)
    print(" Selesai. Semua serangan hanya menembus parameter LEMAH.")
    print(" Kunci yang memenuhi ISO/IEC 18033-2 / FIPS 186-5 kebal terhadapnya.")
    print(line)


if __name__ == "__main__":
    demo()
