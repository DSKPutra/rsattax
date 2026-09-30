"""
rsattax_iso.py — Browser-friendly wrapper around pkc_iso_lab.py.

Exposes the ISO/IEC conformance/validation battery (Part A of the lab) as
JSON-friendly functions for RSAttax. Heavy RSA-2048 keygen from the original
demo() is replaced by a fast lab key so the self-test stays interactive.

Standards mapped:
  [18032]        Miller-Rabin primality
  [18033-2]      RSA public-key validation
  [15946-1]      EC public-key (P-256) point validation
  [19790/24759]  Known-Answer Test (SHA-256) + RSA pairwise consistency
"""
import math
import pkc_iso_lab as lab


def _grp(std, name, checks, pass_):
    return {"std": std, "name": name, "checks": checks, "pass": bool(pass_)}


def standards_selftest():
    """Run the fast conformance battery; returns a list of check groups."""
    groups = []

    # [18032] Miller-Rabin primality
    mr_97 = lab.miller_rabin(97)
    mr_561 = lab.miller_rabin(561)  # Carmichael → must be composite (False)
    mr_2048b = lab.miller_rabin((1 << 2048) - 1)  # composite
    groups.append(_grp("ISO/IEC 18032", "Uji primalitas Miller-Rabin", [
        {"label": "97 → prima", "value": str(mr_97), "ok": mr_97 is True},
        {"label": "561 (Carmichael) → komposit", "value": str(mr_561), "ok": mr_561 is False},
        {"label": "2²⁰⁴⁸−1 → komposit", "value": str(mr_2048b), "ok": mr_2048b is False},
    ], mr_97 and (not mr_561) and (not mr_2048b)))

    # [15946-1] EC public-key validation on P-256
    gen_ok = lab.validate_ec_public_key(lab.P256_GX, lab.P256_GY)["PASS"]
    bad_ok = lab.validate_ec_public_key(lab.P256_GX, lab.P256_GY + 1)["PASS"]
    groups.append(_grp("ISO/IEC 15946-1", "Validasi kunci publik EC (P-256)", [
        {"label": "generator G di kurva", "value": str(gen_ok), "ok": gen_ok is True},
        {"label": "titik palsu (Gy+1) ditolak", "value": str(bad_ok), "ok": bad_ok is False},
    ], gen_ok and not bad_ok))

    # [19790/24759] SHA-256 Known-Answer Test
    kat = lab.sha256_known_answer_test()
    groups.append(_grp("ISO/IEC 19790 / 24759", "Known-Answer Test (SHA-256)", [
        {"label": 'SHA-256("") sesuai vektor uji', "value": str(kat), "ok": kat is True},
    ], kat))

    # [18033-2] + [19790] RSA pubkey validation + pairwise consistency (fast lab key)
    p = lab.generate_prime(512)
    q = lab.generate_prime(512)
    n = p * q
    e = 65537
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    rep = lab.validate_rsa_public_key(n, e, min_modulus_bits=1024)
    pw = lab.rsa_pairwise_consistency_test(n, e, d)
    groups.append(_grp("ISO/IEC 18033-2 / 19790",
                       f"Validasi kunci publik RSA + pairwise ({n.bit_length()}-bit lab key)", [
        {"label": f"panjang modulus = {rep['modulus_bits']} bit (≥1024 lab)", "value": str(rep["modulus_ok"]), "ok": rep["modulus_ok"]},
        {"label": "e = 65537 (direkomendasikan)", "value": str(rep["e_recommended_65537"]), "ok": rep["e_recommended_65537"]},
        {"label": "e ganjil & dalam rentang", "value": str(rep["e_odd"] and rep["e_in_range"]), "ok": rep["e_odd"] and rep["e_in_range"]},
        {"label": "n komposit (bukan prima)", "value": str(rep["n_not_prime"]), "ok": rep["n_not_prime"]},
        {"label": "pairwise consistency (enc→dec)", "value": str(pw), "ok": pw},
    ], rep["PASS"] and pw))

    passed = sum(1 for g in groups if g["pass"])
    return {"groups": groups, "passed": passed, "total": len(groups)}


def _parse_int(s):
    s = str(s).strip().replace("_", "").replace(" ", "")
    if s.lower().startswith("0x"):
        return int(s, 16)
    # allow bare hex if it has hex letters
    try:
        return int(s, 10)
    except ValueError:
        return int(s, 16)


def validate_public_key(n_str, e_str, min_bits=2048):
    """Validate a user-supplied RSA public key against ISO/IEC 18033-2."""
    try:
        n = _parse_int(n_str)
        e = _parse_int(e_str)
    except Exception as ex:
        return {"error": f"input tidak valid: {ex}"}
    if n < 2:
        return {"error": "n harus ≥ 2"}
    rep = lab.validate_rsa_public_key(n, e, min_modulus_bits=min_bits)
    checks = [
        {"label": f"panjang modulus = {rep['modulus_bits']} bit (≥ {min_bits})", "value": str(rep["modulus_ok"]), "ok": rep["modulus_ok"]},
        {"label": "e ganjil", "value": str(rep["e_odd"]), "ok": rep["e_odd"]},
        {"label": "3 ≤ e < n", "value": str(rep["e_in_range"]), "ok": rep["e_in_range"]},
        {"label": "e = 65537 (direkomendasikan)", "value": str(rep["e_recommended_65537"]), "ok": rep["e_recommended_65537"]},
        {"label": "n ganjil", "value": str(rep["n_not_even"]), "ok": rep["n_not_even"]},
        {"label": "n komposit (bukan prima)", "value": str(rep["n_not_prime"]), "ok": rep["n_not_prime"]},
    ]
    return {"modulus_bits": rep["modulus_bits"], "checks": checks, "pass": bool(rep["PASS"])}
