# 🔓 RSAttax — RSA Attack Suite

**RSAttax** adalah laboratorium kriptanalisis RSA interaktif yang berjalan **sepenuhnya di dalam browser** lewat [Pyodide](https://pyodide.org) (CPython dikompilasi ke WebAssembly). Tidak ada server, tidak ada dependensi — toolkit-nya murni Python standar.

> Dibuat oleh **Dea Saka Kurnia Putra** untuk Pelatihan Sertifikasi *Cryptography Analyst* Angkatan 1 — BSSN.

## ✨ Fitur

12 serangan RSA klasik yang dapat dijalankan langsung dari halaman web. Setiap serangan membangun instance RSA yang *rentan* sesuai prasyaratnya, mengenkripsi pesan Anda, lalu memulihkannya hanya dari data publik:

| # | Serangan | Prasyarat kerentanan |
|---|----------|----------------------|
| 1 | Fermat Factorization | p, q berdekatan |
| 2 | Elliptic Curve Method (Lenstra) | faktor prima ukuran sedang |
| 3 | Small Public Exponent | e kecil & tanpa padding (mᵉ < n) |
| 4 | Common Modulus | n sama, gcd(e₁,e₂)=1 |
| 5 | Håstad Broadcast | pesan sama ke ≥ e penerima |
| 6 | Franklin-Reiter | dua pesan berelasi linier, e kecil |
| 8 | Partial Key Exposure | sebagian bit p bocor (Coppersmith) |
| 10 | Small Private Exponent | d sangat kecil (brute-force) |
| 11 | Wiener's Attack | d < ⅓·N^¼ |
| 13 | Pollard's p−1 | p−1 halus (B-smooth) |
| 16 | Blind Signature | akses oracle dekripsi (malleable) |
| 19 | Stereotyped Message | mayoritas plaintext diketahui, e kecil |

## 🛡️ ISO/IEC Conformance Lab

Selain serangan, RSAttax menyertakan **laboratorium pengujian kesesuaian** (`pkc_iso_lab.py`) yang memetakan uji ke standar:

| Standar | Uji |
|---------|-----|
| ISO/IEC 18032 | Uji primalitas Miller-Rabin |
| ISO/IEC 18033-2 | Validasi kunci publik RSA (panjang modulus, eksponen, komposit) |
| ISO/IEC 15946-1 | Validasi titik kunci publik EC (P-256) — cegah *invalid-curve attack* |
| ISO/IEC 19790 / 24759 | Known-Answer Test (SHA-256) & pairwise consistency test |

Pengguna dapat menjalankan self-test standar, atau menempel modulus `n` &amp; eksponen `e` sendiri untuk divalidasi terhadap ISO/IEC 18033-2.

## 🧠 Inti teknis

`rsakit.py` (612 baris, **pure-Python, tanpa dependensi**) mengimplementasikan sendiri:

- Reduksi kisi **LLL** (rasional & integer/Cohen 2.6.3)
- **Coppersmith / Howgrave-Graham** univariat (akar kecil polinomial mod N)
- Miller-Rabin, CRT, `iroot`, GCD polinomial atas ℤ/n, dan aritmetika bilangan besar

Ini menggantikan PyCryptodome, gmpy2, dan SageMath sehingga seluruh serangan bisa berjalan offline di WebAssembly.

## 🚀 Menjalankan lokal

Situs sepenuhnya statis — sajikan folder ini dengan server statis apa pun:

```bash
python3 -m http.server 8000
# buka http://localhost:8000
```

> Harus lewat HTTP (bukan `file://`) karena Web Worker mem-`fetch` file `.py`.

## 🌐 Deploy

Situs statis tanpa build step — kompatibel dengan **GitHub Pages, Netlify, dan Vercel** apa adanya (`netlify.toml` & `vercel.json` sudah disertakan).

## ⚠️ Disclaimer

Dibuat untuk **edukasi dan sertifikasi keamanan**. Serangan hanya berhasil pada konfigurasi RSA yang salah/lemah. RSA yang diimplementasikan benar (kunci ≥ 2048-bit, padding OAEP, e = 65537) tetap aman terhadap semua serangan di sini.

## 📄 Lisensi

[MIT](LICENSE) © 2026 Dea Saka Kurnia Putra
