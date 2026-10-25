"""
aes.py — Implementasi AES (Rijndael) MANUAL sesuai FIPS-197.

Tidak memakai library kriptografi apa pun (tidak ada pycryptodome/cryptography).
Semua komponen ditulis sendiri:
  - Aritmetika GF(2^8)             -> gmul, ginv
  - S-Box & Inverse S-Box          -> dibangun dari invers GF(2^8) + affine transform
  - Key Expansion                  -> key_expansion
  - SubBytes, ShiftRows, MixColumns, AddRoundKey (+ inversnya)
  - Mode ECB & CBC, padding PKCS#7

Format data sesuai tugas:
  - Key        : string ASCII 16 / 24 / 32 karakter (AES-128 / 192 / 256)
  - Plaintext  : string ASCII
  - Ciphertext : hexadecimal (untuk CBC, 16 byte pertama = IV)

Jalankan langsung:
  python aes.py            -> mode interaktif (uji enkripsi/dekripsi, key bisa diganti)
  python aes.py --selftest -> uji dengan test vector resmi FIPS-197
"""

import os
import sys

BLOCK_SIZE = 16
VALID_KEY_LENGTHS = {16: "AES-128", 24: "AES-192", 32: "AES-256"}


# ============================================================
# 1. Aritmetika Galois Field GF(2^8), polinom x^8+x^4+x^3+x+1
# ============================================================
def gmul(a, b):
    """Perkalian dua byte di GF(2^8)."""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B          # reduksi modulo 0x11B
        b >>= 1
    return p


def ginv(a):
    """Invers perkalian di GF(2^8): a^254 = a^-1 (0 dipetakan ke 0)."""
    if a == 0:
        return 0
    result, base, e = 1, a, 254
    while e:
        if e & 1:
            result = gmul(result, base)
        base = gmul(base, base)
        e >>= 1
    return result


def _rotl8(x, s):
    return ((x << s) | (x >> (8 - s))) & 0xFF


def _build_sbox():
    """S-Box = affine transform dari invers GF(2^8)."""
    sbox, inv = [0] * 256, [0] * 256
    for x in range(256):
        b = ginv(x)
        s = b ^ _rotl8(b, 1) ^ _rotl8(b, 2) ^ _rotl8(b, 3) ^ _rotl8(b, 4) ^ 0x63
        sbox[x] = s
        inv[s] = x
    return sbox, inv


def _build_rcon(n=14):
    rcon, r = [], 1
    for _ in range(n):
        rcon.append(r)
        r = gmul(r, 2)
    return rcon


SBOX, INV_SBOX = _build_sbox()
RCON = _build_rcon()


# ============================================================
# 2. Key Expansion
# ============================================================
def key_expansion(key: bytes):
    """Menghasilkan (Nr+1) round key, masing-masing 16 byte."""
    nk = len(key) // 4
    if len(key) not in VALID_KEY_LENGTHS:
        raise ValueError("Panjang key harus 16, 24, atau 32 byte")
    nr = nk + 6
    w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    for i in range(nk, 4 * (nr + 1)):
        temp = list(w[i - 1])
        if i % nk == 0:
            temp = temp[1:] + temp[:1]              # RotWord
            temp = [SBOX[b] for b in temp]          # SubWord
            temp[0] ^= RCON[i // nk - 1]            # XOR Rcon
        elif nk > 6 and i % nk == 4:
            temp = [SBOX[b] for b in temp]          # khusus AES-256
        w.append([w[i - nk][j] ^ temp[j] for j in range(4)])

    round_keys = []
    for r in range(nr + 1):
        rk = []
        for c in range(4):
            rk.extend(w[4 * r + c])
        round_keys.append(rk)
    return round_keys


# ============================================================
# 3. Transformasi ronde
#    State = 16 byte, urutan kolom (column-major): s[r + 4c]
# ============================================================
def add_round_key(s, rk):
    return [a ^ b for a, b in zip(s, rk)]


def sub_bytes(s):
    return [SBOX[b] for b in s]


def inv_sub_bytes(s):
    return [INV_SBOX[b] for b in s]


def shift_rows(s):
    out = [0] * 16
    for c in range(4):
        for r in range(4):
            out[r + 4 * c] = s[r + 4 * ((c + r) % 4)]
    return out


def inv_shift_rows(s):
    out = [0] * 16
    for c in range(4):
        for r in range(4):
            out[r + 4 * ((c + r) % 4)] = s[r + 4 * c]
    return out


def mix_columns(s):
    out = [0] * 16
    for c in range(4):
        a0, a1, a2, a3 = s[4 * c:4 * c + 4]
        out[4 * c + 0] = gmul(a0, 2) ^ gmul(a1, 3) ^ a2 ^ a3
        out[4 * c + 1] = a0 ^ gmul(a1, 2) ^ gmul(a2, 3) ^ a3
        out[4 * c + 2] = a0 ^ a1 ^ gmul(a2, 2) ^ gmul(a3, 3)
        out[4 * c + 3] = gmul(a0, 3) ^ a1 ^ a2 ^ gmul(a3, 2)
    return out


def inv_mix_columns(s):
    out = [0] * 16
    for c in range(4):
        a0, a1, a2, a3 = s[4 * c:4 * c + 4]
        out[4 * c + 0] = gmul(a0, 14) ^ gmul(a1, 11) ^ gmul(a2, 13) ^ gmul(a3, 9)
        out[4 * c + 1] = gmul(a0, 9) ^ gmul(a1, 14) ^ gmul(a2, 11) ^ gmul(a3, 13)
        out[4 * c + 2] = gmul(a0, 13) ^ gmul(a1, 9) ^ gmul(a2, 14) ^ gmul(a3, 11)
        out[4 * c + 3] = gmul(a0, 11) ^ gmul(a1, 13) ^ gmul(a2, 9) ^ gmul(a3, 14)
    return out


# ============================================================
# 4. Enkripsi / dekripsi satu blok (16 byte)
# ============================================================
def encrypt_block(block, round_keys):
    nr = len(round_keys) - 1
    s = add_round_key(list(block), round_keys[0])
    for r in range(1, nr):
        s = sub_bytes(s)
        s = shift_rows(s)
        s = mix_columns(s)
        s = add_round_key(s, round_keys[r])
    s = sub_bytes(s)
    s = shift_rows(s)
    s = add_round_key(s, round_keys[nr])
    return bytes(s)


def decrypt_block(block, round_keys):
    nr = len(round_keys) - 1
    s = add_round_key(list(block), round_keys[nr])
    for r in range(nr - 1, 0, -1):
        s = inv_shift_rows(s)
        s = inv_sub_bytes(s)
        s = add_round_key(s, round_keys[r])
        s = inv_mix_columns(s)
    s = inv_shift_rows(s)
    s = inv_sub_bytes(s)
    s = add_round_key(s, round_keys[0])
    return bytes(s)


# ============================================================
# 5. Padding PKCS#7 & mode operasi
# ============================================================
def pkcs7_pad(data: bytes) -> bytes:
    n = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([n]) * n


def pkcs7_unpad(data: bytes) -> bytes:
    if not data or len(data) % BLOCK_SIZE:
        raise ValueError("Panjang ciphertext bukan kelipatan 16 byte")
    n = data[-1]
    if n < 1 or n > BLOCK_SIZE or data[-n:] != bytes([n]) * n:
        raise ValueError("Padding tidak valid (kemungkinan key salah / ciphertext rusak)")
    return data[:-n]


def _xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def encrypt_ecb(data: bytes, key: bytes) -> bytes:
    rks = key_expansion(key)
    p = pkcs7_pad(data)
    return b"".join(encrypt_block(p[i:i + 16], rks) for i in range(0, len(p), 16))


def decrypt_ecb(data: bytes, key: bytes) -> bytes:
    if len(data) == 0 or len(data) % 16:
        raise ValueError("Panjang ciphertext bukan kelipatan 16 byte")
    rks = key_expansion(key)
    p = b"".join(decrypt_block(data[i:i + 16], rks) for i in range(0, len(data), 16))
    return pkcs7_unpad(p)


def encrypt_cbc(data: bytes, key: bytes, iv: bytes = None) -> bytes:
    """Hasil = IV (16 byte) || ciphertext."""
    rks = key_expansion(key)
    iv = iv if iv is not None else os.urandom(16)
    p = pkcs7_pad(data)
    prev, out = iv, []
    for i in range(0, len(p), 16):
        c = encrypt_block(_xor(p[i:i + 16], prev), rks)
        out.append(c)
        prev = c
    return iv + b"".join(out)


def decrypt_cbc(data: bytes, key: bytes) -> bytes:
    if len(data) < 32 or len(data) % 16:
        raise ValueError("Ciphertext CBC harus berisi IV + minimal 1 blok")
    rks = key_expansion(key)
    prev, out = data[:16], []
    for i in range(16, len(data), 16):
        c = data[i:i + 16]
        out.append(_xor(decrypt_block(c, rks), prev))
        prev = c
    return pkcs7_unpad(b"".join(out))


# ============================================================
# 6. Helper format tugas: key/plaintext ASCII, ciphertext HEX
# ============================================================
def _is_printable_ascii(s: str) -> bool:
    return all(32 <= ord(ch) < 127 for ch in s)


def validate_key(key_str: str) -> bytes:
    if not _is_printable_ascii(key_str):
        raise ValueError("Key harus berupa karakter ASCII printable")
    if len(key_str) not in VALID_KEY_LENGTHS:
        raise ValueError(
            f"Panjang key {len(key_str)} karakter; harus 16 (AES-128), 24 (AES-192), atau 32 (AES-256)")
    return key_str.encode("ascii")


def key_variant(key_str: str) -> str:
    return VALID_KEY_LENGTHS.get(len(key_str), "?")


def validate_plaintext(text: str) -> bytes:
    if not _is_printable_ascii(text):
        raise ValueError("Plaintext harus berupa karakter ASCII printable")
    return text.encode("ascii")


def encrypt_text(key_str: str, plaintext: str, mode: str = "CBC") -> str:
    key = validate_key(key_str)
    data = validate_plaintext(plaintext)
    mode = mode.upper()
    if mode == "ECB":
        return encrypt_ecb(data, key).hex()
    if mode == "CBC":
        return encrypt_cbc(data, key).hex()
    raise ValueError("Mode harus ECB atau CBC")


def decrypt_hex(key_str: str, hex_str: str, mode: str = "CBC") -> str:
    key = validate_key(key_str)
    try:
        data = bytes.fromhex(hex_str.strip())
    except ValueError:
        raise ValueError("Ciphertext bukan hexadecimal yang valid")
    mode = mode.upper()
    if mode == "ECB":
        raw = decrypt_ecb(data, key)
    elif mode == "CBC":
        raw = decrypt_cbc(data, key)
    else:
        raise ValueError("Mode harus ECB atau CBC")
    try:
        return raw.decode("ascii")
    except UnicodeDecodeError:
        raise ValueError("Hasil dekripsi bukan ASCII (kemungkinan key salah)")


# ============================================================
# 7. Self-test & CLI interaktif
# ============================================================
def selftest(verbose=True) -> bool:
    vectors = [
        # FIPS-197 Appendix C
        ("000102030405060708090a0b0c0d0e0f", "00112233445566778899aabbccddeeff",
         "69c4e0d86a7b0430d8cdb78070b4c55a"),
        ("000102030405060708090a0b0c0d0e0f1011121314151617", "00112233445566778899aabbccddeeff",
         "dda97ca4864cdfe06eaf70a0ec0d7191"),
        ("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
         "00112233445566778899aabbccddeeff", "8ea2b7ca516745bfeafc49904b496089"),
        # Contoh populer dengan key & plaintext ASCII
        ("Thats my Kung Fu".encode().hex(), "Two One Nine Two".encode().hex(),
         "29c3505f571420f6402299b31a02d73a"),
    ]
    ok_all = True
    for k, p, c in vectors:
        rks = key_expansion(bytes.fromhex(k))
        enc = encrypt_block(bytes.fromhex(p), rks).hex()
        dec = decrypt_block(bytes.fromhex(c), rks).hex()
        ok = enc == c and dec == p
        ok_all &= ok
        if verbose:
            print(f"[{'OK ' if ok else 'GAGAL'}] {VALID_KEY_LENGTHS[len(k)//2]}  key={k}\n"
                  f"        expected={c}\n        got     ={enc}")
    # Round-trip mode CBC/ECB dengan berbagai panjang plaintext
    for mode in ("ECB", "CBC"):
        for msg in ["", "A", "Halo Bob!", "x" * 16, "Kriptografi KDC AES" * 5]:
            ct = encrypt_text("KunciRahasia1234", msg, mode)
            ok = decrypt_hex("KunciRahasia1234", ct, mode) == msg
            ok_all &= ok
    if verbose:
        print("Round-trip ECB/CBC:", "OK" if ok_all else "ADA YANG GAGAL")
    return ok_all


def _interactive():
    print("=== AES Manual — mode uji interaktif ===")
    print("Perintah: key <KEY> | mode ecb|cbc | enc <plaintext> | dec <hex> | info | quit")
    key, mode = None, "ECB"
    while True:
        try:
            line = input(f"aes[{mode}]> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not line:
            continue
        cmd, _, arg = line.partition(" ")
        cmd = cmd.lower()
        try:
            if cmd == "quit":
                break
            elif cmd == "key":
                validate_key(arg)
                key = arg
                print(f"  Key diset ({key_variant(key)}): '{key}'  hex={key.encode().hex()}")
            elif cmd == "mode":
                if arg.upper() not in ("ECB", "CBC"):
                    raise ValueError("mode ecb atau cbc")
                mode = arg.upper()
            elif cmd == "enc":
                if not key:
                    raise ValueError("Set key dulu: key <KEY>")
                ct = encrypt_text(key, arg, mode)
                print(f"  Plaintext (ASCII): {arg}\n  Ciphertext (HEX) : {ct}")
                if mode == "CBC":
                    print(f"  (IV = {ct[:32]})")
            elif cmd == "dec":
                if not key:
                    raise ValueError("Set key dulu: key <KEY>")
                print(f"  Plaintext (ASCII): {decrypt_hex(key, arg, mode)}")
            elif cmd == "info":
                print(f"  key={key!r} mode={mode}")
            else:
                print("  Perintah tidak dikenal")
        except ValueError as e:
            print(f"  [!] {e}")


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        sys.exit(0 if selftest() else 1)
    _interactive()
