# Simulasi Transmisi Ciphertext Dua Arah (DES-CBC Manual)

Program komunikasi dua arah antara **Sender** dan **Receiver** yang berjalan sebagai
**dua proses terpisah** (dua VM atau dua komputer fisik) dan bertukar pesan terenkripsi
lewat jaringan TCP. Algoritma DES diimplementasikan manual tanpa library kriptografi.

## Pemenuhan ketentuan tugas

| Ketentuan | Implementasi |
|---|---|
| 1. Komunikasi dua arah | Setelah terhubung, Sender dan Receiver sama-sama bisa mengirim & menerima (full-duplex, satu thread penerima + thread pengirim di tiap pihak). |
| 2. Pengelolaan key | Key adalah *pre-shared key* di file `shared.key` yang disalin ke kedua perangkat sebelum program berjalan. Yang dikirim lewat jaringan hanya `IV + ciphertext`; key tidak pernah ditransmisikan. |
| 3. Penerapan sistem | `receiver.py` dan `sender.py` adalah dua program terpisah yang berkomunikasi melalui socket TCP. Enkripsi terjadi di pengirim, dekripsi terjadi di penerima. Bisa dijalankan di 2 VM (logical) atau 2 komputer (physical). |
| 4. Bahasa | Python 3 (hanya standard library: `socket`, `threading`, `struct`, `argparse`). |
| 5. Tanpa library enkripsi | Seluruh DES (IP, FP, ekspansi E, 8 S-Box, permutasi P, key schedule PC-1/PC-2, 16 ronde Feistel), mode CBC, dan padding PKCS#7 ditulis sendiri di `des.py`. `os.urandom` hanya dipakai sebagai sumber bilangan acak untuk IV. |

## Struktur file

```
des.py        Implementasi manual DES + mode CBC + padding PKCS#7
channel.py    Lapisan transmisi: framing pesan & loop chat dua arah
receiver.py   Pihak Receiver (listen pada port, default 5000)
sender.py     Pihak Sender (connect ke IP Receiver)
shared.key    Pre-shared key 64-bit (16 digit hex), harus sama di kedua pihak
```

## Alur kerja

```
      SENDER (Device A)                                RECEIVER (Device B)
  plaintext                                                   
     │ DES-CBC encrypt (key lokal)                             
     ▼                                                         
  IV || ciphertext ──── TCP: [len 4B][IV 8B][ciphertext] ────► DES-CBC decrypt (key lokal)
                                                                  │
                                                                  ▼ plaintext
  plaintext ◄── DES-CBC decrypt ◄──── TCP ◄──── IV || ciphertext ◄── encrypt ◄── balasan
```

Setiap pesan memakai IV acak baru, sehingga pesan yang sama menghasilkan ciphertext berbeda.

## Cara menjalankan

Syarat: Python 3.8+ di kedua perangkat, tidak perlu `pip install` apa pun.

1. Salin folder ini ke **kedua** perangkat (termasuk `shared.key` yang isinya identik).
2. Cek IP perangkat Receiver (`ip a` di Linux, `ipconfig` di Windows).
3. Di perangkat **Receiver**:
   ```bash
   python3 receiver.py --port 5000
   ```
4. Di perangkat **Sender**:
   ```bash
   python3 sender.py --host <IP_RECEIVER> --port 5000
   ```
5. Ketik pesan di sisi mana pun lalu Enter. Ketik `/quit` untuk keluar.

**Catatan VM:** gunakan network adapter *Bridged* atau *Host-only / Internal Network*
agar kedua VM saling bisa di-ping, dan pastikan firewall Receiver mengizinkan port 5000
(misal `sudo ufw allow 5000/tcp`).

**Uji cepat di satu komputer** (dua terminal berbeda, tetap dua proses terpisah):
Receiver `python3 receiver.py`, Sender `python3 sender.py --host 127.0.0.1`.

## Contoh output

Sender:
```
SENDER> Halo receiver, ini pesan rahasia
[10:32:55] >>> dikirim ke RECEIVER
    plaintext       : Halo receiver, ini pesan rahasia
    ciphertext (hex): B08AD040E55ABB16A709DD16BEABBF11...
[10:32:56] <<< diterima dari RECEIVER
    ciphertext (hex): AC3AE21B41050EE6EAB03FDAD24C6413...
    plaintext       : Balasan dari receiver
```

Receiver:
```
[10:32:55] <<< diterima dari SENDER
    ciphertext (hex): B08AD040E55ABB16A709DD16BEABBF11...
    plaintext       : Halo receiver, ini pesan rahasia
RECEIVER> Balasan dari receiver
[10:32:56] >>> dikirim ke SENDER
    ciphertext (hex): AC3AE21B41050EE6EAB03FDAD24C6413...
```

Untuk membuktikan data di jaringan memang terenkripsi, tangkap lalu lintas port 5000 dengan
Wireshark / `sudo tcpdump -i any -X port 5000`: yang terlihat hanya byte acak, bukan plaintext.

## Verifikasi kebenaran DES

Implementasi diuji dengan test vector standar DES:

| Key | Plaintext | Ciphertext yang diharapkan | Hasil |
|---|---|---|---|
| `133457799BBCDFF1` | `0123456789ABCDEF` | `85E813540F0AB405` | ✅ sama |

```bash
python3 -c "from des import *; sk=generate_subkeys(bytes.fromhex('133457799BBCDFF1')); print(encrypt_block(bytes.fromhex('0123456789ABCDEF'),sk).hex().upper())"
```

Jika key di kedua sisi berbeda, penerima menampilkan `gagal dekripsi: Padding tidak valid`,
yang menunjukkan pesan tidak bisa dibaca tanpa key yang benar.

## Keterbatasan

DES (key efektif 56-bit) sudah tidak aman untuk penggunaan nyata dan dipakai di sini untuk
keperluan pembelajaran. Program juga belum memakai autentikasi pesan (MAC), sehingga
ciphertext yang dimodifikasi di jalan tidak terdeteksi kecuali merusak padding.
