# Key Distribution Scenario (KDC) + AES Manual

Implementasi skenario distribusi kunci dengan tiga entitas (**KDC, Alice, Bob**) pada tiga IP berbeda. Setelah langkah ke-5, Alice dan Bob berkomunikasi dua arah memakai **AES yang diimplementasikan manual** (tanpa library kriptografi). Hanya butuh Python 3.8+ (standard library).

## Isi folder

| File | Fungsi |
|---|---|
| `aes.py` | AES manual (FIPS-197): GF(2^8), S-Box, Key Expansion, SubBytes/ShiftRows/MixColumns/AddRoundKey + invers, mode ECB & CBC, padding PKCS#7. Bisa dijalankan sendiri untuk uji test case. |
| `kdc.py` | Key Distribution Center — menyimpan master key tiap entitas, membuat session key, menangani langkah 1–2. |
| `peer.py` | Program Alice **dan** Bob (kode sama, beda `--id`). Menangani langkah 3–5 dan chat AES dua arah. |
| `net.py` | Framing pesan TCP (panjang 4 byte + JSON) dan logging. |
| `test_local.py` | Uji otomatis di satu mesin Linux dengan 3 IP loopback (127.0.0.1/2/3) — untuk latihan sebelum demo. |

## Skenario yang diimplementasikan

```
 (1) Alice -> KDC : IDA || IDB || N1                                   (plaintext)
 (2) KDC -> Alice : E(Ka, [Ks || IDA || IDB || N1]) || E(Kb, [Ks || IDA])
 (3) Alice -> Bob : E(Kb, [Ks || IDA])                                 (tiket)
 (4) Bob -> Alice : E(Ks, N2)
 (5) Alice -> Bob : E(Ks, f(N2))          dengan f(N2) = N2 + 1
 ---- setelah (5): Alice <-> Bob saling kirim E(Ks, pesan) ----
```

- **Ka, Kb** = master key (dimiliki KDC dan pemiliknya), input saat program start, **tidak di-hardcode**, dan bisa diubah saat runtime.
- **Ks** = session key acak yang dibuat KDC (ASCII 16 karakter default; bisa 24/32 → AES-192/256).
- Alice memverifikasi IDA, IDB, dan **N1** di balasan KDC (mencegah replay). Bob memverifikasi `f(N2) = N2+1` (membuktikan Alice benar memegang Ks).
- Setelah langkah 5, Bob mengirim `AUTH_OK` sebagai konfirmasi teknis (bukan bagian dari 5 langkah), lalu sesi chat dibuka.
- Komponen `||` diserialisasi sebagai teks ASCII dipisah `|`, mis. `Ks|Alice|Bob|123456`.

**Format data:** key & plaintext = ASCII printable; ciphertext = HEX. Mode CBC: 32 karakter hex pertama adalah IV acak. Mode ECB: tanpa IV (hasil deterministik, cocok untuk dibandingkan dengan CyberChef). Langkah 2–5 selalu memakai CBC; mode chat bisa dipilih `/mode ecb|cbc`.

## Persiapan 3 perangkat

1. Ketiga perangkat di jaringan yang sama (Wi-Fi/hotspot yang sama). Cek IP: Linux `ip -4 a`, Windows `ipconfig`, macOS `ipconfig getifaddr en0`.
2. Salin seluruh folder ke ketiga perangkat.
3. Buka port di firewall:
   - KDC: TCP **5000**; Alice & Bob: TCP **6000**.
   - Linux (ufw): `sudo ufw allow 5000/tcp` / `sudo ufw allow 6000/tcp`. firewalld: `sudo firewall-cmd --add-port=6000/tcp`.
   - Windows: izinkan Python saat dialog Windows Defender muncul (centang Private network).
4. Uji konektivitas: `ping <IP lain>`.

Contoh IP di bawah: **KDC 192.168.1.10, Alice 192.168.1.11, Bob 192.168.1.12** — ganti sesuai jaringan saat demo.

## Menjalankan

**KDC (192.168.1.10)**
```
python kdc.py --port 5000
Master key untuk Alice: KunciAlice123456
Master key untuk Bob:   KunciBobRahasia!
```

**Bob (192.168.1.12)**
```
python peer.py --id Bob --kdc 192.168.1.10:5000
Master key Bob: KunciBobRahasia!
```

**Alice (192.168.1.11)**
```
python peer.py --id Alice --kdc 192.168.1.10:5000
Master key Alice: KunciAlice123456
Alice> /connect Bob 192.168.1.12
```
Log langkah (1)–(5) muncul di ketiga terminal. Setelah itu ketik teks biasa di Alice **atau** Bob untuk mengirim pesan; sisi lain menampilkan ciphertext HEX dan plaintext ASCII.

Perannya simetris: Bob juga bisa memulai (`/connect Alice 192.168.1.11`) — Bob menjadi "A" dalam skenario.

> `192.168.1.x` di atas hanya contoh. Isi `--kdc` dengan IP Wi-Fi asli laptop KDC.

### Latihan di satu laptop (3 IP loopback)

Jika KDC, Alice, dan Bob dijalankan di **satu laptop**, beri masing-masing IP loopback berbeda dengan `--bind`. Di Linux, semua alamat 127.x.x.x langsung bisa dipakai. Tanpa `--bind`, Alice dan Bob sama-sama listen di `0.0.0.0:6000`, sehingga program kedua gagal dengan *Address already in use*.

```
# terminal 1 — KDC   (127.0.0.1)
python kdc.py --host 127.0.0.1 --port 5000

# terminal 2 — Bob   (127.0.0.3)
python peer.py --id Bob --bind 127.0.0.3 --kdc 127.0.0.1:5000

# terminal 3 — Alice (127.0.0.2)
python peer.py --id Alice --bind 127.0.0.2 --kdc 127.0.0.1:5000
Alice> /connect Bob 127.0.0.3
```
Di Wireshark pilih interface **Loopback: lo**.

### Perintah peer
| Perintah | Fungsi |
|---|---|
| `<teks>` / `/send <teks>` | kirim pesan terenkripsi |
| `/connect <ID> <IP>[:port]` | jalankan langkah 1–5 |
| `/key <KEY>` | ganti master key sendiri |
| `/sk <KEY>` | ganti session key manual (uji key salah/custom) |
| `/mode ecb\|cbc` | mode AES pesan keluar |
| `/enc <teks>`, `/dec <hex>` | enkripsi/dekripsi lokal tanpa kirim |
| `/kdc <IP>[:port]` | ganti alamat KDC |
| `/status`, `/disconnect`, `/quit` | status, tutup sesi, keluar |

### Perintah KDC
`list`, `set <ID> <KEY>`, `del <ID>`, `sklen 16|24|32`, `help`, `quit`.

## Alur demo setelah terhubung

Sesi aktif ditandai baris `Sesi AES dengan ... aktif` dan prompt yang berubah menjadi `Alice->Bob[CBC]>` / `Bob->Alice[CBC]>`.

1. **Komunikasi dua arah.**
   - Ketik teks biasa di Alice, misalnya `Halo Bob, ini Alice`. Alice menampilkan plaintext dan ciphertext HEX.
   - Bob menampilkan ciphertext HEX yang sama, beserta plaintext hasil dekripsinya.
   - Balas dari Bob (`Hai Alice`). Pesan muncul di Alice. Keduanya terbukti bisa menjadi sender maupun receiver.
2. **Tunjukkan di Wireshark.**
   - Klik kanan paket port 6000, pilih *Follow → TCP Stream*. Tunjukkan `"step": 3/4/5` dan `"type": "CHAT"`. Di jaringan hanya ada ciphertext HEX, yang sama dengan HEX di terminal pengirim.
   - Stream port 5000 berisi langkah 1–2. N1 memang plaintext sesuai skenario, sedangkan Ks hanya muncul dalam bentuk terenkripsi.
3. **Variasi test case.** Lihat tabel di bawah (nomor 2–4).
4. **Ganti key lewat KDC** (nomor 5–7):
   - `/disconnect`, lalu `/connect` lagi → Ks baru.
   - Di KDC, `set Alice KunciBaru1234567`. Alice reconnect dengan master key lama → gagal.
   - Di Alice, `/key KunciBaru1234567`, lalu reconnect → berhasil.
5. **Validasi AES.** Di terminal lain jalankan `python aes.py --selftest`.
6. **Selesai.** Ketik `/quit` di Alice dan Bob, dan `quit` di KDC.

## Test case untuk demo (tanpa restart program)

| # | Langkah | Hasil yang diharapkan |
|---|---|---|
| 1 | `/connect Bob <IP>`, kirim pesan dari Alice, balas dari Bob | Langkah 1–5 sukses; pesan dua arah terbaca |
| 2 | Kirim plaintext panjang (>16 karakter) dan pendek (1 karakter) | Ciphertext beberapa blok; dekripsi benar (padding PKCS#7) |
| 3 | `/mode ecb`, kirim teks sama dua kali | Ciphertext ECB identik; CBC selalu beda karena IV acak |
| 4 | Di Bob `/sk SessionKeySalah!`, Alice kirim pesan | Bob gagal dekripsi (padding tidak valid) — membuktikan key berpengaruh |
| 5 | `/disconnect` lalu `/connect` lagi | KDC membuat Ks baru, ciphertext berubah |
| 6 | Di KDC `set Alice KunciBaru1234567`, lalu Alice `/connect` (master key lama) | Alice gagal membuka balasan KDC. Setelah `/key KunciBaru1234567` → berhasil |
| 7 | Di KDC `sklen 32`, lalu reconnect | Session key 32 karakter (AES-256) |
| 8 | `/connect Charlie <IP>` | Ditolak KDC: ID tidak terdaftar |
| 9 | `python aes.py`, `key Thats my Kung Fu`, `mode ecb`, `enc Two One Nine Two` | Blok pertama `29c3505f571420f6402299b31a02d73a` (test vector populer); bisa dicocokkan di CyberChef (AES Encrypt, ECB, key UTF8) |

Validasi implementasi AES: `python aes.py --selftest` (test vector FIPS-197 AES-128/192/256). Latihan semua skenario di satu laptop Linux: `python test_local.py`.

## Troubleshooting

| Gejala | Penyebab & solusi |
|---|---|
| `Address already in use` / `Tidak bisa listen di 0.0.0.0:6000` | Port sudah dipakai proses lain. Cek dengan `ss -ltnp \| grep 6000`, lalu `ps -p <PID> -o pid,args`. Jika itu proses lama, matikan dengan `kill <PID>`. Jika itu peer lain di laptop yang sama, gunakan `--bind` berbeda (lihat *Latihan di satu laptop*) atau `--port 6001`. |
| `Connection refused` / timeout saat `/connect` | Alamat atau port KDC/peer salah, program tujuan belum jalan, atau firewall menutup port 5000/6000. Pastikan `--kdc` berisi IP asli KDC, bukan contoh 192.168.1.10. |
| `Gagal dekripsi balasan KDC (master key salah?)` | Master key di peer berbeda dengan yang terdaftar di KDC. Samakan dengan `/key` di peer atau `set` di KDC. |
| `ID '...' tidak terdaftar di KDC` | Tambahkan di KDC dengan `set <ID> <KEY>`. ID peka huruf besar-kecil. |
| `Masih ada sesi aktif` | Ketik `/disconnect` dulu sebelum `/connect` lagi. |

## Wireshark

**Interface.** Pilih interface yang dipakai untuk terhubung ke jaringan demo (`wlan0`/`wlp…` di Linux, `Wi-Fi` di Windows). Untuk latihan satu mesin dengan IP 127.0.0.x, pilih `Loopback: lo`.

**Di perangkat mana capture dijalankan.** Di Wi-Fi biasa, sebuah perangkat hanya melihat trafiknya sendiri. Jalankan Wireshark di **perangkat Alice (initiator)** — ia terlibat di kelima langkah (KDC↔Alice dan Alice↔Bob) serta chat. Alternatif: jika salah satu laptop menjadi hotspot, capture di interface hotspot laptop itu untuk melihat semua trafik.

Di Linux, agar tanpa sudo: `sudo usermod -aG wireshark $USER` lalu login ulang (atau jalankan `sudo wireshark`).

**Capture filter** (diisi sebelum Start, mengurangi noise):
```
tcp port 5000 or tcp port 6000
```

**Display filter** (simpan sebagai tombol filter lewat ikon bookmark di kiri bar filter):

| Tujuan | Filter |
|---|---|
| Semua trafik tugas | `tcp.port == 5000 \|\| tcp.port == 6000` |
| Hanya paket berisi data | `(tcp.port == 5000 \|\| tcp.port == 6000) && tcp.len > 0` |
| Langkah 1–2 (Alice↔KDC) | `tcp.port == 5000 && tcp.len > 0` |
| Langkah 3–5 + chat (Alice↔Bob) | `tcp.port == 6000 && tcp.len > 0` |
| Langkah tertentu | `frame contains "\"step\": 3"` (ganti 1–5) |
| Hanya pesan chat | `frame contains "CHAT"` |
| Antar dua IP | `ip.addr == 192.168.1.11 && ip.addr == 192.168.1.12` |

**Menunjukkan isi.** Klik kanan sebuah paket → *Follow → TCP Stream*. Isinya JSON terbaca, misalnya:
```
{"step": 1, "type": "KDC_REQUEST", "id_a": "Alice", "id_b": "Bob", "n1": "951737592"}
{"step": 2, "type": "KDC_REPLY", "enc_for_a": "7fc9f9...", "ticket_for_b": "1af6b1..."}
{"type": "CHAT", "from": "Alice", "mode": "CBC", "ciphertext": "c00433..."}
```
Poin yang ditunjukkan ke dosen: langkah 1 memang plaintext (sesuai skenario); Ks tidak pernah muncul dalam bentuk terbaca di jaringan; plaintext chat tidak terlihat, hanya ciphertext HEX yang sama dengan yang tercetak di terminal pengirim.

**Checklist sebelum demo**
- [ ] IP ketiga perangkat dicatat, saling `ping` OK, port 5000/6000 terbuka
- [ ] Wireshark di laptop Alice, interface benar, capture filter terpasang
- [ ] Display filter disimpan sebagai tombol
- [ ] `python aes.py --selftest` lulus di semua perangkat
- [ ] Mulai capture **sebelum** `/connect` supaya langkah 1 ikut terekam
