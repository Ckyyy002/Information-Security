"""
peer.py — Program untuk Alice dan Bob (kode sama, beda --id).

Setiap peer:
  * listen di port sendiri (default 6000) -> bisa menerima tiket (langkah 3)
  * bisa memulai distribusi key ke peer lain dengan /connect (langkah 1-5)
  * setelah langkah 5, keduanya bisa KIRIM dan TERIMA pesan AES (dua arah)

Contoh:
  Bob   : python peer.py --id Bob   --kdc 192.168.1.10:5000
  Alice : python peer.py --id Alice --kdc 192.168.1.10:5000
          lalu di Alice: /connect Bob 192.168.1.12

Ketik /help di program untuk daftar perintah.
"""

import argparse
import secrets
import threading

from aes import encrypt_text, decrypt_hex, validate_key, key_variant
from net import log, send_msg, recv_msg, make_listener, make_connection, parse_hostport


class Session:
    def __init__(self, sock, peer_id, ks, role):
        self.sock, self.peer_id, self.ks, self.role = sock, peer_id, ks, role
        self.send_lock = threading.Lock()


class Peer:
    def __init__(self, ident, bind="0.0.0.0", port=6000, kdc_host="127.0.0.1", kdc_port=5000):
        self.id = ident
        self.bind, self.port = bind, port
        self.kdc_host, self.kdc_port = kdc_host, kdc_port
        self.master_key = None
        self.session = None
        self.mode = "CBC"
        self.lock = threading.Lock()
        self.inbox = []            # (dari, plaintext, ciphertext) — dipakai pengujian
        self._srv = None

    @property
    def prompt(self):
        if self.session:
            return f"{self.id}->{self.session.peer_id}[{self.mode}]> "
        return f"{self.id}> "

    def _log(self, text):
        log(self.id, text, self.prompt)

    # ---------------- key ----------------
    def set_master_key(self, key):
        validate_key(key)
        self.master_key = key

    def set_session_key(self, key):
        validate_key(key)
        if not self.session:
            raise ValueError("Belum ada sesi aktif")
        self.session.ks = key

    # ---------------- listener (peran responder / Bob) ----------------
    def start_listener(self):
        self._srv = make_listener(self.bind, self.port)
        threading.Thread(target=self._accept_loop, daemon=True).start()
        self._log(f"Listening di {self.bind}:{self.port}")

    def _accept_loop(self):
        while True:
            try:
                conn, addr = self._srv.accept()
            except OSError:
                break
            threading.Thread(target=self._handle_incoming, args=(conn, addr), daemon=True).start()

    def _handle_incoming(self, conn, addr):
        try:
            conn.settimeout(15)
            if self.session:
                send_msg(conn, {"type": "BUSY"})
                conn.close()
                return
            # ---- Langkah (3): terima E(Kb, [Ks || IDA]) ----
            msg = recv_msg(conn)
            if not msg or msg.get("type") != "TICKET":
                conn.close()
                return
            self._log(f"(3) Tiket dari {addr[0]}: {msg['ticket']}")
            try:
                plain = decrypt_hex(self.master_key, msg["ticket"], "CBC")
                ks, id_a = plain.split("|", 1)
                validate_key(ks)
            except ValueError as e:
                self._log(f"    Gagal membuka tiket dengan master key sendiri: {e}")
                send_msg(conn, {"type": "AUTH_FAIL", "reason": "Tiket tidak bisa didekripsi"})
                conn.close()
                return
            self._log(f"    Dekripsi tiket -> Ks='{ks}', IDA={id_a}")

            # ---- Langkah (4): kirim E(Ks, N2) ----
            n2 = secrets.randbelow(10 ** 9)
            c4 = encrypt_text(ks, str(n2), "CBC")
            send_msg(conn, {"step": 4, "type": "CHALLENGE", "data": c4})
            self._log(f"(4) Kirim E(Ks, N2={n2}) = {c4}")

            # ---- Langkah (5): terima E(Ks, f(N2)) ----
            msg = recv_msg(conn)
            if not msg or msg.get("type") != "RESPONSE":
                conn.close()
                return
            try:
                val = int(decrypt_hex(ks, msg["data"], "CBC"))
            except ValueError:
                val = None
            self._log(f"(5) Terima {msg['data']} -> f(N2)={val}")
            if val != n2 + 1:
                self._log("    Verifikasi GAGAL (f(N2) != N2+1). Koneksi ditutup.")
                send_msg(conn, {"type": "AUTH_FAIL", "reason": "Nonce tidak cocok"})
                conn.close()
                return
            send_msg(conn, {"type": "AUTH_OK"})
            self._log(f"    Verifikasi OK. Sesi AES dengan {id_a} aktif. Ks='{ks}'")
            self._begin_session(Session(conn, id_a, ks, "responder"))
        except Exception as e:
            self._log(f"Error koneksi masuk: {e}")
            try:
                conn.close()
            except OSError:
                pass

    # ---------------- initiator (peran Alice) ----------------
    def connect(self, peer_id, host, port=6000):
        if self.session:
            raise ValueError("Masih ada sesi aktif, /disconnect dulu")
        if not self.master_key:
            raise ValueError("Master key belum diset")

        # ---- Langkah (1): IDA || IDB || N1 ke KDC ----
        n1 = secrets.randbelow(10 ** 9)
        k = make_connection(self.kdc_host, self.kdc_port, self.bind)
        try:
            send_msg(k, {"step": 1, "type": "KDC_REQUEST", "id_a": self.id, "id_b": peer_id, "n1": str(n1)})
            self._log(f"(1) Ke KDC {self.kdc_host}:{self.kdc_port}: IDA={self.id}, IDB={peer_id}, N1={n1}")
            # ---- Langkah (2): balasan KDC ----
            rep = recv_msg(k)
        finally:
            k.close()
        if not rep:
            raise ValueError("KDC menutup koneksi")
        if rep.get("type") == "ERROR":
            raise ValueError(f"KDC: {rep['reason']}")
        self._log(f"(2) Dari KDC:\n      E(Ka,..) = {rep['enc_for_a']}\n      E(Kb,..) = {rep['ticket_for_b']}")
        try:
            plain = decrypt_hex(self.master_key, rep["enc_for_a"], "CBC")
            ks, ida, idb, rn1 = plain.split("|")
            validate_key(ks)
        except ValueError as e:
            raise ValueError(f"Gagal dekripsi balasan KDC (master key salah?): {e}")
        self._log(f"    Dekripsi -> Ks='{ks}', IDA={ida}, IDB={idb}, N1={rn1}")
        if ida != self.id or idb != peer_id or rn1 != str(n1):
            raise ValueError("Balasan KDC tidak cocok dengan request (IDA/IDB/N1) — kemungkinan replay")
        self._log("    N1 cocok -> balasan KDC fresh dan asli")

        # ---- Langkah (3): kirim tiket ke B ----
        s = make_connection(host, port, self.bind, timeout=15)
        try:
            send_msg(s, {"step": 3, "type": "TICKET", "ticket": rep["ticket_for_b"]})
            self._log(f"(3) Kirim tiket E(Kb,[Ks||IDA]) ke {peer_id} ({host}:{port})")

            # ---- Langkah (4): terima E(Ks, N2) ----
            msg = recv_msg(s)
            if not msg:
                raise ValueError("Peer menutup koneksi")
            if msg.get("type") in ("BUSY", "AUTH_FAIL"):
                raise ValueError(f"Ditolak peer: {msg.get('reason', msg['type'])}")
            n2 = int(decrypt_hex(ks, msg["data"], "CBC"))
            self._log(f"(4) Terima {msg['data']} -> N2={n2}")

            # ---- Langkah (5): kirim E(Ks, f(N2)) ----
            c5 = encrypt_text(ks, str(n2 + 1), "CBC")
            send_msg(s, {"step": 5, "type": "RESPONSE", "data": c5})
            self._log(f"(5) Kirim E(Ks, f(N2)={n2 + 1}) = {c5}")

            msg = recv_msg(s)
            if not msg or msg.get("type") != "AUTH_OK":
                raise ValueError(f"Autentikasi gagal: {msg}")
        except Exception:
            s.close()
            raise
        self._log(f"    Sesi AES dengan {peer_id} aktif. Ks='{ks}' ({key_variant(ks)})")
        self._begin_session(Session(s, peer_id, ks, "initiator"))

    # ---------------- sesi chat dua arah ----------------
    def _begin_session(self, sess):
        sess.sock.settimeout(None)
        with self.lock:
            self.session = sess
        threading.Thread(target=self._receiver, args=(sess,), daemon=True).start()

    def _receiver(self, sess):
        try:
            while True:
                msg = recv_msg(sess.sock)
                if msg is None or msg.get("type") == "BYE":
                    break
                if msg.get("type") != "CHAT":
                    continue
                ct, mode = msg["ciphertext"], msg.get("mode", "CBC")
                try:
                    pt = decrypt_hex(sess.ks, ct, mode)
                    self.inbox.append((msg.get("from"), pt, ct))
                    self._log(f"Pesan dari {msg.get('from')} [{mode}]\n"
                              f"      Ciphertext (HEX) : {ct}\n"
                              f"      Plaintext (ASCII): {pt}")
                except ValueError as e:
                    self.inbox.append((msg.get("from"), None, ct))
                    self._log(f"Pesan dari {msg.get('from')} [{mode}] GAGAL didekripsi dengan Ks='{sess.ks}'\n"
                              f"      Ciphertext (HEX) : {ct}\n      Alasan: {e}")
        except OSError:
            pass
        finally:
            with self.lock:
                if self.session is sess:
                    self.session = None
            try:
                sess.sock.close()
            except OSError:
                pass
            self._log(f"Sesi dengan {sess.peer_id} berakhir")

    def send_chat(self, text):
        sess = self.session
        if not sess:
            raise ValueError("Belum ada sesi. Gunakan /connect atau tunggu peer terhubung")
        ct = encrypt_text(sess.ks, text, self.mode)
        with sess.send_lock:
            send_msg(sess.sock, {"type": "CHAT", "from": self.id, "mode": self.mode, "ciphertext": ct})
        return ct

    def disconnect(self):
        sess = self.session
        if not sess:
            return
        try:
            send_msg(sess.sock, {"type": "BYE"})
        except OSError:
            pass
        try:
            sess.sock.close()
        except OSError:
            pass
        with self.lock:
            if self.session is sess:
                self.session = None

    def stop(self):
        self.disconnect()
        if self._srv:
            self._srv.close()


HELP = """Perintah:
  <teks>                       kirim pesan terenkripsi AES ke peer (atau /send <teks>)
  /connect <ID> <IP>[:port]    jalankan skenario KDC langkah 1-5 lalu buka sesi
  /key <KEY>                   ubah master key sendiri (harus sama dengan di KDC)
  /sk <KEY>                    ubah session key manual (uji key salah / key custom)
  /mode ecb|cbc                mode AES untuk pesan yang dikirim
  /kdc <IP>[:port]             ubah alamat KDC
  /enc <teks>   /dec <hex>     enkripsi/dekripsi lokal dengan session key (tanpa kirim)
  /status                      tampilkan key, sesi, mode
  /disconnect                  tutup sesi (lalu /connect lagi = session key baru)
  /quit                        keluar"""


def main():
    ap = argparse.ArgumentParser(description="Peer (Alice / Bob)")
    ap.add_argument("--id", required=True, help="ID entitas, mis. Alice atau Bob")
    ap.add_argument("--kdc", required=True, help="Alamat KDC, mis. 192.168.1.10:5000")
    ap.add_argument("--port", type=int, default=6000, help="Port listen peer (default 6000)")
    ap.add_argument("--bind", default="0.0.0.0", help="IP lokal yang dipakai (default 0.0.0.0)")
    args = ap.parse_args()

    kh, kp = parse_hostport(args.kdc, 5000)
    p = Peer(args.id, args.bind, args.port, kh, kp)
    print(f"=== Peer {args.id} ===")
    while True:
        k = input(f"Master key {args.id} (sama dengan yang terdaftar di KDC): ")
        try:
            p.set_master_key(k)
            break
        except ValueError as e:
            print(f"  [!] {e}")
    try:
        p.start_listener()
    except OSError as e:
        print(f"[!] Tidak bisa listen di {args.bind}:{args.port} — {e}\n"
              f"    Port kemungkinan dipakai proses lain (cek: ss -ltnp | grep {args.port}).\n"
              f"    Jika Alice & Bob di laptop yang sama, pakai --port berbeda (mis. 6001)\n"
              f"    atau --bind berbeda (mis. 127.0.0.2 dan 127.0.0.3).")
        return
    print(HELP)

    while True:
        try:
            line = input(p.prompt)
        except (EOFError, KeyboardInterrupt):
            print()
            break
        line = line.rstrip("\n")
        if not line.strip():
            continue
        try:
            if not line.startswith("/"):
                ct = p.send_chat(line)
                print(f"  Terkirim. Ks='{p.session.ks}' mode={p.mode}\n"
                      f"  Plaintext (ASCII): {line}\n  Ciphertext (HEX) : {ct}")
                continue
            cmd, _, arg = line.partition(" ")
            cmd = cmd.lower()
            if cmd == "/quit":
                break
            elif cmd == "/help":
                print(HELP)
            elif cmd == "/send":
                ct = p.send_chat(arg)
                print(f"  Plaintext (ASCII): {arg}\n  Ciphertext (HEX) : {ct}")
            elif cmd == "/connect":
                parts = arg.split()
                if len(parts) != 2:
                    raise ValueError("Format: /connect <ID> <IP>[:port]")
                h, port = parse_hostport(parts[1], 6000)
                p.connect(parts[0], h, port)
            elif cmd == "/key":
                p.set_master_key(arg)
                print(f"  Master key diubah -> '{arg}' ({key_variant(arg)})")
            elif cmd == "/sk":
                p.set_session_key(arg)
                print(f"  Session key diubah manual -> '{arg}' ({key_variant(arg)})")
            elif cmd == "/mode":
                if arg.upper() not in ("ECB", "CBC"):
                    raise ValueError("Pilih ecb atau cbc")
                p.mode = arg.upper()
                print(f"  Mode -> {p.mode}")
            elif cmd == "/kdc":
                p.kdc_host, p.kdc_port = parse_hostport(arg.strip(), 5000)
                print(f"  KDC -> {p.kdc_host}:{p.kdc_port}")
            elif cmd in ("/enc", "/dec"):
                if not p.session:
                    raise ValueError("Belum ada sesi (session key)")
                if cmd == "/enc":
                    print(f"  Ciphertext (HEX): {encrypt_text(p.session.ks, arg, p.mode)}")
                else:
                    print(f"  Plaintext (ASCII): {decrypt_hex(p.session.ks, arg, p.mode)}")
            elif cmd == "/status":
                s = p.session
                print(f"  ID={p.id}  listen={p.bind}:{p.port}  KDC={p.kdc_host}:{p.kdc_port}\n"
                      f"  Master key='{p.master_key}' ({key_variant(p.master_key)})  mode={p.mode}\n"
                      + (f"  Sesi dengan {s.peer_id} ({s.role}), Ks='{s.ks}'" if s else "  Tidak ada sesi"))
            elif cmd == "/disconnect":
                p.disconnect()
                print("  Sesi ditutup")
            else:
                print("  Perintah tidak dikenal. /help")
        except (ValueError, OSError) as e:
            print(f"  [!] {e}")
    p.stop()


if __name__ == "__main__":
    main()