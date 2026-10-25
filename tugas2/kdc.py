"""
kdc.py — Key Distribution Center (implementasi manual).

KDC menyimpan master key setiap entitas (Ka untuk Alice, Kb untuk Bob).
Master key TIDAK di-hardcode: diinput saat start dan bisa diubah kapan saja
lewat konsol (tanpa restart).

Skenario (Stallings, Key Distribution Scenario):
  (1) A  -> KDC : IDA || IDB || N1                                (plaintext)
  (2) KDC -> A  : E(Ka, [Ks || IDA || IDB || N1]) || E(Kb, [Ks || IDA])
  (3) A  -> B   : E(Kb, [Ks || IDA])
  (4) B  -> A   : E(Ks, N2)
  (5) A  -> B   : E(Ks, f(N2))           f(N2) = N2 + 1
KDC menangani langkah (1) dan (2).

Jalankan:  python kdc.py --host 0.0.0.0 --port 5000
"""

import argparse
import secrets
import string
import threading

from aes import encrypt_text, validate_key, key_variant
from net import log, send_msg, recv_msg, make_listener

ALPHABET = string.ascii_letters + string.digits
PROMPT = "kdc> "


class KDC:
    def __init__(self, host="0.0.0.0", port=5000):
        self.host, self.port = host, port
        self.keys = {}                 # ID -> master key (ASCII)
        self.lock = threading.Lock()
        self.session_key_len = 16      # 16/24/32 -> AES-128/192/256
        self.issued = []               # riwayat (untuk pengujian)
        self._srv = None

    # ---------- manajemen key ----------
    def set_key(self, ident, key):
        if not ident.isalnum():
            raise ValueError("ID hanya boleh huruf/angka")
        validate_key(key)
        with self.lock:
            self.keys[ident] = key

    def del_key(self, ident):
        with self.lock:
            return self.keys.pop(ident, None) is not None

    def get_key(self, ident):
        with self.lock:
            return self.keys.get(ident)

    def gen_session_key(self):
        return "".join(secrets.choice(ALPHABET) for _ in range(self.session_key_len))

    # ---------- server ----------
    def start(self):
        self._srv = make_listener(self.host, self.port)
        threading.Thread(target=self._accept_loop, daemon=True).start()
        log("KDC", f"Listening di {self.host}:{self.port}")

    def stop(self):
        if self._srv:
            self._srv.close()

    def _accept_loop(self):
        while True:
            try:
                conn, addr = self._srv.accept()
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn, addr), daemon=True).start()

    def _handle(self, conn, addr):
        try:
            conn.settimeout(15)
            msg = recv_msg(conn)
            if not msg or msg.get("type") != "KDC_REQUEST":
                send_msg(conn, {"type": "ERROR", "reason": "Request tidak dikenal"})
                return
            id_a, id_b, n1 = str(msg["id_a"]), str(msg["id_b"]), str(msg["n1"])
            log("KDC", f"(1) Diterima dari {addr[0]}:{addr[1]} -> IDA={id_a}, IDB={id_b}, N1={n1}", PROMPT)

            ka, kb = self.get_key(id_a), self.get_key(id_b)
            if not ka or not kb:
                missing = id_a if not ka else id_b
                send_msg(conn, {"type": "ERROR", "reason": f"ID '{missing}' tidak terdaftar di KDC"})
                log("KDC", f"    Ditolak: '{missing}' tidak terdaftar", PROMPT)
                return
            if not (id_a.isalnum() and id_b.isalnum() and n1.isdigit()):
                send_msg(conn, {"type": "ERROR", "reason": "Format IDA/IDB/N1 tidak valid"})
                return

            ks = self.gen_session_key()
            plain_for_a = f"{ks}|{id_a}|{id_b}|{n1}"        # [Ks || IDA || IDB || N1]
            plain_ticket = f"{ks}|{id_a}"                    # [Ks || IDA]
            enc_for_a = encrypt_text(ka, plain_for_a, "CBC")
            ticket_b = encrypt_text(kb, plain_ticket, "CBC")

            send_msg(conn, {
                "step": 2,
                "type": "KDC_REPLY",
                "enc_for_a": enc_for_a,       # E(Ka, [Ks||IDA||IDB||N1])
                "ticket_for_b": ticket_b,     # E(Kb, [Ks||IDA])
            })
            self.issued.append((id_a, id_b, ks))
            log("KDC",
                f"(2) Ks dibuat ({key_variant(ks)}): '{ks}'\n"
                f"      E(Ka,[{plain_for_a}]) = {enc_for_a}\n"
                f"      E(Kb,[{plain_ticket}]) = {ticket_b}\n"
                f"      -> dikirim ke {id_a} ({addr[0]})", PROMPT)
        except Exception as e:
            log("KDC", f"Error menangani {addr}: {e}", PROMPT)
        finally:
            conn.close()


HELP = """Perintah KDC:
  list                  tampilkan entitas & master key terdaftar
  set <ID> <KEY>        tambah / ubah master key (KEY ASCII 16/24/32 karakter, boleh spasi)
  del <ID>              hapus entitas
  sklen <16|24|32>      panjang session key yang dibuat KDC
  help                  bantuan
  quit                  keluar"""


def ask_key(ident):
    while True:
        k = input(f"Master key untuk {ident} (16/24/32 karakter ASCII): ")
        try:
            validate_key(k)
            return k
        except ValueError as e:
            print(f"  [!] {e}")


def main():
    ap = argparse.ArgumentParser(description="Key Distribution Center")
    ap.add_argument("--host", default="0.0.0.0", help="IP untuk listen (default 0.0.0.0)")
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--ids", default="Alice,Bob", help="ID yang didaftarkan saat start")
    args = ap.parse_args()

    kdc = KDC(args.host, args.port)
    print("=== KDC — Key Distribution Center ===")
    for ident in [i.strip() for i in args.ids.split(",") if i.strip()]:
        kdc.set_key(ident, ask_key(ident))
    try:
        kdc.start()
    except OSError as e:
        print(f"[!] Tidak bisa listen di {args.host}:{args.port} — {e}\n"
              f"    Cek proses yang memakai port: ss -ltnp | grep {args.port}")
        return
    print(HELP)

    while True:
        try:
            line = input(PROMPT).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not line:
            continue
        parts = line.split(" ", 2)
        cmd = parts[0].lower()
        try:
            if cmd == "quit":
                break
            elif cmd == "help":
                print(HELP)
            elif cmd == "list":
                with kdc.lock:
                    for i, k in kdc.keys.items():
                        print(f"  {i:<10} {key_variant(k)}  '{k}'")
                print(f"  (session key: {kdc.session_key_len} karakter)")
            elif cmd == "set" and len(parts) == 3:
                kdc.set_key(parts[1], parts[2])
                print(f"  Master key {parts[1]} diubah -> '{parts[2]}'")
            elif cmd == "del" and len(parts) >= 2:
                print("  Dihapus" if kdc.del_key(parts[1]) else "  ID tidak ada")
            elif cmd == "sklen" and len(parts) >= 2 and parts[1] in ("16", "24", "32"):
                kdc.session_key_len = int(parts[1])
                print(f"  Session key sekarang {parts[1]} karakter")
            else:
                print("  Perintah tidak dikenal / argumen kurang. Ketik 'help'.")
        except ValueError as e:
            print(f"  [!] {e}")
    kdc.stop()


if __name__ == "__main__":
    main()