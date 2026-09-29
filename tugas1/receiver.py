"""
receiver.py — Pihak RECEIVER (device B).

Membuka port dan menunggu SENDER terhubung. Setelah terhubung, kedua pihak
dapat saling mengirim & menerima pesan terenkripsi DES-CBC (dua arah).

Pemakaian:
    python receiver.py [--host 0.0.0.0] [--port 5000] [--key shared.key]
"""

import argparse
import socket

from channel import run_chat
from des import DES, load_key


def main():
    ap = argparse.ArgumentParser(description="Receiver — DES encrypted channel")
    ap.add_argument("--host", default="0.0.0.0", help="alamat bind (default 0.0.0.0)")
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--key", default="shared.key", help="file pre-shared key")
    args = ap.parse_args()

    cipher = DES(load_key(args.key))

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.host, args.port))
    srv.listen(1)
    print(f"[RECEIVER] Menunggu sender di {args.host}:{args.port} ...")

    conn, addr = srv.accept()
    srv.close()
    print(f"[RECEIVER] Sender terhubung dari {addr[0]}:{addr[1]}")
    run_chat(conn, cipher, me="RECEIVER", peer="SENDER")


if __name__ == "__main__":
    main()
