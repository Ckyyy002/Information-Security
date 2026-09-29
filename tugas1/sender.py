"""
sender.py — Pihak SENDER (device A).

Terhubung ke RECEIVER melalui TCP. Setelah terhubung, kedua pihak dapat
saling mengirim & menerima pesan terenkripsi DES-CBC (dua arah).

Pemakaian:
    python sender.py --host <IP_RECEIVER> [--port 5000] [--key shared.key]
"""

import argparse
import socket

from channel import run_chat
from des import DES, load_key


def main():
    ap = argparse.ArgumentParser(description="Sender — DES encrypted channel")
    ap.add_argument("--host", required=True, help="IP address receiver")
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--key", default="shared.key", help="file pre-shared key")
    args = ap.parse_args()

    cipher = DES(load_key(args.key))

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print(f"[SENDER] Menghubungkan ke {args.host}:{args.port} ...")
    sock.connect((args.host, args.port))
    print("[SENDER] Terhubung ke receiver.")
    run_chat(sock, cipher, me="SENDER", peer="RECEIVER")


if __name__ == "__main__":
    main()
