"""
channel.py — Lapisan transmisi yang dipakai bersama oleh sender.py & receiver.py.

Format frame di jaringan (TCP):
    [ 4 byte panjang (big-endian) ][ IV 8 byte ][ ciphertext n*8 byte ]

Yang dikirim lewat jaringan HANYA IV + ciphertext. Key tidak pernah dikirim;
masing-masing pihak membacanya dari file shared.key miliknya sendiri.
"""

import socket
import struct
import sys
import threading
from datetime import datetime

from des import DES


def _ts() -> str:
    return datetime.now().strftime("%H:%M:%S")


def send_frame(sock: socket.socket, payload: bytes) -> None:
    sock.sendall(struct.pack(">I", len(payload)) + payload)


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Koneksi ditutup oleh peer.")
        buf += chunk
    return buf


def recv_frame(sock: socket.socket) -> bytes:
    (length,) = struct.unpack(">I", _recv_exact(sock, 4))
    return _recv_exact(sock, length)


def run_chat(sock: socket.socket, cipher: DES, me: str, peer: str) -> None:
    """Komunikasi dua arah (full-duplex): satu thread menerima, thread utama mengirim."""
    stop = threading.Event()

    def receiver_loop():
        try:
            while not stop.is_set():
                frame = recv_frame(sock)
                print(f"\n[{_ts()}] <<< diterima dari {peer}")
                print(f"    ciphertext (hex): {frame.hex().upper()}")
                try:
                    plain = cipher.decrypt(frame).decode("utf-8")
                    print(f"    plaintext       : {plain}")
                except ValueError as e:
                    print(f"    [!] gagal dekripsi: {e}")
                print(f"{me}> ", end="", flush=True)
        except (ConnectionError, OSError):
            if not stop.is_set():
                print(f"\n[{_ts()}] {peer} memutus koneksi. Tekan Enter untuk keluar.")
            stop.set()

    threading.Thread(target=receiver_loop, daemon=True).start()
    print(f"Terhubung dengan {peer}. Ketik pesan lalu Enter. Ketik /quit untuk keluar.\n")

    try:
        while not stop.is_set():
            msg = input(f"{me}> ")
            if stop.is_set():
                break
            if msg.strip() == "/quit":
                break
            if not msg:
                continue
            ct = cipher.encrypt(msg.encode("utf-8"))
            send_frame(sock, ct)
            print(f"[{_ts()}] >>> dikirim ke {peer}")
            print(f"    plaintext       : {msg}")
            print(f"    ciphertext (hex): {ct.hex().upper()}")
    except (EOFError, KeyboardInterrupt):
        pass
    finally:
        stop.set()
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        sock.close()
        print("Koneksi ditutup.")
        sys.exit(0)
