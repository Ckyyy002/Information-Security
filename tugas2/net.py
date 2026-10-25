"""
net.py — utilitas jaringan & tampilan (dipakai KDC dan peer).

Format pesan di jaringan:
    [4 byte panjang, big-endian][JSON UTF-8]
JSON dipilih supaya isi paket mudah dibaca di Wireshark (Follow TCP Stream):
field "step" menunjukkan langkah skenario, field ciphertext berisi HEX.
"""

import json
import socket
import struct
import threading
import time

MAX_MSG = 1024 * 1024
_print_lock = threading.Lock()


def log(tag, text, prompt=None):
    """Cetak aman dari banyak thread; tampilkan ulang prompt bila ada."""
    ts = time.strftime("%H:%M:%S")
    with _print_lock:
        print(f"\r[{ts}] [{tag}] {text}")
        if prompt:
            print(prompt, end="", flush=True)


def send_msg(sock, obj):
    data = json.dumps(obj).encode("utf-8")
    sock.sendall(struct.pack(">I", len(data)) + data)


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def recv_msg(sock):
    """Kembalikan dict, atau None jika koneksi ditutup."""
    hdr = _recv_exact(sock, 4)
    if hdr is None:
        return None
    (length,) = struct.unpack(">I", hdr)
    if length > MAX_MSG:
        raise ValueError("Pesan terlalu besar")
    body = _recv_exact(sock, length)
    if body is None:
        return None
    return json.loads(body.decode("utf-8"))


def make_listener(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen(5)
    return s


def make_connection(host, port, bind_ip=None, timeout=10):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if bind_ip and bind_ip not in ("0.0.0.0", ""):
        s.bind((bind_ip, 0))      # paksa IP sumber (berguna untuk uji 1 mesin)
    s.settimeout(timeout)
    s.connect((host, port))
    return s


def parse_hostport(text, default_port):
    if ":" in text:
        h, p = text.rsplit(":", 1)
        return h, int(p)
    return text, default_port
