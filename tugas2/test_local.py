"""
test_local.py — uji otomatis end-to-end di satu mesin Linux memakai
3 IP loopback berbeda (KDC 127.0.0.1, Alice 127.0.0.2, Bob 127.0.0.3).
Hanya untuk latihan; demo sebenarnya dijalankan di 3 perangkat.

    python test_local.py
"""
import time

from aes import selftest
from kdc import KDC
from peer import Peer


def wait(cond, t=5):
    end = time.time() + t
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.05)
    return False


def check(name, ok):
    print(f"[{'PASS' if ok else 'FAIL'}] {name}")
    return ok


def main():
    ok = check("AES self-test FIPS-197", selftest(verbose=False))

    kdc = KDC("127.0.0.1", 5500)
    kdc.set_key("Alice", "KunciAlice123456")
    kdc.set_key("Bob", "KunciBobRahasia!")
    kdc.start()

    alice = Peer("Alice", "127.0.0.2", 6600, "127.0.0.1", 5500)
    bob = Peer("Bob", "127.0.0.3", 6600, "127.0.0.1", 5500)
    alice.set_master_key("KunciAlice123456")
    bob.set_master_key("KunciBobRahasia!")
    alice.start_listener()
    bob.start_listener()
    time.sleep(0.2)

    # Skenario 1-5
    alice.connect("Bob", "127.0.0.3", 6600)
    ok &= check("Langkah 1-5 selesai, kedua sisi punya Ks yang sama",
                wait(lambda: bob.session is not None) and alice.session.ks == bob.session.ks
                and alice.session.ks == kdc.issued[-1][2])

    # Dua arah
    alice.send_chat("Halo Bob, ini Alice!")
    bob.send_chat("Hai Alice, pesan diterima.")
    ok &= check("Alice -> Bob", wait(lambda: any(m[1] == "Halo Bob, ini Alice!" for m in bob.inbox)))
    ok &= check("Bob -> Alice", wait(lambda: any(m[1] == "Hai Alice, pesan diterima." for m in alice.inbox)))

    # Mode ECB
    alice.mode = "ECB"
    alice.send_chat("Pesan mode ECB")
    ok &= check("Mode ECB", wait(lambda: any(m[1] == "Pesan mode ECB" for m in bob.inbox)))

    # Session key salah di sisi penerima
    bob.set_session_key("SessionKeySalah!")
    n = len(bob.inbox)
    alice.send_chat("Seharusnya gagal")
    ok &= check("Key berbeda -> gagal dekripsi", wait(lambda: len(bob.inbox) > n) and bob.inbox[-1][1] != "Seharusnya gagal")

    # Re-key: disconnect, connect lagi -> Ks baru
    old = alice.session.ks
    alice.disconnect()
    wait(lambda: bob.session is None)
    bob.connect("Alice", "127.0.0.2", 6600)          # kali ini Bob yang memulai
    ok &= check("Bob sebagai initiator, Ks baru", wait(lambda: alice.session is not None)
                and alice.session.ks == bob.session.ks != old)

    # Master key diubah di KDC tanpa restart, peer belum diubah -> gagal
    alice.disconnect()
    wait(lambda: bob.session is None)
    kdc.set_key("Alice", "KunciAliceBaru!!")
    try:
        alice.connect("Bob", "127.0.0.3", 6600)
        failed = False
    except ValueError as e:
        failed = "master key" in str(e)
    ok &= check("Master key Alice tidak cocok dengan KDC -> ditolak", failed)
    alice.set_master_key("KunciAliceBaru!!")
    alice.connect("Bob", "127.0.0.3", 6600)
    ok &= check("Setelah master key disamakan -> berhasil", wait(lambda: bob.session is not None))

    # AES-256 session key
    alice.disconnect()
    wait(lambda: bob.session is None)
    kdc.session_key_len = 32
    alice.connect("Bob", "127.0.0.3", 6600)
    wait(lambda: bob.session is not None)
    alice.send_chat("Pakai AES-256")
    ok &= check("Session key 32 karakter (AES-256)",
                len(alice.session.ks) == 32 and wait(lambda: any(m[1] == "Pakai AES-256" for m in bob.inbox)))

    # ID tak terdaftar
    alice.disconnect()
    try:
        alice.connect("Charlie", "127.0.0.3", 6600)
        failed = False
    except ValueError as e:
        failed = "tidak terdaftar" in str(e)
    ok &= check("ID tidak terdaftar ditolak KDC", failed)

    for x in (alice, bob, kdc):
        x.stop()
    print("\nSEMUA LULUS" if ok else "\nADA YANG GAGAL")


if __name__ == "__main__":
    main()
