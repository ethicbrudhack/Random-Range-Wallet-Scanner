import random
import os
import time
import threading
import sqlite3
import base58
import hashlib
from typing import List, Tuple

from bip_utils import (
    Secp256k1PrivateKey,
    P2PKHAddrEncoder,
    P2WPKHAddrEncoder,
    BchP2PKHAddrEncoder,
    EthAddrEncoder,
)
import nacl.signing  # Solana (ed25519)

# ───────────────────────────────────────────────────────────
# KONFIGURACJA
# ───────────────────────────────────────────────────────────
DB_PATH = "alladdresses3.db"
OUTPUT_FILE = "HITS_RANGE.txt"
MIN_LOG_INTERVAL = 50
MAX_WORKERS = 1

sema = threading.BoundedSemaphore(MAX_WORKERS)
file_lock = threading.Lock()
print_lock = threading.Lock()

checked = 0

# ───────────────────────────────────────────────────────────
# POMOCNICZE
# ───────────────────────────────────────────────────────────

def priv_to_wif(priv_hex: str, compressed: bool = True) -> str:
    b = bytes.fromhex(priv_hex)
    payload = b"\x80" + b + (b"\x01" if compressed else b"")
    check = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return base58.b58encode(payload + check).decode()

def solana_from_seed(seed32: bytes) -> Tuple[str, str]:
    signer = nacl.signing.SigningKey(seed32)
    pubkey = signer.verify_key.encode()
    addr = base58.b58encode(pubkey).decode()
    return addr, seed32.hex()

# ───────────────────────────────────────────────────────────
# GENERACJA ADRESÓW
# ───────────────────────────────────────────────────────────

def generate_addresses(priv_int: int) -> List[Tuple[str, str, str]]:
    priv_bytes = priv_int.to_bytes(32, "big")
    priv_hex = priv_bytes.hex()
    secp_priv = Secp256k1PrivateKey.FromBytes(priv_bytes)
    pub_key = secp_priv.PublicKey()

    out = []

    # BTC
    btc_p2pkh = P2PKHAddrEncoder.EncodeKey(pub_key, net_ver=b"\x00")
    btc_bech = P2WPKHAddrEncoder.EncodeKey(pub_key, hrp="bc")
    out.append(("BTC", btc_p2pkh, priv_to_wif(priv_hex)))
    out.append(("BTC", btc_bech, priv_to_wif(priv_hex)))

    # LTC
    ltc_p2pkh = P2PKHAddrEncoder.EncodeKey(pub_key, net_ver=b"\x30")
    ltc_bech = P2WPKHAddrEncoder.EncodeKey(pub_key, hrp="ltc")
    out.append(("LTC", ltc_p2pkh, priv_to_wif(priv_hex)))
    out.append(("LTC", ltc_bech, priv_to_wif(priv_hex)))

    # DOGE
    doge_p2pkh = P2PKHAddrEncoder.EncodeKey(pub_key, net_ver=b"\x1e")
    out.append(("DOGE", doge_p2pkh, priv_to_wif(priv_hex)))

    # DASH
    dash_p2pkh = P2PKHAddrEncoder.EncodeKey(pub_key, net_ver=b"\x4c")
    out.append(("DASH", dash_p2pkh, priv_to_wif(priv_hex)))

    # BCH
    bch_cash = BchP2PKHAddrEncoder.EncodeKey(pub_key, net_ver=b"\x00", hrp="bitcoincash").split(":")[-1]
    bch_legacy = P2PKHAddrEncoder.EncodeKey(pub_key, net_ver=b"\x00")
    out.append(("BCH", bch_cash, priv_to_wif(priv_hex)))
    out.append(("BCH", bch_legacy, priv_to_wif(priv_hex)))

    # ETH
    eth_addr = EthAddrEncoder.EncodeKey(pub_key)
    out.append(("ETH", eth_addr, priv_hex))

    # SOL
    sol_addr, sol_priv_hex = solana_from_seed(priv_bytes)
    out.append(("SOL", sol_addr, sol_priv_hex))

    return out

# ───────────────────────────────────────────────────────────
# BAZA DANYCH
# ───────────────────────────────────────────────────────────

def db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.execute("PRAGMA journal_mode = OFF;")
    conn.execute("PRAGMA synchronous = OFF;")
    conn.execute("PRAGMA temp_store = MEMORY;")
    return conn

def address_exists(conn: sqlite3.Connection, address: str) -> bool:
    try:
        cur = conn.cursor()
        cur.execute("SELECT 1 FROM addresses WHERE address = ?", (address,))
        return cur.fetchone() is not None
    except Exception:
        return False

# ───────────────────────────────────────────────────────────
# PRZETWARZANIE KLUCZA
# ───────────────────────────────────────────────────────────

def process_key(priv_int: int, conn: sqlite3.Connection):
    global checked
    entries = generate_addresses(priv_int)

    hit = False
    for coin, addr, _ in entries:
        if address_exists(conn, addr):
            hit = True
            break

    with print_lock:
        print(f"[KEY] {priv_int}")
        for coin, addr, priv in entries:
            print(f"[GEN] {coin} | {addr} | key: {priv}")

    if hit:
        with file_lock:
            with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
                f.write(f"✅ HIT dla klucza {priv_int}\n")
                for coin, addr, priv in entries:
                    f.write(f"{coin}|{addr}|key:{priv}\n")

        with print_lock:
            print(f"\033[92m[HIT] Znaleziono trafienie dla klucza {priv_int}\033[0m")

    checked += len(entries)
    if checked % MIN_LOG_INTERVAL == 0:
        with print_lock:
            print(f"[INFO] Sprawdzono {checked} wygenerowanych adresów")

# ───────────────────────────────────────────────────────────
# WORKER DETERMINISTYCZNY
# ───────────────────────────────────────────────────────────

def random_worker_range(start_int: int, end_int: int, attempts: int = 100000000):
    conn = db_connection()
    for _ in range(attempts):
        rand_key = random.randint(start_int, end_int - 1)
        process_key(rand_key, conn)


# ───────────────────────────────────────────────────────────
# MAIN
# ───────────────────────────────────────────────────────────

def main():
    if not os.path.exists(DB_PATH):
        print(f"Brak bazy {DB_PATH}")
        return

    b1 = int(input("Od bitu: "))
    b2 = int(input("Do bitu: "))
    if b2 <= b1:
        print("'Do bitu' musi być większe od 'Od bitu'")
        return

    start = 2 ** b1
    end = 2 ** b2
    print(f"Zakres prywatnych kluczy: {start} … {end - 1}")

    threads = []
    for _ in range(MAX_WORKERS):
        sema.acquire()
        t = threading.Thread(target=random_worker_range, args=(start, end, 100000000))
        t.start()
        threads.append(t)

    try:
        for t in threads:
            t.join()
        print(f"\n✅ Gotowe. Sprawdzono {checked} adresów.")
    except KeyboardInterrupt:
        print("\n[🛑] Przerwano przez użytkownika.")



if __name__ == "__main__":
    main()
