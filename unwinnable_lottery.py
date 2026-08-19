#!/usr/bin/env python3
"""
unwinnable_lottery.py
==========================
At, say, 10 billion keys/s on a GPU farm you would still expect your first
funded-address hit roughly 3.36 x 10^11 times (over 300 billion times) the
current age of the universe from now.

This tool is READ-ONLY. It has no signing/spending/sweeping code and never will.

Dependencies:
    pip install coincurve

Funded set format (optional): a Loyce.club-format address file (one Bitcoin
address per line, with an optional balance column). Empty/omitted => always misses.

There is one missing piece for this to "fully" work: a list of files with addresses.
You can get those from addresses.loyce.club and you must use the --funded flag.

Usage:
    python3 unwinnable_lottery.py
    python3 unwinnable_lottery.py --workers 8 --funded hashes.txt
"""

import argparse
import hashlib
import multiprocessing as mp
import os
import secrets
import time

from coincurve import PublicKey

ADDRESS_SPACE = 2 ** 160
FUNDED_ESTIMATE = 1_000_000_000
AGE_OF_UNIVERSE_SECONDS = 4.35e17
P_PER_KEY = FUNDED_ESTIMATE / ADDRESS_SPACE
EXPECTED_KEYS = 1 / P_PER_KEY
BATCH = 2000  # keys per reporting batch (amortizes IPC overhead)


GOLDEN_TICKET = "Golden Ticket.txt"


def write_golden_ticket(chain, priv_hex, h_hex):
    """Symbolic record of a 'win'. Under uniform-random generation this branch is
    statistically unreachable, so in real use this file is never written. This is a
    READ-ONLY tool: recording a key here does not move anything, and using a found
    key to take funds you don't own would be theft."""
    import datetime
    with open(GOLDEN_TICKET, "a") as f:
        f.write(f"=== GOLDEN TICKET  ({datetime.datetime.now().isoformat()}) ===\n")
        f.write(f"  chain        : {chain}\n")
        f.write(f"  hash160/addr : {h_hex}\n")
        f.write(f"  private key  : {priv_hex}\n")
        f.write("  note         : symbolic record only. This tool never spends.\n\n")


# ---------------------------------------------------------------------------
# Address decoders: turn a Base58 / bech32 address string into its raw bytes,
# so the funded set holds the same 20-byte values the worker derives & compares.
# ---------------------------------------------------------------------------
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _b58check_decode(s):
    """Base58Check-decode; return (version_byte, payload_bytes) or None if invalid."""
    num = 0
    for c in s:
        idx = _B58.find(c)
        if idx < 0:
            return None
        num = num * 58 + idx
    raw = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    raw = b"\x00" * (len(s) - len(s.lstrip("1"))) + raw  # restore leading-zero bytes
    if len(raw) < 5:
        return None
    data, checksum = raw[:-4], raw[-4:]
    if hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4] != checksum:
        return None
    return data[0], data[1:]


def _bech32_polymod(values):
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if ((b >> i) & 1) else 0
    return chk


def _bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _bech32_convertbits(data, frombits, tobits):
    """5->8 bit regrouping with strict validation; return bytes or None."""
    acc = bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None  # leftover bits must be zero padding
    return bytes(ret)


def _segwit_program(addr, hrp="bc"):
    """Decode a bech32/bech32m SegWit address to its witness program bytes, or None."""
    if any(ord(x) < 33 or ord(x) > 126 for x in addr):
        return None
    addr = addr.lower()
    pos = addr.rfind("1")
    if pos < 1 or pos + 7 > len(addr) or addr[:pos] != hrp:
        return None
    if not all(x in _BECH32_CHARSET for x in addr[pos + 1:]):
        return None
    data = [_BECH32_CHARSET.find(x) for x in addr[pos + 1:]]
    const = _bech32_polymod(_bech32_hrp_expand(hrp) + data)
    if const not in (1, 0x2BC830A3):  # bech32 (v0) or bech32m (v1+)
        return None
    witver = data[0]
    prog = _bech32_convertbits(data[1:-6], 5, 8)
    if prog is None or witver > 16 or not (2 <= len(prog) <= 40):
        return None
    if witver == 0 and len(prog) not in (20, 32):
        return None
    return prog


def address_to_bytes(addr):
    """Return the identifying bytes for a BTC address (20-byte hash / witness program),
    or None for anything that doesn't decode (e.g. Loyce 'm-...' non-standard markers)."""
    if addr.startswith(("1", "3")):              # P2PKH / P2SH (Base58Check)
        out = _b58check_decode(addr)
        return out[1] if out and len(out[1]) == 20 else None
    if addr.startswith("bc1"):                   # native SegWit (bech32/bech32m)
        return _segwit_program(addr)
    return None


def load_funded(path, min_balance=0, assume_sorted_desc=True):
    """Parse a Loyce.club funded-address file into a set of raw address-bytes.

    Format (whitespace-separated, optional header line 'address balance'):
        <address> <balance_in_satoshis>
    The alphabetical Loyce file (address only, no balance column) also works.

    Only 20-byte values can ever match what the worker derives, so 32-byte programs
    (P2WSH / Taproot) are decoded but dropped to save memory. P2SH 20-byte script
    hashes are kept: a match is membership-only and not spendable, but including
    them makes the futility check as comprehensive as possible.
    """
    funded = set()
    if not path:
        return funded
    kept = skipped = 0
    with open(path) as f:
        for line in f:
            parts = line.split()
            if not parts:
                continue
            addr = parts[0]
            if addr == "address" or addr.startswith("m-"):  # header / non-standard marker
                continue
            balance = None
            if len(parts) >= 2 and parts[1].lstrip("-").isdigit():
                balance = int(parts[1])
            if min_balance and balance is not None:
                if balance < min_balance:
                    # balance-sorted file is highest-first: once below the floor, stop
                    if assume_sorted_desc:
                        break
                    continue
            decoded = address_to_bytes(addr)
            if decoded is None or len(decoded) != 20:
                skipped += 1
                continue
            funded.add(decoded)
            kept += 1
    print(f"Loaded {kept:,} funded addresses ({skipped:,} skipped: non-standard / 32-byte / undecodable).")
    return funded


def worker(funded, result_q, stop):
    """Generate random keys and check their Bitcoin address against the funded set.

    Each key needs a compressed-pubkey serialize + SHA-256 + RIPEMD-160 to derive
    its HASH160, which is then compared (as raw bytes) against the funded set.
    """
    # Ignore Ctrl+C in workers: the main process catches it and signals us via `stop`.
    # Without this, Windows (spawn) delivers SIGINT to every process and each worker
    # prints its own KeyboardInterrupt traceback on shutdown. Purely cosmetic, but noisy.
    import signal
    signal.signal(signal.SIGINT, signal.SIG_IGN)

    sha256 = hashlib.sha256
    new_ripemd = lambda b: hashlib.new("ripemd160", b).digest()  # noqa: E731
    count = 0
    try:
        while not stop.is_set():
            for _ in range(BATCH):
                pk = secrets.token_bytes(32)
                P = PublicKey.from_valid_secret(pk)        # the one EC multiply
                btc_h160 = new_ripemd(sha256(P.format(True)).digest())
                if btc_h160 in funded:
                    result_q.put(("hit", "BTC", pk.hex(), btc_h160.hex()))
            count += BATCH
            result_q.put(("count", BATCH))
    except (KeyboardInterrupt, EOFError, BrokenPipeError):
        pass  # main process is tearing things down; exit quietly
    finally:
        try:
            result_q.put(("final", count))
        except Exception:
            pass


def banner(workers):
    print("=" * 74)
    print("  THE UNWINNABLE FREE LOTTERY  —  educational futility demo")
    print("=" * 74)
    print(f"  Workers / CPU cores  : {workers}")
    print(f"  Address space        : 2^160 = {ADDRESS_SPACE:.3e}")
    print(f"  Generous funded guess: {FUNDED_ESTIMATE:,}")
    print(f"  Win chance per key   : {P_PER_KEY:.3e}")
    print(f"  Expected keys to win : {EXPECTED_KEYS:.3e}")
    print("=" * 74)
    print("  (each random key's Bitcoin address is checked against the funded set)\n")


def main():
    ap = argparse.ArgumentParser(description="Educational unwinnable-lottery scanner (read-only, Bitcoin).")
    ap.add_argument("--workers", type=int, default=os.cpu_count(), help="parallel processes (default: all cores)")
    ap.add_argument("--funded", help="path to a Loyce.club-format funded-address file "
                                      "('address balance' per line; default: empty => always miss)")
    ap.add_argument("--min-balance", type=int, default=0,
                    help="only load addresses with at least this many satoshis (trims memory; "
                         "for the balance-sorted Loyce file this also stops reading early)")
    ap.add_argument("--no-sorted", action="store_true",
                    help="set if your funded file is NOT sorted by balance descending "
                         "(disables the early-stop optimization for --min-balance)")
    ap.add_argument("--demo-ticket", action="store_true",
                    help="write one sample Golden Ticket (clearly-fake placeholder) so you can see the feature, then exit")
    args = ap.parse_args()

    if args.demo_ticket:
        write_golden_ticket(
            "DEMO",
            "<sample placeholder - not a real key; this path is unreachable under random search>",
            "<sample placeholder hash>",
        )
        print(f"Wrote a sample (clearly fake) entry to {GOLDEN_TICKET!r} to demonstrate the feature.")
        print("In real use this file is never written, because the lottery is unwinnable.")
        return

    funded = load_funded(args.funded, min_balance=args.min_balance,
                         assume_sorted_desc=not args.no_sorted)
    banner(args.workers)
    print(f"Checking against {len(funded):,} known-funded hashes "
          f"({'empty set => always misses, as expected' if not funded else 'loaded'}).\n")

    result_q = mp.Queue()
    stop = mp.Event()
    procs = [mp.Process(target=worker, args=(funded, result_q, stop), daemon=True)
             for _ in range(args.workers)]
    for p in procs:
        p.start()

    checked = hits = 0
    started = time.time()
    last = started
    try:
        while True:
            msg = result_q.get()
            if msg[0] == "count":
                checked += msg[1]
            elif msg[0] == "hit":
                hits += 1
                _, chain, priv, h = msg
                write_golden_ticket(chain, priv, h)
                print(f"\n\n*** lottery 'hit' (astronomically improbable) ***")
                print(f"    chain: {chain}   hash: {h}")
                print(f"    private key (hex): {priv}")
                print(f"    written to: {GOLDEN_TICKET!r}")
                print("    NOTE: read-only demo. It will not move funds. Doing so would be theft.\n")
            now = time.time()
            if now - last >= 0.25:
                last = now
                elapsed = now - started
                rate = checked / elapsed if elapsed else 0
                cum_p = checked * P_PER_KEY
                wait = (EXPECTED_KEYS / rate / AGE_OF_UNIVERSE_SECONDS) if rate else float("inf")
                print(f"\rchecked {checked:>13,} | {rate:9.0f} keys/s | "
                      f"P(any hit) {cum_p:.2e} | wait {wait:.2e}x age of universe | hits {hits}",
                      end="", flush=True)
    except KeyboardInterrupt:
        stop.set()  # tell workers to finish; they ignore SIGINT themselves
        elapsed = time.time() - started
        # Give workers a moment to wind down, then make sure they're gone.
        for p in procs:
            p.join(timeout=1.0)
        for p in procs:
            if p.is_alive():
                p.terminate()
        print(f"\n\nStopped after {checked:,} keys in {elapsed:.1f}s "
              f"({checked / elapsed:,.0f} keys/s).")
        print(f"Fraction of address space explored: {checked / ADDRESS_SPACE:.2e}")
        print("The lottery remains free to play and impossible to win.")


if __name__ == "__main__":
    main()
