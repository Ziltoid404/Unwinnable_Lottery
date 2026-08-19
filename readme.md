# The Unwinnable Lottery

> A lottery that's free to play and impossible to win.

This is an educational demonstration of one of the most counterintuitive truths in cryptography: you can run a perfectly valid attack, at enormous speed, on as many machines as you like, forever, and still have effectively zero chance of ever succeeding.

The "lottery" generates random cryptocurrency private keys and checks whether any of them happen to unlock a real, funded Bitcoin wallet. There is no entry fee. There is no trick. The code genuinely does exactly what it says.

It will also never, ever win. That is the entire point.

## The premise

Every Bitcoin wallet is protected by a private key drawn from an address space of 2^160 possible values. "Brute forcing" a wallet means guessing random keys and hoping one lands on an address that already holds funds.

So this tool does precisely that. It guesses. Fast. In parallel. And it loses every single time.

## The catch

Even at 10 billion guesses per second on a GPU farm, your first expected hit against a generous estimate of 1 billion funded addresses would arrive roughly **3.36 x 10^11 times the current age of the universe** from now.

It is more than 300 billion times the entire age of everything that has ever existed.

```
Address space         : 2^160  = 1.46 x 10^48
Generous funded guess : 1,000,000,000
Win chance per key    : 6.84 x 10^-40
Expected keys to win  : 1.46 x 10^39
Wait at 10B keys/sec  : ~3.36 x 10^11 x age of the universe
```

The address space is the bottleneck. You could make the code a million times faster and the conclusion would not move in any way a human could perceive.

The exact thing that makes this lottery unwinnable is what makes cryptographic keys unbreakable. Your Bitcoin is safe because the math behind it is brutal.

## Read-only by design

This is the part that matters, so it gets its own section.

This tool is **read-only**. It contains no signing, spending, or sweeping code, and it never will. On the astronomically improbable event of a match, it writes a symbolic record to a local `Golden Ticket.txt` file and keeps scanning. It does not, and cannot, move anyone's funds.

To be completely clear: using a found key to take funds you do not own would be theft. This project exists to demonstrate why that outcome is impossible, not to pursue it.

## Installation

Requires Python 3.

```bash
pip install coincurve pycryptodome
```

## Usage

```bash
# Default run: Bitcoin only, all CPU cores, empty funded set (always misses)
python3 unwinnable_lottery.py

# Check against a real funded-address file
python3 unwinnable_lottery.py --funded funded.txt

# Limit workers
python3 unwinnable_lottery.py --workers 8 --funded funded.txt

# See the Golden Ticket feature without waiting for the heat death of the universe
python3 unwinnable_lottery.py --demo-ticket
```

While running, it prints a live readout:

```
checked   12,480,000 |   415,000 keys/s | P(any hit) 8.54e-33 | wait 3.36e11x age of universe | hits 0
```

Press Ctrl+C to stop. It will report how much of the address space you explored, which will be a number indistinguishable from zero.

## Options

| Flag | Description |
| --- | --- |
| `--workers N` | Number of parallel processes. Defaults to all CPU cores. |
| `--funded PATH` | Path to a funded-address file. Omit it and every check is a guaranteed miss. |
| `--min-balance N` | Only load addresses holding at least N satoshis. Trims memory, and stops reading early on a balance-sorted file. |
| `--no-sorted` | Set this if your funded file is not sorted by balance descending. |
| `--chains btc\|eth\|both` | Which chain(s) to derive and check. Default: `btc`. |
| `--demo-ticket` | Write one clearly-fake sample Golden Ticket so you can see the output format, then exit. |

## The funded-address file

The optional `--funded` file uses the Loyce.club format: one address per line, optionally followed by a balance in satoshis.

```
address balance
1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa 6850000000
3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy 1200000000
bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4 50000000
```

Addresses are decoded to their raw 20-byte values so comparisons happen on bytes, not strings. P2WSH and Taproot (32-byte) programs are decoded and dropped, since they cannot match what the worker derives. If you omit the file, the funded set is empty and the tool is purely a benchmark of how futile the search is.

## How it works

The "fast" in the filename refers to wringing the most futility-per-second out of your hardware. None of it changes the conclusion.

1. **One elliptic-curve multiply per key.** Both the Bitcoin HASH160 and the Ethereum address are derived from a single public key, since both chains share the secp256k1 curve. No heavyweight wallet objects are built.
2. **Raw-byte comparison in the hot loop.** Base58, bech32, EIP-55, and hex encoding only ever run on a (statistically nonexistent) hit, not millions of times per second.
3. **Multiprocessing.** The search is embarrassingly parallel, so throughput scales almost linearly with cores.

## Why this exists

We are not rational about probability. We are emotional about possibility.

Tell someone the odds are 1 in 10^48 and show them the proof, and a surprising number will still ask how to run it. That instinct is the same one behind state lotteries, longshot job applications, and cold emails to people who will never reply. We know the odds. We reach for the ticket anyway.

This project is a small, honest monument to that instinct, and a demonstration of the mathematics that quietly keeps the entire cryptocurrency ecosystem standing.

The lottery remains free to play, and impossible to win.

## License

Provided as-is for educational purposes. Use it to learn, to teach, or to lose gracefully. Do not use a found key to access funds that are not yours.
