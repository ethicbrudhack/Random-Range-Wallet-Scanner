🎲 Random Range Wallet Scanner (Untested Prototype)

⚠️ Educational / Research Use Only — Untested and Potentially Unsafe
This script is an experimental prototype for educational and research use.
It has not been thoroughly tested, may contain bugs, and could behave unpredictably.
Use it only in a safe, offline environment and never to attempt access to wallets or addresses that you do not own.

📘 Overview

This Python script generates random private keys within a user-defined numerical range, derives multiple cryptocurrency addresses from each key (BTC, LTC, DOGE, DASH, BCH, ETH, SOL), and checks whether any of those addresses exist in a local SQLite database of known addresses (alladdresses3.db).

If a match (“hit”) is found, the script immediately logs it to an output file (HITS_RANGE.txt) and prints a highlighted message.

The program demonstrates key/address derivation from random entropy — useful for learning how wallets encode and structure addresses, but must not be used for real-world brute-forcing or recovery of other people’s wallets.

⚙️ Features

Random generation of 256-bit private keys within a numeric range (2**start_bit … 2**end_bit).

Derives public keys and addresses for multiple cryptocurrencies:

Bitcoin (BTC) — P2PKH, Bech32

Litecoin (LTC) — P2PKH, Bech32

Dogecoin (DOGE) — P2PKH

Dash (DASH) — P2PKH

Bitcoin Cash (BCH) — CashAddr & Legacy formats

Ethereum (ETH) — Hex address

Solana (SOL) — ed25519 base58 public key

Checks generated addresses against a local SQLite DB (addresses table).

Logs all hits immediately to a text file.

Basic multi-threading support (configurable worker count).

Minimal resource usage — no caching or bulk inserts.

🧠 How It Works

User input
On startup, the script prompts:

From bit: 
To bit: 


Example: entering 120 and 121 scans the integer range 2^120 … 2^121 - 1.

Private key generation
A random integer is selected from the specified range and converted into 32-byte big-endian form.

Address derivation
For each private key:

A secp256k1 public key is generated (via bip_utils).

Addresses are encoded for each supported cryptocurrency using appropriate standards (P2PKH, Bech32, etc.).

Solana uses an ed25519 keypair via nacl.signing.

Database check
Each address is queried in alladdresses3.db:

SELECT 1 FROM addresses WHERE address = ?


If found → logged as a “hit”.

Logging

Console output prints generated addresses and progress.

Hits are appended to HITS_RANGE.txt.

🧩 Configuration
Variable	Description	Default
DB_PATH	Path to the SQLite database of known addresses	alladdresses3.db
OUTPUT_FILE	File to log discovered hits	HITS_RANGE.txt
MAX_WORKERS	Number of worker threads	1
MIN_LOG_INTERVAL	Progress print interval	50 addresses
🧰 Requirements
pip install bip-utils pynacl base58


Ensure the local database exists and has a compatible schema:

CREATE TABLE addresses (address TEXT PRIMARY KEY);

▶️ Usage Example
python3 random_range_wallet_scanner.py


Then, when prompted:

From bit: 120
To bit: 122


The script will scan the range between 2^120 and 2^122, generate random keys, derive addresses, and check for matches.

⚠️ Disclaimer

This software is for educational, testing, and cryptographic research purposes only.

It is not optimized, not validated, and may produce incorrect or duplicate results.

It has not been tested for reliability, correctness, or security.

Do not use this script to search real networks or attempt unauthorized access to any wallet.

The author(s) assume no liability for any misuse, loss of data, or damages resulting from its use.

🚧 Limitations & Notes

Untested — may contain logic, threading, or encoding errors.

SQLite lookups are simple and unoptimized.

Performance is single-machine, CPU-bound (no GPU support).

Solana and Ethereum derivations are simplified and may differ from production wallets.

No safety mechanisms to prevent scanning huge numeric ranges — use small ranges only for demonstration.

💡 Educational Use Cases

Learn how different cryptocurrencies derive and encode addresses.

Explore relationships between private keys and address formats.

Demonstrate why random “brute-force” key scanning is computationally infeasible.

Build intuition about keyspace size and address collisions.

🪪 License

MIT License — provided “AS IS”, without warranty of any kind.
If you reuse this code, please keep the educational-use disclaimer visible.

BTC donation address: bc1q4nyq7kr4nwq6zw35pg0zl0k9jmdmtmadlfvqhr
