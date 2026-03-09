# Keycarver

Scans raw disk images for Bitcoin private keys by testing every 32-byte sequence against a pre-built index of known blockchain addresses.

Full writeup: [dojo7.com/2025/01/08/keycarver](https://dojo7.com/2025/01/08/keycarver/)

### Building

```
cargo build --release
```

### Workflow

There are three steps: build an address index from your Bitcoin node's block files, then scan drive images against it.

**1. Build the address index**

```
keycarver index-build --block-dir <path/to/blocks> --index-dir <path/to/index>
```

Scans all `blk*.dat` files in `block-dir`, extracts P2PKH and P2WPKH addresses, and builds a minimal perfect hash index for O(1) lookup. Takes a while on a full node; only needs to be done once. The `--factor` parameter (default 1.7) controls the MPHF construction trade-off between build time and index size.

**2. Query the index (optional sanity check)**

```
keycarver index-query --address <address> --index-dir <path/to/index>
```

**3. Scan a drive image**

```
keycarver scan-raw \
  --file <image.bin> \
  --checkpoint-file <image.bin.chk> \
  --index-dir <path/to/index> \
  --cache-size 16777216
```

Tests every byte offset in the file as a candidate 32-byte private key. Checks each valid key against the index. Saves progress to `--checkpoint-file` every second so interrupted scans can be resumed. `--cache-size` controls the deduplication cache (entries of 32 bytes each, ~64 bytes overhead per entry); the default 16M entries uses ~1GB of RAM — increase this on machines with more available memory.

Output lines look like:
```
priv: <hex>, pkh: <hex>, p2pkh: <1addr>, p2wpkh: <bc1addr>, offset: <byte offset>
```

### Checking recovered keys

Once you have results, `balance_check.py` checks each recovered key's addresses against the blockchain:

```
uv sync
uv run balance_check.py checkpoints/ --output results.csv
```

Checks both P2PKH and P2WPKH address forms for each key, deduplicates keys appearing across multiple checkpoint files, and writes a full CSV. Hits are printed immediately as they're found.

### How it works

The scanner reads the image with a 32-byte sliding window, one byte at a time. Each window is:

1. Validated against the secp256k1 curve order
2. Converted to a compressed public key via scalar multiplication
3. Hashed: `RIPEMD160(SHA256(pubkey))` to get the public key hash (PKH)
4. Looked up in the index

The index is built using [boomphf](https://github.com/10XGenomics/rust-boomphf) — a minimal perfect hash function over all known PKHs. At query time, the MPHF maps a PKH to an offset in a memory-mapped flat file storing the actual PKH bytes at that position. A match requires the stored value to equal the query, ruling out false positives from hash collisions.

Repeated byte sequences (common in sparse or zeroed regions of a drive) are filtered by a deduplication cache before the expensive EC multiplication step.

### Performance

- ~300k keys/sec on a 5975WX using 32 worker threads
- Index startup: ~1 second for a full-blockchain index (~17GB index, ~370MB MPHF)
- Memory: MPHF loaded into RAM (~370MB), index file memory-mapped

### Limitations

- Only finds keys stored as a contiguous 32-byte big-endian sequence. Keys in wallet file formats (Bitcoin Core, Electrum, etc.) won't be found this way — use [btc-recover](https://btcrecover.readthedocs.io/en/latest/) instead.
- No support for HD wallet derivation (BIP-32). Experimental support is on a feature branch.
- No GPU acceleration of the EC or hash operations.
- No support from this maintainer.

### Contributions

- Fork and enjoy.
- If this helps you uncover a massive treasure trove, I'll happily accept a few [LBMA Good Delivery gold bars](https://en.wikipedia.org/wiki/Good_Delivery) by way of thanks.
