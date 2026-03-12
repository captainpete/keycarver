# Keycarver

Scans raw disk images for Bitcoin private keys by testing every 32-byte sequence against a pre-built index of known blockchain addresses.

Full writeup: [dojo7.com/2025/01/08/keycarver](https://dojo7.com/2025/01/08/keycarver/)

### Building

```
cargo build --release
```

For GPU acceleration (requires CUDA toolkit and an NVIDIA GPU):

```
cargo build --release --features cuda
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

CPU:
```
keycarver scan-raw \
  --file <image.bin> \
  --checkpoint-file <image.bin.chk> \
  --index-dir <path/to/index> \
  --cache-size 16777216
```

GPU (requires `--features cuda` build):
```
keycarver scan-raw \
  --file <image.bin> \
  --checkpoint-file <image.bin.chk> \
  --index-dir <path/to/index> \
  --gpu \
  --gpu-chunk-size 4194304
```

Tests every byte offset in the file as a candidate 32-byte private key. Checks each valid key against the index. Saves progress to `--checkpoint-file` every second so interrupted scans can be resumed.

CPU options: `--cache-size` controls the deduplication cache (entries of 32 bytes each, ~64 bytes overhead per entry); the default 16M entries uses ~1GB of RAM.

GPU options: `--gpu-chunk-size` sets the batch size in bytes (default 1MB; 4–16MB recommended). Checkpoint files are compatible between CPU and GPU runs — you can switch modes and resume.

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

The CPU path filters repeated byte sequences with a deduplication cache before the EC multiplication step.

The GPU path runs the full SK→PKH pipeline (secp256k1 scalar multiply → SHA256 → RIPEMD160) in CUDA, one thread per byte offset. A precomputed table of 256 points (G, 2G, 4G, …, 2²⁵⁵·G) is generated in Rust and uploaded to the GPU once at startup. A double-buffer pipeline overlaps GPU computation with CPU-side index lookups (parallelised with rayon) so neither side sits idle waiting for the other.

### Performance

|Mode|Rate|Notes|
|---|---|---|
|CPU|~330k keys/sec|5975WX, 64 threads|
|GPU|~166 Mk/sec|RTX 3090, PCIe 4.0 ×16|

GPU throughput is limited by the CPU-side MPHF index lookup, not the CUDA kernel — the GPU finishes each batch well before the CPU consumes the results. The kernel itself has low SM occupancy (~192 registers/thread → 1–2 warps/SM on RTX 3090), but the bottleneck is the random-access memory latency of the MPHF lookup across 64 rayon threads.

The D→H transfer uses regular pinned host memory (`cuMemHostAlloc` with `flags=0`). Using write-combining pinned memory (`CU_MEMHOSTALLOC_WRITECOMBINED`) makes D→H async but CPU reads uncached, reducing throughput ~300×.

- Index startup: ~1 second for a full-blockchain index (~17GB index, ~370MB MPHF)
- Memory: MPHF loaded into RAM (~370MB), index file memory-mapped

### Limitations

- Only finds keys stored as a contiguous 32-byte big-endian sequence. Keys in wallet file formats (Bitcoin Core, Electrum, etc.) won't be found this way — use [btc-recover](https://btcrecover.readthedocs.io/en/latest/) instead.
- No support for HD wallet derivation (BIP-32). Experimental support is on a feature branch.
- GPU build requires CUDA 12.x toolkit and a compute capability 8.6+ GPU. Update the `cuda-12090` feature in `Cargo.toml` and `-arch=sm_86` in `build.rs` to match a different CUDA version or GPU architecture.
- No support from this maintainer.

### Contributions

- Fork and enjoy.
- If this helps you uncover a massive treasure trove, I'll happily accept a few [LBMA Good Delivery gold bars](https://en.wikipedia.org/wiki/Good_Delivery) by way of thanks.
