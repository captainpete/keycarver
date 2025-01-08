# Keycarver

Checks sequences of bytes on drives/files to see if they're valid Bitcoin private keys.
Tests against an address database for validity.

### Usage

```
Usage: keycarver <COMMAND>

Commands:
  index-build  Build an address index from a directory of block files
  index-query  Query the address index for a BitCoin p2pkh address
  scan-raw     Scan by testing keys for every 32-byte sequence in the file
  help         Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

### Advantages

- If a private key exists in big-endian format as a contiguous sequence of bytes, and that private key simply corresponds to a known address, then this approach may serve you.
- Runs at around 300k keys/sec on a 5975WX (32 cores).
- Memory-mapped file access, O(1) address validation through an over-engineered PKH index.

### Limitations

- This is a low-level, brute-force approach that will work for some very old keys (pre-2012), as was my use-case.
- Experimental support for HD wallets (BIP-0032) on the feature branch.
- Still very slow for large drives, works best with images of old USB drives.
- No awareness of wallet formats. Consider [btc-recover](https://btcrecover.readthedocs.io/en/latest/).
- No GPU acceleration.
- No support from this maintainer.

### The journey

I had downtime, and a stack of dusty USB drives taking up space in a junk drawer.
I'd lost track of some old wallets a while back, and had a suspicion one of these keys might contain a backup.

I'd (helpfully?) formatted these 4GB USB keys, but hadn't zeroed the free-space.
So I imaged the drives using [ddrescue](https://www.gnu.org/software/ddrescue/) and got to work.
Traditional file-carving using [photorec](https://en.wikipedia.org/wiki/PhotoRec) was throwing up a lot of false-positives for wallets (BerkeleyDB, SQLite, etc).
So I settled on the approach of brute-forcing it.
If the sequence of SK bytes was on disk somewhere, I'd find it.

I set up a bitcoin full node to download all the blocks, and started writing code.
Good news, I was able to recover previously lost keys, even if they did correspond to empty wallets.

### The solution

This program reads a disk image and tests every possible sequence of bytes as a candidate Bitcoin private key.
It does this by reading using a sliding window 32 bytes long (assuming byte-alignment for 256-bit private keys) and generates candidate keys.
Each candidate key is tested to see if it fits secp256k1 curve order,
then converted to a public key, then to a public key hash (PKH).
The PKHs are then checked against an address database populated ahead of time by scanning the blockchain for PK2PKH transactions.

### Performance considerations

Given the number of known PKHs, I spent a bit of time making the lookup fast.
The address building routine constructs a minimal perfect hash function that converts a PKH to an offset in the index.
With a memory-mapped address index, this permits parallel O(1) lookups.

Additionally, there's a cost to the `SK -> PK -> PKH` process, so I make use of an LRU cache.
For the data on my drives this resulted in a big speedup.
IO is about the only thing not parallelized, and represents a bit of a trade-off.

This could be made faster with GPU acceleration of the secp256k1 SK to PK, and the `RIPEMD160(SHA256(PK))`, but it was fast enough for my purposes.

### Contributions

- Fork and enjoy.
- If this helps you uncover a massive treasure trove, I'll happily accept a few [LBMA Good Delivery gold bars](https://en.wikipedia.org/wiki/Good_Delivery) by way of thanks.
