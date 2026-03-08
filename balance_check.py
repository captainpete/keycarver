#!/usr/bin/env python3
"""
Check Bitcoin/BCH balances for keys recovered from drive scans.

Usage:
    uv run balance_check.py checkpoints/
    uv run balance_check.py checkpoints-v2/
    uv run balance_check.py checkpoints/ checkpoints-v2/ --coins btc,bch --output results.csv
"""

import argparse
import csv
import json
import sys
import time
from glob import glob
from pathlib import Path

import requests
from bech32 import bech32_encode, convertbits
from tqdm import tqdm


def pkh_to_p2wpkh(pkh_bytes: bytes) -> str:
    converted = convertbits(pkh_bytes, 8, 5)
    return bech32_encode('bc', [0] + converted)


def load_checkpoints(dirs: list[str]) -> dict[str, dict]:
    """
    Load all recovered keys from checkpoint directories.
    Returns a dict keyed by address (both P2PKH and P2WPKH entries),
    deduplicating across files. Last-seen source wins on collision.
    """
    seen_sks = {}  # sk_hex -> canonical record, to avoid processing same key twice
    addr_map = {}  # addr -> record

    for d in dirs:
        chk_files = sorted(glob(str(Path(d) / '*.chk')))
        if not chk_files:
            print(f"Warning: no .chk files found in {d}", file=sys.stderr)
            continue

        for chk_file in chk_files:
            source = Path(chk_file).stem  # e.g. "usb_019.bin"
            with open(chk_file) as f:
                data = json.load(f)

            for record in data.get('results', []):
                sk_hex = bytes(record['sk']).hex()
                if sk_hex in seen_sks:
                    continue  # same key found on multiple drives, already recorded

                pkh = bytes(record['pkh'])
                p2pkh = record['addr']
                p2wpkh = pkh_to_p2wpkh(pkh)

                entry = {
                    'sk':     sk_hex,
                    'pkh':    pkh.hex(),
                    'p2pkh':  p2pkh,
                    'p2wpkh': p2wpkh,
                    'offset': record['offset'],
                    'source': source,
                }
                seen_sks[sk_hex] = entry

                # Index both address forms; they share the same entry
                addr_map[p2pkh]  = dict(entry, addr=p2pkh,  addr_type='p2pkh')
                addr_map[p2wpkh] = dict(entry, addr=p2wpkh, addr_type='p2wpkh')

    return addr_map


def check_balance(session: requests.Session, addr: str, coin: str, retries: int = 3) -> int | None:
    url = f"https://api.blockchain.info/haskoin-store/{coin}/address/{addr}/balance"
    for attempt in range(retries):
        try:
            r = session.get(url, timeout=15)
            if r.status_code == 404:
                return 0  # address never seen on-chain, balance is definitively 0
            if r.status_code == 429:
                wait = 10 * (attempt + 1)
                tqdm.write(f"Rate limited — waiting {wait}s", file=sys.stderr)
                time.sleep(wait)
                continue
            r.raise_for_status()
            return r.json().get('confirmed', 0)
        except Exception as e:
            if attempt == retries - 1:
                tqdm.write(f"Warning: failed to check {addr} ({coin}): {e}", file=sys.stderr)
                return None
            time.sleep(2 ** attempt)
    return None


def main():
    parser = argparse.ArgumentParser(
        description="Check BTC/BCH balances for keys recovered from drive scans",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument('checkpoint_dirs', nargs='+', metavar='DIR',
                        help='Directories containing .chk checkpoint files')
    parser.add_argument('--coins', default='btc,bch',
                        help='Comma-separated coins to check (default: btc,bch)')
    parser.add_argument('--output', '-o', default='balance_results.csv',
                        help='Output CSV path (default: balance_results.csv)')
    parser.add_argument('--sleep', type=float, default=1.0,
                        help='Seconds between API requests (default: 1.0)')
    args = parser.parse_args()

    coins = [c.strip().lower() for c in args.coins.split(',')]

    print(f"Loading checkpoints from: {args.checkpoint_dirs}", file=sys.stderr)
    addr_map = load_checkpoints(args.checkpoint_dirs)
    total = len(addr_map)
    print(f"Unique addresses to check: {total} ({total // 2} keys × 2 address formats)",
          file=sys.stderr)

    results = []
    hits = []

    session = requests.Session()
    session.headers['User-Agent'] = 'keycarver-balance-check/1.0'

    for entry in tqdm(addr_map.values(), desc='Checking balances', unit='addr'):
        row = dict(entry)
        has_balance = False
        for coin in coins:
            balance = check_balance(session, entry['addr'], coin)
            row[f'{coin}_balance'] = balance
            if balance and balance > 0:
                has_balance = True
            time.sleep(args.sleep)

        results.append(row)
        if has_balance:
            hits.append(row)
            bal_str = '  '.join(
                f"{c.upper()}: {row[f'{c}_balance']} sat"
                for c in coins if row.get(f'{c}_balance')
            )
            tqdm.write(f"*** HIT: {entry['addr']}  {bal_str}  (sk: {entry['sk']}  source: {entry['source']})")

    # Write full CSV
    fieldnames = ['addr', 'addr_type', 'p2pkh', 'p2wpkh', 'sk', 'pkh', 'offset', 'source'] + \
                 [f'{c}_balance' for c in coins]
    with open(args.output, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(results)
    print(f"\nFull results written to {args.output}", file=sys.stderr)

    # Summary
    print(f"\n{'='*60}", file=sys.stderr)
    if hits:
        print(f"ADDRESSES WITH BALANCE ({len(hits)} found):", file=sys.stderr)
        for row in hits:
            for coin in coins:
                bal = row.get(f'{coin}_balance') or 0
                if bal > 0:
                    print(f"  [{coin.upper()}] {row['addr']}  {bal} sat  "
                          f"({bal/1e8:.8f} {coin.upper()})", file=sys.stderr)
                    print(f"       sk: {row['sk']}", file=sys.stderr)
                    print(f"       source: {row['source']}  offset: {row['offset']}", file=sys.stderr)
    else:
        print("No addresses with non-zero balance found.", file=sys.stderr)


if __name__ == '__main__':
    main()
