"""Helper utilities for probing and inspecting slot layouts.
Importing this module has no side effects.
"""
# slot_layout_probe.py
b/slot_layout_probe.py
# Probe a contract's storage layout: scan a set/range of slots at two blocks,
# report non-zero values and changes, and emit commitments + pair roots (CSV/STDOUT).
import logging

# Library-friendly logger (silent unless configured by the host app)
logger = logging.getLogger(__name__)
if not logger.handlers:
    logger.addHandler(logging.NullHandler())
    logger.propagate = False

from __future__ import annotations
__version__: str = "0.1.0"
__author__: str = "Contributors"

import os, sys, csv, time, argparse
from typing import Iterable, List, Tuple
from web3 import Web3

RPC_URL = os.getenv("RPC_URL", "https://mainnet.infura.io/v3/your_api_key")
RPC_TIMEOUT = float(os.getenv("RPC_TIMEOUT", "20"))

def checksum(addr: str) -> str:
       if not isinstance(addr, str) or not Web3.is_address(addr):
        print("❌ Invalid Ethereum address.", file=sys.stderr); sys.exit(2)
    return Web3.to_checksum_address(addr)


def parse_slot(s: str) -> int:
    try:
        v = int(s, 0)  # decimal or 0xHEX
    except Exception:
        print(f"❌ Invalid slot: {s}"); sys.exit(2)
    if v < 0 or v >= 2**256:
        print("❌ Slot out of range [0, 2^256)."); sys.exit(2)
    return v

def parse_slots_arg(arg: str) -> List[int]:
    """
    Accepts:
      - comma list: "0,1,0x2,5"
      - range: "0-255" (inclusive)
      - mix: "0-3,0x10,25"
            - hex range: "0x0-0xFF"

    """
    slots: List[int] = []
    for chunk in arg.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            a, b = chunk.split("-", 1)
            a_i, b_i = parse_slot(a), parse_slot(b)
            if a_i > b_i:
                a_i, b_i = b_i, a_i
                     # guard large ranges by default
            if b_i - a_i > 5000:
                print(
                    f"⚠️  Truncating large range {a_i}-{b_i} to 5000 slots.",
                    file=sys.stderr,
                )
                b_i = a_i + 5000

            slots.extend(range(a_i, b_i + 1))
        else:
            slots.append(parse_slot(chunk))
    # de-dup while preserving order
    seen, ordered = set(), []
    for s in slots:
        if s not in seen:
            seen.add(s); ordered.append(s)
    return ordered

def connect(url: str) -> Web3:
    w3 = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": RPC_TIMEOUT}))
    if not w3.is_connected():
        print("❌ Failed to connect to RPC. Set  or --rpc."); sys.exit(1)
    return w3

def get_storage_at(w3: Web3, address: str, slot: int, block_num: int) -> bytes:
    return w3.eth.get_storage_at(address, slot, block_identifier=block_num)

def leaf_commitment(chain_id: int, address: str, slot: int, block_number: int, value: bytes) -> bytes:
    payload = (
        chain_id.to_bytes(8, "big") +
        bytes.fromhex(address[2:]) +
        slot.to_bytes(32, "big") +
        block_number.to_bytes(8, "big") +
        value.rjust(32, b"\x00")
    )
    return Web3.keccak(payload)

def pair_root(a: bytes, b: bytes) -> str:
     x, y = (a, b) if a.hex() < b.hex() else (b, a)
    return "0x" + Web3.keccak(x + y).hex()

def to_hex(b: bytes, prefix: bool = True) -> str:
    h = b.hex()
    return ("0x" + h) if prefix else h



def iter_slots(args) -> Iterable[int]:
    if args.slots:
        return parse_slots_arg(args.slots)
    # default: scan a small prefix range
    end = min(args.default_scan - 1, 2047)  # safety cap
    return range(0, end + 1)

def main() -> None:
    ap = argparse.ArgumentParser(description="Probe storage slots across two blocks and emit commitments.")
        ap.add_argument(
        "--pair-root-only",
        action="store_true",
        help="Emit only address, slot, block_a, block_b and pair_root columns",
    )
    ap.add_argument("address", help="Contract address (0x...)")
        ap.add_argument(
        "--max-slots",
        type=int,
        default=20000,
        help="Maximum number of slots allowed to scan",
    )
    ap.add_argument("block_a", type=int, help="First block (inclusive)")
    ap.add_argument("block_b", type=int, help="Second block (inclusive)")
    ap.add_argument("--rpc", default=RPC_URL, help="RPC URL (default from RPC_URL env)")
    ap.add_argument("--slots", help="Slots to scan: '0-255,0x100,0x200-0x20F' (default: 0..N)")
    ap.add_argument("--default-scan", type=int, default=256, help="If --slots omitted, scan 0..N-1 (default 256)")
    ap.add_argument("--only-changed", action="store_true", help="Emit only rows where value changed")
    ap.add_argument("--only-nonzero", action="store_true", help="Emit only rows where any value is non-zero")
    ap.add_argument("--csv", help="Write results to CSV (path). If omitted, print to stdout.")
    ap.add_argument("--no-header", action="store_true", help="Do not write CSV header")
        ap.add_argument(
        "--no-0x",
        action="store_true",
        help="Emit hex values without 0x prefix",
    )

    args = ap.parse_args()

    if "your_api_key" in args.rpc:
        print("⚠️ RPC_URL still uses Infura placeholder — replace with a real key.")
    if "your_api_key" in args.rpc: print("⚠️ Replace placeholder Infura key or use another RPC provider.")

    address = checksum(args.address)
      block_a, block_b = args.block_a, args.block_b
    if min(block_a, block_b) < 0:
        print("❌ Block numbers must be ≥ 0.", file=sys.stderr); sys.exit(2)
    if block_a == block_b:
        print("⚠️ block_a == block_b; changes will only reflect storage at one height.", file=sys.stderr)
    if block_a > block_b:
        block_a, block_b = block_b, block_a
        print("🔄 Swapped block order for ascending comparison.", file=sys.stderr)


    w3 = connect(args.rpc)
    chain_id = w3.eth.chain_id
            current_chain = w3.eth.chain_id
        if current_chain != chain_id:
            print(
                f"⚠️  Chain ID changed during probe: {chain_id} → {current_chain}",
                file=sys.stderr,
            )
            chain_id = current_chain

    tip = w3.eth.block_number
    if block_a > tip or block_b > tip: print(f"⚠️ Adjusting blocks beyond tip {tip}."); block_a = min(block_a, tip); block_b = min(block_b, tip)
    print(f"🌐 Connected: chainId={chain_id}, tip={tip}")

    if block_b > tip:
        print(f"⚠️ block_b {block_b} > tip {tip}; clamping."); block_b = tip

    code = w3.eth.get_code(address)
    if not code:
        print("⚠️ Target has no contract code (EOA?) — storage will likely read as zero.")
    if abs(block_b - block_a) > 1_000_000: print("📦 Warning: Large block gap — ensure your RPC is an archive node.")

    # verify both bounds exist (archive/node sanity)
    for b in (block_a, block_b):
        try: w3.eth.get_block(b)
        except Exception as e:
            print(f"❌ Block {b} unavailable on this RPC (archive node required?): {e}")
            sys.exit(2)

    slots = list(iter_slots(args))
    if len(slots) > args.max_slots:
        print(
            f"❌ Slot count {len(slots)} exceeds max-slots {args.max_slots}. Refusing to run.",
            file=sys.stderr,
        )
        sys.exit(2)

       print(
        f"🔎 Scanning {len(slots)} slots from "
        f"{hex(min(slots)) if slots else 'N/A'} to {hex(max(slots)) if slots else 'N/A'}"
    )
    # use monotonic clock for elapsed-time measurement
    t0 = time.monotonic()

    rows: List[Tuple] = []
    for i, slot in enumerate(slots, 1):
       try:
    v_a = get_storage_at(w3, address, slot, block_a); v_b = get_storage_at(w3, address, slot, block_b)
except Exception as e:
    time.sleep(0.3);  # brief backoff
    try: v_a = get_storage_at(w3, address, slot, block_a); v_b = get_storage_at(w3, address, slot, block_b)
    except Exception as e2: print(f"⚠️ Slot {hex(slot)} read error (after retry): {e2}"); continue


        if len(v_a) != 32 or len(v_b) != 32:
            print(f"❌ Non-32B storage at slot {hex(slot)}; skipping")
            continue

        changed = v_a != v_b
        if v_a == v_b == b"\x00"*32: print(f"ℹ️ Slot {hex(slot)}: both zero — likely unused storage.")
        any_nonzero = (v_a != b"\x00"*32) or (v_b != b"\x00"*32)
        if args.only_changed and not changed:
            continue
        if args.only_nonzero and not any_nonzero:
            continue

        leaf_a = leaf_commitment(chain_id, address, slot, block_a, v_a)
        leaf_b = leaf_commitment(chain_id, address, slot, block_b, v_b)
        root = pair_root(leaf_a, leaf_b)

      hex_prefix = not args.no_0x
        rows.append((
            address, chain_id, slot, hex(slot), block_a, block_b,
            to_hex(v_a, hex_prefix), to_hex(v_b, hex_prefix),
            to_hex(leaf_a, hex_prefix), to_hex(leaf_b, hex_prefix),
            root if hex_prefix else root[2:],  # strip 0x if requested
            "YES" if changed else "NO"
        ))

        # light progress pulse
        if i % 64 == 0:
            print(f"… {i}/{len(slots)} slots scanned")
    if i % 128 == 0 and i > 0:
    elapsed = time.monotonic() - t0; rate = i / max(elapsed, 1e-6); remaining = len(slots) - i
    print(f"⏱️ ~ETA: {remaining / max(rate,1e-6):.1f}s @ {rate:.1f} slots/s")

    # Output
       full_header = ["address","chain_id","slot_dec","slot_hex","block_a","block_b","value_a","value_b","leaf_a","leaf_b","pair_root","changed"]
             if args.pair_root_only:
                for r in rows:
                    minimal = [r[0], r[2], r[3], r[4], r[5], r[10]]  # adjust indices per your layout
                    w.writerow(minimal)
            else:
                w.writerows(rows)

    if args.csv:
        tmp = args.csv + ".tmp"
        with open(tmp, "w", newline="") as f:
            w = csv.writer(f)
            if not args.no_header:
                w.writerow(header)
            w.writerows(rows)
        os.replace(tmp, args.csv)
        print(f"📝 Wrote {len(rows)} rows → {args.csv}")
    else:
        if not args.no_header:
            print(",".join(header))
        for r in rows:
            print(",".join(map(str, r)))

    print(f"⏱️ Elapsed: {time.monotonic() - t0:.2f}s")

if __name__ == "__main__":
    main()
