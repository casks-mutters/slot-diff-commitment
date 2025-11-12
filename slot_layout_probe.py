"""Utilities for probing/inspecting slot layouts.

Intentionally lightweight; importing this module has no side effects.
"""
# slot_layout_probe.py
# Probe a contract's storage layout: scan a set/range of slots at two blocks,
# report non-zero values and changes, and emit commitments + pair roots (CSV/STDOUT).

import os, sys, csv, time, argparse
from typing import Iterable, List, Tuple
from web3 import Web3

RPC_URL = os.getenv("RPC_URL", "https://mainnet.infura.io/v3/your_api_key")

def checksum(addr: str) -> str:
    if not Web3.is_address(addr):
        print("❌ Invalid Ethereum address."); sys.exit(2)
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
                print(f"⚠️  Truncating large range {a_i}-{b_i} to 5000 slots.")
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
    w3 = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": 20}))
    if not w3.is_connected():
        print("❌ Failed to connect to RPC. Set RPC_URL or --rpc."); sys.exit(1)
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
    x, y = (a, b) if a < b else (b, a)
    return "0x" + Web3.keccak(x + y).hex()

def to_hex(b: bytes) -> str:
    return "0x" + b.hex()

def iter_slots(args) -> Iterable[int]:
    if args.slots:
        return parse_slots_arg(args.slots)
    # default: scan a small prefix range
    end = min(args.default_scan - 1, 2047)  # safety cap
    return range(0, end + 1)

def main():
    ap = argparse.ArgumentParser(description="Probe storage slots across two blocks and emit commitments.")
    ap.add_argument("address", help="Contract address (0x...)")
    ap.add_argument("block_a", type=int, help="First block (inclusive)")
    ap.add_argument("block_b", type=int, help="Second block (inclusive)")
    ap.add_argument("--rpc", default=RPC_URL, help="RPC URL (default from RPC_URL env)")
    ap.add_argument("--slots", help="Slots to scan: '0-255,0x100,0x200-0x20F' (default: 0..N)")
    ap.add_argument("--default-scan", type=int, default=256, help="If --slots omitted, scan 0..N-1 (default 256)")
    ap.add_argument("--only-changed", action="store_true", help="Emit only rows where value changed")
    ap.add_argument("--only-nonzero", action="store_true", help="Emit only rows where any value is non-zero")
    ap.add_argument("--csv", help="Write results to CSV (path). If omitted, print to stdout.")
    ap.add_argument("--no-header", action="store_true", help="Do not write CSV header")
    args = ap.parse_args()

    if "your_api_key" in args.rpc:
        print("⚠️ RPC_URL still uses Infura placeholder — replace with a real key.")

    address = checksum(args.address)
    block_a, block_b = args.block_a, args.block_b
    if min(block_a, block_b) < 0:
        print("❌ Block numbers must be ≥ 0."); sys.exit(2)
    if block_a > block_b:
        block_a, block_b = block_b, block_a
        print("🔄 Swapped block order for ascending comparison.")

    w3 = connect(args.rpc)
    chain_id = w3.eth.chain_id
    tip = w3.eth.block_number
    print(f"🌐 Connected: chainId={chain_id}, tip={tip}")

    if block_b > tip:
        print(f"⚠️ block_b {block_b} > tip {tip}; clamping."); block_b = tip

    code = w3.eth.get_code(address)
    if not code:
        print("⚠️ Target has no contract code (EOA?) — storage will likely read as zero.")

    # verify both bounds exist (archive/node sanity)
    for b in (block_a, block_b):
        try: w3.eth.get_block(b)
        except Exception as e:
            print(f"❌ Block {b} unavailable on this RPC (archive node required?): {e}")
            sys.exit(2)

    slots = list(iter_slots(args))
    print(f"🔎 Scanning {len(slots)} slots from {hex(min(slots)) if slots else 'N/A'} to {hex(max(slots)) if slots else 'N/A'}")
    t0 = time.monotonic()

    rows: List[Tuple] = []
    for i, slot in enumerate(slots, 1):
        try:
            v_a = get_storage_at(w3, address, slot, block_a)
            v_b = get_storage_at(w3, address, slot, block_b)
        except Exception as e:
            print(f"⚠️ Slot {hex(slot)} read error: {e}")
            continue

        if len(v_a) != 32 or len(v_b) != 32:
            print(f"❌ Non-32B storage at slot {hex(slot)}; skipping")
            continue

        changed = v_a != v_b
        any_nonzero = (v_a != b"\x00"*32) or (v_b != b"\x00"*32)
        if args.only_changed and not changed:
            continue
        if args.only_nonzero and not any_nonzero:
            continue

        leaf_a = leaf_commitment(chain_id, address, slot, block_a, v_a)
        leaf_b = leaf_commitment(chain_id, address, slot, block_b, v_b)
        root = pair_root(leaf_a, leaf_b)

        rows.append((
            address, chain_id, slot, block_a, block_b,
            to_hex(v_a), to_hex(v_b), to_hex(leaf_a), to_hex(leaf_b), root,
            "YES" if changed else "NO"
        ))

        # light progress pulse
        if i % 64 == 0:
            print(f"… {i}/{len(slots)} slots scanned")

    # Output
    header = ["address","chain_id","slot_dec","block_a","block_b","value_a","value_b","leaf_a","leaf_b","pair_root","changed"]
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
