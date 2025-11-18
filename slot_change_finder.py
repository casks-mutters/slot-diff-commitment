# Find the earliest block where a storage slot changes between two block bounds (binary search).
"""Find the earliest block where a contract storage slot changes.

Performs a binary search between two block bounds, assuming the storage slot is
piecewise-constant over the range, and emits basic commitments over endpoints.
"""
import os
import sys
import time
import argparse
from functools import lru_cache
from web3 import Web3
import json
RPC_URL = os.getenv("RPC_URL", "https://mainnet.infura.io/v3/your_api_key")

def parse_slot(s: str) -> int:
    try:
        v = int(s, 0)  # accepts "5" or "0x5"
    except Exception:
        print(f"❌ Invalid slot format: {s!r} (use decimal or 0xHEX).", file=sys.stderr)
        sys.exit(2)
    if v < 0 or v >= 2**256:
        print("❌ Slot out of range [0, 2^256).", file=sys.stderr)
        sys.exit(2)
    return v


def checksum(addr: str) -> str:
     if not Web3.is_address(addr):
        print("❌ Invalid Ethereum address.", file=sys.stderr); sys.exit(2)
    return Web3.to_checksum_address(addr)

def connect(url: str) -> Web3:
    w3 = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": 30}))
      if not w3.is_connected():
        print("❌ Failed to connect to RPC. Check RPC_URL."); sys.exit(1)
    return w3

@lru_cache(maxsize=8192)
def storage_at(w3_provider_uri: str, address: str, slot: int, block_number: int) -> bytes:
    """
    Cached storage read with simple retry logic (3 attempts).
    Cache key uses the provider URI string plus address/slot/block.
    """
    w3 = Web3(Web3.HTTPProvider(w3_provider_uri, request_kwargs={"timeout": 30}))
    for _ in range(3):
        try:
            return w3.eth.get_storage_at(address, slot, block_identifier=block_number)
        except Exception:
            time.sleep(0.3)
    print(f"❌ RPC retries failed for block {block_number}.", file=sys.stderr)
    sys.exit(2)


def leaf_commitment(chain_id: int, address: str, slot: int, block_number: int, value: bytes) -> bytes:
    addr_hex = address[2:]
    if len(addr_hex) != 40:
        print(f"❌ Unexpected address length for {address}", file=sys.stderr)
        sys.exit(2)

    payload = (
        chain_id.to_bytes(8, "big")
        + bytes.fromhex(addr_hex)
        + slot.to_bytes(32, "big")
        + block_number.to_bytes(8, "big")
        + value.rjust(32, b"\x00")
    )
    return Web3.keccak(payload)

def pair_root(a: bytes, b: bytes) -> str:
    x, y = (a, b) if a.hex() < b.hex() else (b, a)
    return "0x" + Web3.keccak(x + y).hex()

def fmt_ts(ts: int) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(ts))

def find_first_change(w3: Web3, addr: str, slot: int, lo: int, hi: int) -> int | None:
      """
    Assumes piecewise-constant storage between blocks.

    Returns:
      - The earliest block in (lo, hi] where value != value_at(lo), or
      - None if no change in [lo, hi].

    Performs a binary search over the range, O(log N) storage reads.
    """

    if lo >= hi:
        return None
        try:
        base = storage_at(str(w3.provider.endpoint_uri), addr, slot, lo)
    except Exception as e:
        print(f"❌ Failed reading base value at block {lo}: {e}", file=sys.stderr)
        sys.exit(2)

    # If end equals base too — no change in range
     try:
        endv = storage_at(str(w3.provider.endpoint_uri), addr, slot, hi)
    except Exception as e:
        print(f"❌ Failed reading end value at block {hi}: {e}", file=sys.stderr)
        sys.exit(2)

    left, right = lo, hi
    max_iters = 512
    while right - left > 1 and (max_iters := max_iters - 1) > 0:
        mid = (left + right) // 2
             vmid = storage_at(str(w3.provider.endpoint_uri), addr, slot, mid)
        if mid in (lo, hi):
            print("❌ Inconsistent boundary read; possible reorg or unstable RPC data.", file=sys.stderr)
            sys.exit(2)
        if vmid == base:
            left = mid
        else:
            right = mid
    return right  # first block after 'left' with value != base

def main():
        ap = argparse.ArgumentParser(
        description="Find earliest storage slot change between two blocks (binary search).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    ap.add_argument("address", help="Contract address (0x...)")
        ap.add_argument(
        "--json",
        action="store_true",
        help="Also print a JSON summary to stdout",
    )
    ap.add_argument("slot", help="Storage slot (decimal or hex, e.g. 5 or 0x5)")
    ap.add_argument("start_block", type=int, help="Lower bound block (inclusive baseline)")
    ap.add_argument("end_block", type=int, help="Upper bound block (inclusive search end)")
    ap.add_argument("-r", "--rpc", default=RPC_URL, help="RPC URL (default: RPC_URL env or Infura placeholder)")
    args = ap.parse_args()

        address = checksum(args.address)
    if int(address, 16) == 0:
        print("❌ Zero address is not a valid contract target.", file=sys.stderr)
        sys.exit(2)
    slot = parse_slot(args.slot)
    if slot == 0: print("⚠️ Slot 0 may hold global variables — double-check if that’s intended.")
       if slot < 0 or slot >= 2**256:
        print("❌ Slot out of range [0, 2^256).", file=sys.stderr)
        sys.exit(2)

        lo, hi = args.start_block, args.end_block
    if lo > hi:
        lo, hi = hi, lo
        print("🔄 Swapped block order for ascending search.", file=sys.stderr)
    if lo == hi:
        print("ℹ️ start_block == end_block; nothing to search.", file=sys.stderr)
        sys.exit(0)
            
    w3 = connect(args.rpc)
    print(f"🔗 Using RPC endpoint: {args.rpc}")
    chain_id = w3.eth.chain_id
    tip = w3.eth.block_number
    print(f"🌐 Connected (chainId {chain_id}, tip {tip})")
    if hi > tip: print(f"⚠️ end_block {hi} > tip {tip}; clamping."); hi = tip

       if hi > tip:
        print(f"⚠️ Upper bound {hi} exceeds tip {tip}; clamping to tip.", file=sys.stderr)
        hi = tip
    if lo < 0:
        print("❌ start_block must be ≥ 0.", file=sys.stderr)
        sys.exit(2)


        code = w3.eth.get_code(address)
    if not code:
        print("❌ Target has no contract code (EOA).", file=sys.stderr)
        sys.exit(2)
   
    t0 = time.time()
    try: _ = storage_at(str(w3.provider.endpoint_uri), address, slot, lo)
    except Exception as e: print(f"❌ Cannot read baseline at {lo}: {e}"); sys.exit(2)
    first_change = find_first_change(w3, address, slot, lo, hi)

    base_val = storage_at(str(w3.provider.endpoint_uri), address, slot, lo)
    end_val  = storage_at(str(w3.provider.endpoint_uri), address, slot, hi)
    if len(base_val) != 32 or len(end_val) != 32: print("❌ Storage read not 32 bytes."); sys.exit(2)

    print("\n📦 Target")
    print(f"  Address: {address}")
    print(f"  Slot: {hex(slot)} ({slot})")

    print("\n🔢 Bounds")
    b_lo = w3.eth.get_block(lo)
    b_hi = w3.eth.get_block(hi)
    print(f"  Start: {lo}  ({fmt_ts(b_lo.timestamp)} UTC)")
    print(f"  End:   {hi}  ({fmt_ts(b_hi.timestamp)} UTC)")

    print("\n🔍 Values")
    print(f"  Value@{lo}:  0x{base_val.hex()}")
    print(f"  Value@{hi}:  0x{end_val.hex()}")

    if first_change is None:
        print("\n✅ No change detected in the range — storage is constant on (start..end].")
                print("ℹ️  No change boundary found in the given range.", file=sys.stderr)
        # Still emit a two-leaf root committing to endpoints for auditability
        leaf_a = leaf_commitment(chain_id, address, slot, lo, base_val)
        leaf_b = leaf_commitment(chain_id, address, slot, hi, end_val)
        print(f"🌳 Pair root (endpoints): {pair_root(leaf_a, leaf_b)}")
    else:
        v_chg = storage_at(str(w3.provider.endpoint_uri), address, slot, first_change)
        print(f"\n⚡ First change detected at block: {first_change} ({fmt_ts(w3.eth.get_block(first_change).timestamp)} UTC)")
        print(f"  Value@{first_change}:  0x{v_chg.hex()}")
        # Emit a commitment trio: baseline, boundary, end
        leaf_base = leaf_commitment(chain_id, address, slot, lo, base_val)
        leaf_edge = leaf_commitment(chain_id, address, slot, first_change, v_chg)
        leaf_end  = leaf_commitment(chain_id, address, slot, hi, end_val)
        root12 = pair_root(leaf_base, leaf_edge)
        root23 = pair_root(leaf_edge, leaf_end)
        print("🔐 Emitting pair roots that commit to (base, change) and (change, end).")
        print(f"🌳 Pair root (base,change): {root12}")
        print(f"🌳 Pair root (change,end): {root23}")
    if args.json:
        summary = {
            "address": address,
            "slot_dec": slot,
            "slot_hex": hex(slot),
            "chainId": int(chain_id),
            "startBlock": lo,
            "endBlock": hi,
            "firstChangeBlock": first_change,
            "baseValue": "0x" + base_val.hex(),
            "endValue": "0x" + end_val.hex(),
            "elapsedSec": round(time.monotonic() - t0, 3),
        }
        print(json.dumps(summary, sort_keys=True, indent=2))


    print(f"\n⏱️ Elapsed: {time.time() - t0:.2f}s")
    print(f"🕒 Report generated at {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())} UTC")
    
if __name__ == "__main__":
    main()
