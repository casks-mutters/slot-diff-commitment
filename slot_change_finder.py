# Find the earliest block where a storage slot changes between two block bounds (binary search).
import os
import sys
import time
import argparse
from functools import lru_cache
from web3 import Web3

RPC_URL = os.getenv("RPC_URL", "https://mainnet.infura.io/v3/your_api_key")

def parse_slot(s: str) -> int:
    return int(s, 0)  # accepts "5" or "0x5"

def checksum(addr: str) -> str:
    if not Web3.is_address(addr):
        print("❌ Invalid Ethereum address."); sys.exit(2)
    return Web3.to_checksum_address(addr)

def connect(url: str) -> Web3:
    w3 = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": 30}))
    if not w3.is_connected():
        print("❌ Failed to connect to RPC. Check RPC_URL."); sys.exit(1)
    return w3

@lru_cache(maxsize=8192)
def storage_at(w3_provider_uri: str, address: str, slot: int, block_number: int) -> bytes:
    # cache key uses provider URI string via decorator arg; w3 constructed per call to avoid unhashable
    w3 = Web3(Web3.HTTPProvider(w3_provider_uri, request_kwargs={"timeout": 30}))
    return w3.eth.get_storage_at(address, slot, block_identifier=block_number)

def leaf_commitment(chain_id: int, address: str, slot: int, block_number: int, value: bytes) -> bytes:
    payload = (
        chain_id.to_bytes(8, "big")
        + bytes.fromhex(address[2:])
        + slot.to_bytes(32, "big")
        + block_number.to_bytes(8, "big")
        + value.rjust(32, b"\x00")
    )
    return Web3.keccak(payload)

def pair_root(a: bytes, b: bytes) -> str:
    x, y = (a, b) if a < b else (b, a)
    return "0x" + Web3.keccak(x + y).hex()

def fmt_ts(ts: int) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(ts))

def find_first_change(w3: Web3, addr: str, slot: int, lo: int, hi: int) -> int | None:
    """
    Assumes piecewise-constant storage; returns the earliest block in (lo, hi] where value != value_at(lo).
    Binary-search boundary; O(log N) storage reads.
    """
    if lo >= hi:
        return None
    try:
        base = storage_at(str(w3.provider.endpoint_uri), addr, slot, lo)
    except Exception as e:
        print(f"❌ Failed reading base value at block {lo}: {e}"); sys.exit(2)

    # If end equals base too — no change in range
    try:
        endv = storage_at(str(w3.provider.endpoint_uri), addr, slot, hi)
    except Exception as e:
        print(f"❌ Failed reading end value at block {hi}: {e}"); sys.exit(2)
    if endv == base:
        return None

    left, right = lo, hi
    while right - left > 1:
        mid = (left + right) // 2
        vmid = storage_at(str(w3.provider.endpoint_uri), addr, slot, mid)
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
    ap.add_argument("slot", help="Storage slot (decimal or hex, e.g. 5 or 0x5)")
    ap.add_argument("start_block", type=int, help="Lower bound block (inclusive baseline)")
    ap.add_argument("end_block", type=int, help="Upper bound block (inclusive search end)")
    ap.add_argument("--rpc", default=RPC_URL, help="RPC URL (default: RPC_URL env or Infura placeholder)")
    args = ap.parse_args()

    address = checksum(args.address)
    slot = parse_slot(args.slot)
    if slot < 0 or slot >= 2**256:
        print("❌ Slot out of range [0, 2^256)."); sys.exit(2)

    lo, hi = args.start_block, args.end_block
    if lo > hi:
        lo, hi = hi, lo
        print("🔄 Swapped block order for ascending search.")

    w3 = connect(args.rpc)
    chain_id = w3.eth.chain_id
    tip = w3.eth.block_number
    print(f"🌐 Connected (chainId {chain_id}, tip {tip})")

    if hi > tip:
        print(f"⚠️ Upper bound {hi} exceeds tip {tip}; clamping to tip.")
        hi = tip
    if lo < 0:
        print("❌ start_block must be ≥ 0."); sys.exit(2)

    code = w3.eth.get_code(address)
    if not code:
        print("⚠️ Target has no contract code — likely an EOA.")

    t0 = time.time()
    first_change = find_first_change(w3, address, slot, lo, hi)

    base_val = storage_at(str(w3.provider.endpoint_uri), address, slot, lo)
    end_val  = storage_at(str(w3.provider.endpoint_uri), address, slot, hi)

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
        print(f"🌳 Pair root (base,change): {root12}")
        print(f"🌳 Pair root (change,end): {root23}")

    print(f"\n⏱️ Elapsed: {time.time() - t0:.2f}s")

if __name__ == "__main__":
    main()
