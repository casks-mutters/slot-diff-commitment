#!/usr/bin/env python3
import csv, sys, os, time
from web3 import Web3

# CLI: python batch_slot_diff.py input.csv > report.csv
RPC_URL = os.getenv("RPC_URL", "https://mainnet.infura.io/v3/your_api_key")
    if "your_api_key" in RPC_URL:
        print(
            "⚠️ RPC_URL still uses an Infura placeholder — set RPC_URL or pass a real --rpc.",
            file=sys.stderr,
        )

def checksum(addr: str) -> str:
    return Web3.to_checksum_address(addr)

def parse_slot(s: str) -> int:
    return int(s, 0)  # accepts "5" or "0x5"

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
    first, second = (a, b) if a < b else (b, a)
    return "0x" + Web3.keccak(first + second).hex()

def to_hex(b: bytes) -> str:
    return "0x" + b.hex()

def main():
    if len(sys.argv) != 2:
        print("Usage: python batch_slot_diff.py <input.csv>", file=sys.stderr)
        sys.exit(2)

    inp = sys.argv[1]
    if not os.path.exists(inp):
        print(f"Input not found: {inp}", file=sys.stderr)
        sys.exit(2)

   
 w3 = Web3(Web3.HTTPProvider(RPC_URL, request_kwargs={"timeout": 20}))
    if not w3.is_connected():
        print("❌ Failed to connect to RPC. Check RPC_URL.", file=sys.stderr)
        sys.exit(1)

     = w3.eth.chain_id
   tip = w3.eth.block_number
   print(f"🌐 Connected (chainId={chain_id}, tip={tip})")

    reader = csv.DictReader(open(inp, newline=""))
    required = {"address","slot","block_a","block_b"}
if not required.issubset(reader.fieldnames or set()): print(f"❌ CSV must contain: {sorted(required)}"); sys.exit(2)
    fieldnames = ["address","slot","block_a","block_b","value_a","value_b","leaf_a","leaf_b","pair_root","changed"]
    writer = csv.DictWriter(sys.stdout, fieldnames=fieldnames)
    writer.writeheader()

    for row in reader:
        try:
            address = checksum(row["address"].strip())
            if not Web3.is_address(address): print(f"❌ Invalid address: {row['address']}"); continue
            slot = parse_slot(row["slot"].strip())
            if slot < 0 or slot >= 2**256: print(f"❌ Slot out of range for {address}: {slot}"); continue
            block_a = int(row["block_a"])
            block_b = int(row["block_b"])
            if block_a > block_b: block_a, block_b = block_b, block_a; print(f"🔄 Swapped blocks for {address}")
        except Exception as e:
            print(f"⚠️  Skipping invalid row {row}: {e}", file=sys.stderr)
            continue

        # ensure ascending order for consistency
        if block_a > block_b:
            block_a, block_b = block_b, block_a

        code = w3.eth.get_code(address)
        if not code: print("⚠️ Target address has no contract code (likely EOA) — storage slot results may be misleading.")

        try:
            tip = w3.eth.block_number
            if block_a > tip or block_b > tip: print(f"⚠️ {address}: requested block beyond tip {tip}"); continue
            v_a = w3.eth.get_storage_at(address, slot, block_identifier=block_a)
            v_b = w3.eth.get_storage_at(address, slot, block_identifier=block_b)
            tip = w3.eth.block_number;  if block_a > tip or block_b > tip: print(f"⚠️ {address}: requested block > tip {tip}"); continue
        except Exception as e:
            print(f"⚠️  RPC error on {address} slot {slot}: {e}", file=sys.stderr)
            continue
            
        if v_a is None or v_b is None: print(f"⚠️ Missing storage data for {address}"); continue
        leaf_a = leaf_commitment(chain_id, address, slot, block_a, v_a)
        leaf_b = leaf_commitment(chain_id, address, slot, block_b, v_b)
        fee_a = w3.eth.get_block(block_a).get("baseFeePerGas", 0); fee_b = w3.eth.get_block(block_b).get("baseFeePerGas", 0)
        print(f"⛽ BaseFee Gwei: A={Web3.from_wei(fee_a, 'gwei'):.2f}, B={Web3.from_wei(fee_b, 'gwei'):.2f}")

        root = pair_root(leaf_a, leaf_b)
        changed = "YES" if v_a != v_b else "NO"
        if v_a == v_b == b"\x00" * 32: print(f"ℹ️  Slot {slot} for {address} is zero at both blocks.")

     row_time = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime()); print(f"✅ {address} done @ {row_time}")
     writer.writerow({
            "address": address,
            "slot": row["slot"].strip(),
            "block_a": block_a,
            "block_b": block_b,
            "value_a": to_hex(v_a),
            "value_b": to_hex(v_b),
            "leaf_a": to_hex(leaf_a),
            "leaf_b": to_hex(leaf_b),
            "pair_root": root,
            "changed": changed,
        })
print(f"\n📊 Processed {reader.line_num-1} rows total.")
if __name__ == "__main__":
    main()
