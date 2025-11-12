# app.py
import os
import sys
import time
from web3 import Web3

# RPC configuration (override via environment: RPC_URL)
RPC_URL = os.getenv("RPC_URL", "https://mainnet.infura.io/v3/your_api_key")

NETWORKS = {
    1: "Ethereum Mainnet",
    11155111: "Sepolia Testnet",
    10: "Optimism",
    137: "Polygon",
    42161: "Arbitrum One",
}

def network_name(chain_id: int) -> str:
    return NETWORKS.get(chain_id, f"Unknown (chain ID {chain_id})")

def parse_slot(slot_str: str) -> int:
    # Accept decimal or hex (e.g., "5" or "0x5")
    return int(slot_str, 0)

def checksum(addr: str) -> str:
    return Web3.to_checksum_address(addr)

def connect(url: str) -> Web3:
    w3 = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": 30}))
    if not w3.is_connected():
        print("❌ Failed to connect to RPC. Check RPC_URL.")
        sys.exit(1)
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
    first, second = (a, b) if a < b else (b, a)
    return "0x" + Web3.keccak(first + second).hex()

def to_hex(b: bytes) -> str:
    return "0x" + b.hex()

def main():
    if len(sys.argv) != 5:
        print("Usage: python app.py <contract_address> <slot(hex|int)> <block_a> <block_b>")
        print("Example: python app.py 0xA0b8...eB48 0x0 18000000 19000000")
        sys.exit(1)

    address = checksum(sys.argv[1])
    slot = parse_slot(sys.argv[2])
    try:
        block_a = int(sys.argv[3])
        block_b = int(sys.argv[4])
    except ValueError:
        print("❌ block_a and block_b must be integers.")
        sys.exit(1)

    w3 = connect(RPC_URL)
    if not w3.eth.get_code(address): print("⚠️ Target has no contract code — likely an EOA, not a smart contract.")
    print(f"🌐 Connected to {network_name(w3.eth.chain_id)} (chainId {w3.eth.chain_id})")

    start = time.time()

    v_a = get_storage_at(w3, address, slot, block_a)
    v_b = get_storage_at(w3, address, slot, block_b)

    leaf_a = leaf_commitment(w3.eth.chain_id, address, slot, block_a, v_a)
    leaf_b = leaf_commitment(w3.eth.chain_id, address, slot, block_b, v_b)
    root = pair_root(leaf_a, leaf_b)

    changed = "YES" if v_a != v_b else "NO"

    print("\n📦 Target")
    print(f"  Address: {address}")
    print(f"  Slot: {hex(slot)} ({slot})")

    print("\n🔢 Observations")
    print(f"  Block A: {block_a}  Value: {to_hex(v_a)}  Leaf: {to_hex(leaf_a)}")
    print(f"  Block B: {block_b}  Value: {to_hex(v_b)}  Leaf: {to_hex(leaf_b)}")
    print(f"\n🌳 Pair commitment (Merkle-style root over two leaves): {root}")
    print(f"🔁 Value changed between blocks: {changed}")

    if v_a == v_b:
        print("✅ Soundness note: storage value is identical at both blocks; root binds the equality evidence.")
    else:
        print("ℹ️  Soundness note: values differ; root succinctly commits to both histories for independent verification.")

    print(f"\n⏱️  Elapsed: {time.time() - start:.2f}s")

if __name__ == "__main__":
    main()
