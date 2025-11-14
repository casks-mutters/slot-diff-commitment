# Produce a signed JSON attestation (optional) for a storage slot across two blocks:
# includes slot values, two leaf commitments, and the pair root.
import os, sys, json, time, argparse
from dataclasses import asdict, dataclass
from typing import Optional
from web3 import Web3

try:
    from eth_account import Account
    from eth_account.messages import encode_defunct
except Exception:
    Account = None  # signing remains optional

RPC_URL = os.getenv("RPC_URL", "https://mainnet.infura.io/v3/your_api_key")
DEFAULT_OUT = "slot_diff_attestation.json"

@dataclass
class Attestation:
    address: str
    slot_hex: str
    slot_dec: int
    chain_id: int
    block_a: int
    block_b: int
    value_a: str
    value_b: str
    leaf_a: str
    leaf_b: str
    pair_root: str
    changed: bool
    timestamp_utc: str
    rpc_url: str
    signer_address: Optional[str] = None
    signature: Optional[str] = None
    note: Optional[str] = None

def checksum(addr: str) -> str:
    if not Web3.is_address(addr):
        print("❌ Invalid Ethereum address."); sys.exit(2)
    return Web3.to_checksum_address(addr)

def parse_slot(s: str) -> int:
    try:
        v = int(s, 0)  # decimal or 0xHEX
    except Exception:
        print("❌ Invalid slot format (use decimal or 0xHEX)."); sys.exit(2)
    if v < 0 or v >= 2**256:
        print("❌ Slot out of range [0, 2^256)."); sys.exit(2)
    return v

def connect(url: str) -> Web3:
    w3 = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": 20}))
    if not w3.is_connected():
        print("❌ Failed to connect to RPC."); sys.exit(1)
    return w3

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

def to_hex(b: bytes) -> str:
    return "0x" + b.hex()

def now_utc() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())

def main():
    ap = argparse.ArgumentParser(description="Create (optionally sign) a JSON attestation for a storage slot across two blocks.")
    ap.add_argument("address", help="Contract address (0x...)")
        ap.add_argument(
        "--compact",
        action="store_true",
        help="Write compact JSON without indentation",
    )
    ap.add_argument("slot", help="Storage slot (decimal or 0xHEX)")
    ap.add_argument("block_a", type=int, help="First block (inclusive)")
    ap.add_argument("block_b", type=int, help="Second block (inclusive)")
    ap.add_argument("--rpc", default=RPC_URL, help="RPC URL (env RPC_URL)")
    ap.add_argument("--out", default=DEFAULT_OUT, help=f"Output JSON path (default: {DEFAULT_OUT})")
    ap.add_argument("--note", default="", help="Optional note embedded in attestation")
    ap.add_argument("--sign", action="store_true", help="Sign with PRIVATE_KEY (EIP-191 personal_sign)")
    args = ap.parse_args()

    address = checksum(args.address)
    slot = parse_slot(args.slot)
    block_a, block_b = args.block_a, args.block_b

    if min(block_a, block_b) < 0:
        print("❌ Block numbers must be ≥ 0."); sys.exit(2)
    if block_a > block_b:
        block_a, block_b = block_b, block_a
        print("🔄 Swapped block order for ascending comparison.")

    w3 = connect(args.rpc)
    chain_id = w3.eth.chain_id
    tip = w3.eth.block_number
    print(f"🌐 Connected chainId={chain_id}, tip={tip}")

    if block_b > tip:
        print(f"⚠️ block_b {block_b} > tip {tip}; clamping."); block_b = tip
    if not w3.eth.get_code(address):
        print("⚠️ Target has no contract code — likely an EOA (reads will be zero).")

    try:
        v_a = w3.eth.get_storage_at(address, slot, block_identifier=block_a)
        v_b = w3.eth.get_storage_at(address, slot, block_identifier=block_b)
    except Exception as e:
        print(f"❌ Storage read failed: {e}"); sys.exit(2)

    leaf_a = leaf_commitment(chain_id, address, slot, block_a, v_a)
    leaf_b = leaf_commitment(chain_id, address, slot, block_b, v_b)
    root  = pair_root(leaf_a, leaf_b)
    changed = v_a != v_b

    att = Attestation(
        address=address,
        slot_hex=hex(slot),
        slot_dec=slot,
        chain_id=chain_id,
        block_a=block_a,
        block_b=block_b,
        value_a=to_hex(v_a),
        value_b=to_hex(v_b),
        leaf_a=to_hex(leaf_a),
        leaf_b=to_hex(leaf_b),
        pair_root=root,
        changed=changed,
        timestamp_utc=now_utc(),
        rpc_url=args.rpc,
        note=args.note or None,
    )

    if args.sign:
        if Account is None:
            print("❌ Signing requires eth_account. Install web3[account] or eth-account."); sys.exit(2)
        pk = os.getenv("PRIVATE_KEY", "").strip()
        if not pk:
            print("❌ --sign requested but PRIVATE_KEY env var not set."); sys.exit(2)
        try:
            acct = Account.from_key(pk)
        except Exception as e:
            print(f"❌ Invalid PRIVATE_KEY: {e}"); sys.exit(2)

        # EIP-191 personal_sign over the keccak of canonical JSON
        payload = json.dumps(asdict(att), separators=(",", ":"), sort_keys=True).encode()
        msg = encode_defunct(primitive=Web3.keccak(payload))
        signed = Account.sign_message(msg, private_key=pk)
        att.signer_address = acct.address
        att.signature = signed.signature.hex()
        print(f"✍️  Signed by {acct.address}")

    with open(args.out, "w") as f:
               json.dump(
            asdict(att),
            f,
            indent=None if args.compact else 2,
            separators=(",", ":") if args.compact else None,
            sort_keys=True,
        )
    print(f"📝 Wrote attestation → {args.out}")
    print(f"🌳 Pair root: {root}")
    print(f"🔁 Changed: {'YES' if changed else 'NO'}")

if __name__ == "__main__":
    main()
