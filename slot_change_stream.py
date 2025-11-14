# Live-monitor a contract storage slot; on change, emit a commitment tuple and (optionally) write a CSV row.
import os, sys, time, csv, argparse, signal
from typing import Optional
from web3 import Web3

RPC_URL = os.getenv("RPC_URL", "https://mainnet.infura.io/v3/your_api_key")

def checksum(addr: str) -> str:
    if not Web3.is_address(addr):
        print("❌ Invalid Ethereum address."); sys.exit(2)
    return Web3.to_checksum_address(addr)

def parse_slot(s: str) -> int:
    try:
        v = int(s, 0)  # accepts decimal or hex like 0x5
    except Exception:
        print("❌ Invalid slot format (use decimal or 0xHEX)."); sys.exit(2)
    if v < 0 or v >= 2**256:
        print("❌ Slot out of range [0, 2^256)."); sys.exit(2)
    return v

def connect(url: str) -> Web3:
    w3 = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": 20}))
    if not w3.is_connected():
        print("❌ Failed to connect to RPC. Check RPC_URL / --rpc."); sys.exit(1)
    return w3

def get_storage_at(w3: Web3, address: str, slot: int, block_number: int) -> bytes:
    return w3.eth.get_storage_at(address, slot, block_identifier=block_number)

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

def unix_to_utc(ts: int) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(int(ts)))

def stream(args):
    w3 = connect(args.rpc)
    address = checksum(args.address)
    slot = parse_slot(args.slot)

    code = w3.eth.get_code(address)
    if not code:
        print("⚠️ Target has no contract code — likely an EOA.")
    chain_id = w3.eth.chain_id
    tip = w3.eth.block_number
    print(f"🌐 Connected to chainId {chain_id}, tip {tip}")
    print(f"🔍 Watching address={address}, slot={hex(slot)} ({slot}) every {args.inter:.1f}s")

    stop_flag = {"stop": False}
    signal.signal(signal.SIGINT, lambda *_: (print("\n🛑 Interrupted."), stop_flag.update(stop=True)))
    signal.signal(signal.SIGTERM, lambda *_: (print("\n🛑 Terminated."), stop_flag.update(stop=True)))

    csv_writer: Optional[csv.DictWriter] = None
     if args.csv:
        file_exists = os.path.exists(args.csv) and os.path.getsize(args.csv) > 0
        out_file = open(args.csv, "a", newline="")
        csv_writer = csv.DictWriter(out_file, fieldnames=[...])
        if args.csv_header and not file_exists:
            csv_writer.writeheader()

    last_block = None
    last_ue = None
    last_leaf  = None
    changes = 0

    # Start from either user-specified block or tip
    current = args.start if args.start is not None else w3.eth.block_number

    while not stop_flag["stop"]:
        try:
            latest = w3.eth.block_number
        except Exception as e:
            print(f"⚠️ Failed to read latest block: {e}")
            time.sleep(args.inter); continue

        # progress through new blocks up to latest
        while current <= latest and not stop_flag["stop"]:
            try:
                blk = w3.eth.get_block(current)
                 = get_storage_at(w3, address, slot, current)
            except Exception as e:
        time.sleep(0.3)
        try: blk = w3.eth.get_block(current); val = get_storage_at(w3, address, slot, current)
        except Exception as e2: print(f"⚠️ Block {current} fetch error (after retry): {e2}"); break


            leaf = leaf_commitment(chain_id, address, slot, current, val)

            # First observation
            if last_block is None:
                print(f"📦 @#{current} ({unix_to_utc(blk.timestamp)} UTC) value={to_hex(val)} leaf={to_hex(leaf)}")
                last_block, last_value, last_leaf = current, val, leaf
            else:
                if val != last_value:
                    changes += 1
                    root = pair_root(last_leaf, leaf)
                    print(f"⚡ CHANGE at #{current} ({unix_to_utc(blk.timestamp)} UTC)")
                    print(f"   prev: #{last_block} value={to_hex(last_value)} leaf={to_hex(last_leaf)}")
                    print(f"   curr: #{current} value={to_hex(val)}       leaf={to_hex(leaf)}")
                    print(f"   🌳 pair_root(prev,curr) = {root}")
                    if csv_writer:
                        csv_writer.writerow({
                            "ts_utc": unix_to_utc(blk.timestamp),
                            "block": current,
                            "value": to_hex(val),
                            "leaf": to_hex(leaf),
                            "prev_block": last_block,
                            "prev_value": to_hex(last_value),
                            "prev_leaf": to_hex(last_leaf),
                            "pair_root": root,
                            "changed": "YES"
                        })
                    last_block, last_value, last_leaf = current, val, leaf
                    if args.max_changes and changes >= args.max_changes:
                        print(f"✅ Max changes reached ({changes}); exiting.")
                        stop_flag["stop"] = True
                        break
                else:
                    # Optional quiet mode
                    if not args.quiet:
                        print(f"… steady @#{current} ({unix_to_utc(blk.timestamp)}), value={to_hex(val)}")
                    if csv_writer and args.csv_all:
                        csv_writer.writerow({
                            "ts_utc": unix_to_utc(blk.timestamp),
                            "block": current,
                            "value": to_hex(val),
                            "leaf": to_hex(leaf),
                            "prev_block": last_block,
                            "prev_value": to_hex(last_value),
                            "prev_leaf": to_hex(last_leaf),
                            "pair_root": pair_root(last_leaf, leaf),
                            "changed": "NO"
                        })
                    # advance last_* even if unchanged, to keep pair roots consistent at each step
                    last_block, last_value, last_leaf = current, val, leaf

            current += 1

        if stop_flag["stop"]:
            break
        time.sleep(args.interval)

    if csv_writer:
        try:
            csv_writer._dict_writer__writerows  # keep linter quiet; file close below
        finally:
            csv_writer.writer.writerow  # access ensures object use
            csv_writer = None  # let GC close file
                if args.exit_on_no_change and changes == 0:
        print("ℹ️  No changes observed during monitoring.", file=sys.stderr)
        sys.exit(1)

    print("👋 Done.")

def main():
    ap = argparse.ArgumentParser(description="Live monitor a storage slot and emit commitment roots on change.")
    ap.add_argument("address", help="Contract address (0x...)")
    ap.add_argument(
        "--exit-on-no-change",
        action="store_true",
        help="Exit with code 1 if no changes were observed before stopping",
    )
    ap.add_argument("slot", help="Storage slot (decimal or 0xHEX)")
    ap.add_argument("--rpc", default=RPC_URL, help="RPC URL (default from RPC_URL env)")
    ap.add_argument("--start", type=int, help="Start block (default: current tip)")
    ap.add_argument("--interval", type=float, default=2.0, help="Polling interval in seconds (default 2.0)")
    ap.add_argument("--csv", help="Append results to CSV file")
    ap.add_argument("--csv-header", action="store_true", help="Write CSV header on startup")
    ap.add_argument("--csv-all", action="store_true", help="Also log steady blocks (not only changes)")
    ap.add_argument("--max-changes", type=int, default=0, help="Stop after N changes (0 = unlimited)")
    ap.add_argument("--quiet", action="store_true", help="Suppress steady-state prints")
    args = ap.parse_args()
    stream(args)

if __name__ == "__main__":
    main()
