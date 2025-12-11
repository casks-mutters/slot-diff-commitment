from urllib.parse import urlparse

# RPC validation
if not urlparse(args.rpc).scheme:
    print("❌ Invalid RPC URL format.", file=sys.stderr)
    sys.exit(2)

# Private key validation
if args.sign and (len(pk) != 64 or not all(c in "0123456789abcdef" for c in pk.lower())):
    print("❌ Invalid PRIVATE_KEY format. Should be 64 hexadecimal characters.", file=sys.stderr)
    sys.exit(2)
