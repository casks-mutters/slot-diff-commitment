# slot-diff-commitment

## Overview
A tiny Web3 tool that checks the soundness of a specific contract storage slot across two block heights. It fetches the storage value at block A and block B, computes Keccak commitments (leaves) that bind (chainId, address, slot, blockNumber, value), and then produces a deterministic pair commitment (a Merkle-style root over the two leaves). This mirrors the commitment patterns used in ZK/rollup systems (e.g., Aztec-like designs) where small roots capture larger facts; verifiers can later request the corresponding leaves to validate statements about history or equality.

## Files
- app.py — CLI tool to read a storage slot at two blocks and emit a pair commitment.
- README.md — this document.

## Requirements
- Python 3.10+
- web3.py
- An Ethereum-compatible RPC endpoint (Infura, Alchemy, or your own node)

## Install
1) Install the dependency: pip install web3
2) Configure RPC: set environment variable RPC_URL or edit the constant in app.py

## Usage
python app.py <contract_address> <slot(hex|int)> <block_a> <block_b>
Example: python app.py 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 0x0 18000000 19000000

## What it prints
- Network name and chain ID
- Address and slot (hex and decimal)
- For each block (A and B): the storage value and its per-block leaf commitment
- A deterministic pair commitment (root) over the two leaves
- Whether the storage value changed between the two blocks
- Elapsed time

## How it relates to soundness and ZK
- Soundness: Once the commitment is published, any mismatch or tampering is detectable because the leaves recompute to the same root only if the facts match.
- ZK-ready: These leaves can be inputs to a circuit so a prover can show “the value remained the same” (or changed) between two blocks without revealing the raw values in certain designs.

## Notes
- Works with any EVM network supported by your RPC. Set RPC_URL to point at Mainnet, Sepolia, Polygon, Optimism, Arbitrum, etc.
- For historical blocks some providers require archival access; errors or missing data may occur otherwise.
- Slots are integers; you may pass decimal like 5 or hex like 0x5. The tool right-pads values to 32 bytes when building commitments.
- The pair commitment uses keccak(sorted(leafA, leafB)) for determinism regardless of leaf order.
- This is a conceptual demo; it does not generate zk proofs. It focuses on commitments that are easy to verify and compare.
- To extend: accept multiple slots and build a larger Merkle tree, or export JSON for downstream verifiers.
