import unittest
from attestation_tool import leaf_commitment, pair_root

class TestAttestationFunctions(unittest.TestCase):
    
    def test_leaf_commitment(self):
        # Example values for testing
        chain_id = 1
        address = "0xYourContractAddress"
        slot = 123456
        block_number = 1000
        value = bytes.fromhex("0x" + "00" * 32)  # Example empty value
        leaf = leaf_commitment(chain_id, address, slot, block_number, value)
        self.assertEqual(len(leaf), 32)

    def test_pair_root(self):
        leaf_a = bytes.fromhex("0x" + "00" * 32)
        leaf_b = bytes.fromhex("0x" + "01" * 32)
        root = pair_root(leaf_a, leaf_b)
        self.assertEqual(len(root), 66)  # Hex string of 32 bytes + 32 bytes
