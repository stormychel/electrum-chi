from electrum import auxpow, blockchain, constants
from electrum.util import bfh, bh2u

from . import SequentialTestCase
from . import FAST_TESTS

# Xaya testnet block #63 is merge mined without an explicit MM header
# in the coinbase.
header_without_mm = "000000201ca9bca05ff37a8dfdbb402dd5d4167071dd6bbb6b40717e0c24ec00b8959e51bc454273fd23c69a007286b4f00c2a2c6b18c36f39d4cf23c78bb1a2cc6c6398f67e435b000000000000000081ffff031d02000000010000000000000000000000000000000000000000000000000000000000000000ffffffff2928567850635d4796668fb7320e8a240c3a34aa5ac8705182bea09cbf9d8eebf2d30100000000000000ffffffff00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000008ead030f4bb1e353d11cf20e465b143990063bca0a200421700f9b6e5bb22cf30000000000000000e5bb0000"
prev_hash_without_mm = "519e95b800ec240c7e71406bbb6bdd717016d4d52d40bbfd8d7af35fa0bca91c"
target_without_mm = blockchain.Blockchain.bits_to_target(0x1d03ffff)

# Xaya mainnet block #101,000 is merge-mined with an explicit MM header
# and non-trivial coinbase and chain merkle branches.
header_with_mm = "00000020cd3a2f096c83b363a907dd24d59438fe0a4f4fcc062ab36b46a4c276fa838194b237a64b5dd29c93d185c4127038d3cf2b606f8513344db9d9045d856b35b09f3b83785b000000000000000081e5f62e1801000000010000000000000000000000000000000000000000000000000000000000000000ffffffff64033c33082cfabe6d6d4ad528f778b623eeeee687a8a4c2bbb397a795b590cc49bc189cb194754a049f08000000f09f909f00144d696e6564206279206c696e66616e796f75646200000000000000000000000000000000000000000000000000000000001e61000003c28f404b000000001976a914c825a1ecf2a6830c4401620c3a16f1995057c2ab88ac00000000000000002f6a24aa21a9edfcf633f051f7a215671c67f024def8ee7f299c5719ca7dbeadd81eeb5db6bdcd08000000000000000000000000000000002c6a4c2952534b424c4f434b3ac8dd8200d478e91f34f987364d657f021ab3d9b7eaa0b86a9fd8dbc5f4958003a54a3e3a00000000000000000000000000000000000000000000000000000000000000000c094ba7af1a3113168b23066f8f6b45778460505669f977ba7f9108f1d458315cd955a774c4ac7d174ae3b31a6ee37c64a3f0401157dde6975445abb9b6f1baeeb96cf814ca30a8d25e07ceab0dfbd02a099b324c886a6c411d01f44bb86076b55439cdb5bd4cc11278edaa43c1a4eaecbbfcbb4475eddb1386644a4ffd74892fbf2c0a0fbb032870103d8dff714966ec588e0d9b1774fe89f506e3f0cb65fe26074c1da03e9b5dafb1dd658a128628df639731a0353471889b2ad6f63cde80f2fac85bac65fef992b1bf59287662954ab07e6de15bd6a5eb2b8470db197ca25266a4f8a2948db984abe3c5b816dcd02303659a16d992822262e948e3893aee487a0996ea92e8e8d8e4208487e1448c3fc10629aa2c0d2c20492852a55f7ad4e23ea71e2e51bfc4067792eeef9c9486b8b6b35cda347d040f67e27304b7bc44a6919b71bd7be6811ee8c96e559952c5bab3f3bad6e0207ba85d6abb06c9c46a677018189c9cddbc85c689589939000d9538f5b2cb8572d5017ed7ff083b35b40400000000030bd3078054f6234585a6a98299a6c3f80526c2122057956ffc6947e33cbbad2c77032806e674b9cc358f8a8f78759a4ca893c2c5500ccf28ebff54a47b40c2e51cdeb4b83c713eb2cca3e6872f3d66b4167e64f36bd01674d70fea5b3551cda5070000000000ff3f913d01444f14db2c6ab43ffd0f36af5613423815543c22000000000000000000ef6330ff500ba8a2eb0d2e988d3275057fcf81beb55e430e5cdf4a20dee82ad76c83785ba70d2c1728f397b0"
prev_hash_with_mm = "948183fa76c2a4466bb32a06cc4f4f0afe3894d524dd07a963b3836c092f3acd"
target_with_mm = blockchain.Blockchain.bits_to_target(0x182ef6e5)

class Test_auxpow(SequentialTestCase):

    @staticmethod
    def deserialize_with_auxpow(data_hex: str, **kwargs):
        """Deserializes a block header given as hex string

        This makes sure that the data is always deserialised as full
        block header with AuxPoW.

        The keyword-arguments expect_trailing_data and start_position can be
        set and will be passed on to deserialize_full_header."""

        # We pass a height beyond the last checkpoint, because
        # deserialize_full_header expects checkpointed headers to be truncated
        # by ElectrumX (i.e. not contain an AuxPoW).
        return blockchain.deserialize_full_header(bfh(data_hex), constants.net.max_checkpoint() + 1, **kwargs)

    @staticmethod
    def clear_coinbase_outputs(auxpow_header: dict, fix_merkle_root=True) -> None:
        """Clears the auxpow coinbase outputs

        Set the outputs of the auxpow coinbase to an empty list.  This is
        necessary when the coinbase has been modified and needs to be
        re-serialised, since present outputs are invalid due to the
        fast_tx_deserialize optimisation."""

        auxpow_header['parent_coinbase_tx']._outputs = []

        # Clear the cached raw serialization
        auxpow_header['parent_coinbase_tx'].raw = None
        auxpow_header['parent_coinbase_tx'].raw_bytes = None

        # Re-serialize.  Note that our AuxPoW library won't do this for us,
        # because it optimizes via fast_txid.
        auxpow_header['parent_coinbase_tx'].raw_bytes = bfh(auxpow_header['parent_coinbase_tx'].serialize_to_network(witness=False))

        # Correct the coinbase Merkle root.
        if fix_merkle_root:
            update_merkle_root_to_match_coinbase(auxpow_header)

    # Deserialize the AuxPoW header with explicit coinbase MM header.
    def test_deserialize_auxpow_header_explicit_coinbase(self):
        header = self.deserialize_with_auxpow(header_with_mm)
        header_auxpow = header['powdata']['auxpow']

        coinbase_tx = header_auxpow['parent_coinbase_tx']
        expected_coinbase_txid = 'e751249a0dfc33c119c2f3375054a8cfe18eacf8291da689cb8f4570afbdb1a3'
        observed_coinbase_txid = auxpow.fast_txid(coinbase_tx)

        self.assertEqual(expected_coinbase_txid, observed_coinbase_txid)

        self.assertEqual(header_auxpow['coinbase_merkle_branch'], [
            "5c3158d4f108917fba77f9695650608477456b8f6f06238b1613311aafa74b09",
            "eebaf1b6b9ab455497e6dd571140f0a3647ce36e1ab3e34a177dacc474a755d9",
            "b57660b84bf4011d416c6a884c329b092ad0fb0dabce075ed2a830ca14f86cb9",
            "2f8974fd4f4a648613dbed7544bbfcbbeceaa4c143aaed7812c14cbdb5cd3954",
            "26fe65cbf0e306f589fe74179b0d8e58ec664971ff8d3d10702803bb0f0a2cbf",
            "f280de3cf6d62a9b88713435a0319763df2886128a65ddb1af5d9b3ea01d4c07",
            "52a27c19db70842beba5d65be16d7eb04a9562762859bfb192f9fe65ac5bc8fa",
            "48ee3a89e348e962228292d9169a650323d0dc16b8c5e3ab84b98d94a2f8a466",
            "e2d47a5fa5522849202c0d2caa2906c13f8c44e1878420e4d8e8e892ea96097a",
            "a644bcb70473e2670f047d34da5cb3b6b886949cefee927706c4bf512e1ea73e",
            "676ac4c906bb6a5da87b20e0d6baf3b3bac55299556ec9e81e81e67bbd719b91",
            "04b4353b08ffd77e01d57285cbb2f538950d0039995889c685bcdd9c9c181870",
        ])

        coinbase_merkle_index = header_auxpow['coinbase_merkle_index']
        self.assertEqual(0, coinbase_merkle_index)

        self.assertEqual(header_auxpow['chain_merkle_branch'], [
            "2cadbb3ce34769fc6f95572012c22605f8c3a69982a9a6854523f6548007d30b",
            "e5c2407ba454ffeb28cf0c50c5c293a84c9a75788f8a8f35ccb974e606280377",
            "a5cd51355bea0fd77416d06bf3647e16b4663d2f87e6a3ccb23e713cb8b4de1c",
        ])

        chain_merkle_index = header_auxpow['chain_merkle_index']
        self.assertEqual(7, chain_merkle_index)

        expected_parent_header = blockchain.deserialize_pure_header(bfh('0000ff3f913d01444f14db2c6ab43ffd0f36af5613423815543c22000000000000000000ef6330ff500ba8a2eb0d2e988d3275057fcf81beb55e430e5cdf4a20dee82ad76c83785ba70d2c1728f397b0'), None)

        expected_parent_hash = blockchain.hash_header(expected_parent_header)
        observed_parent_hash = blockchain.hash_header(header_auxpow['parent_header'])
        self.assertEqual(expected_parent_hash, observed_parent_hash)

        expected_parent_merkle_root = expected_parent_header['merkle_root']
        observed_parent_merkle_root = header_auxpow['parent_header']['merkle_root']
        self.assertEqual(expected_parent_merkle_root, observed_parent_merkle_root)

    def test_deserialize_should_reject_trailing_junk(self):
        with self.assertRaises(Exception):
            self.deserialize_with_auxpow(header_with_mm + "00")

    def test_deserialize_with_expected_trailing_data(self):
        data = "00" + header_with_mm + "00"
        _, start_position = self.deserialize_with_auxpow(data, expect_trailing_data=True, start_position=1)
        self.assertEqual(start_position, len(header_with_mm)//2 + 1)

    # Verify the AuxPoW header with MM header.
    def test_verify_auxpow_header_explicit_coinbase(self):
        header = self.deserialize_with_auxpow(header_with_mm)
        blockchain.Blockchain.verify_header(header, prev_hash_with_mm, target_with_mm)

    # Verify the AuxPoW header without MM header.
    def test_verify_auxpow_header_implicit_coinbase(self):
        header = self.deserialize_with_auxpow(header_without_mm)
        blockchain.Blockchain.verify_header(header, prev_hash_without_mm, target_without_mm)

    # Check that a non-generate AuxPoW transaction is rejected.
    def test_should_reject_non_generate_auxpow(self):
        header = self.deserialize_with_auxpow(header_with_mm)
        header['powdata']['auxpow']['coinbase_merkle_index'] = 0x01

        with self.assertRaises(auxpow.AuxPoWNotGenerateError):
            blockchain.Blockchain.verify_header(header, prev_hash_with_mm, target_with_mm)

    # Check that where the chain merkle branch is far too long to use, it's
    # rejected.
    def test_should_reject_very_long_merkle_branch(self):
        header = self.deserialize_with_auxpow(header_with_mm)
        header['powdata']['auxpow']['chain_merkle_branch'] = list([32 * '00' for i in range(32)])

        with self.assertRaises(auxpow.AuxPoWChainMerkleTooLongError):
            blockchain.Blockchain.verify_header(header, prev_hash_with_mm, target_with_mm)

    # Later steps in AuxPoW validation depend on the contents of the coinbase
    # transaction. Obviously that's useless if we don't check the coinbase
    # transaction is actually part of the parent chain block, so first we test
    # that the transaction hash is part of the merkle tree. This test modifies
    # the transaction, invalidating the hash, to confirm that it's rejected.
    def test_should_reject_bad_coinbase_merkle_branch(self):
        header = self.deserialize_with_auxpow(header_with_mm)

        # Clearing the outputs modifies the coinbase transaction so that its
        # hash no longer matches the parent block merkle root.
        self.clear_coinbase_outputs(header['powdata']['auxpow'], fix_merkle_root=False)

        with self.assertRaises(auxpow.AuxPoWBadCoinbaseMerkleBranchError):
            blockchain.Blockchain.verify_header(header, prev_hash_with_mm, target_with_mm)

    # Ensure that in case of a malformed coinbase transaction (no inputs) it's
    # caught and processed neatly.
    def test_should_reject_coinbase_no_inputs(self):
        header = self.deserialize_with_auxpow(header_with_mm)

        # Set inputs to an empty list
        header['powdata']['auxpow']['parent_coinbase_tx']._inputs = []

        self.clear_coinbase_outputs(header['powdata']['auxpow'])

        with self.assertRaises(auxpow.AuxPoWCoinbaseNoInputsError):
            blockchain.Blockchain.verify_header(header, prev_hash_with_mm, target_with_mm)

    # Catch the case that the coinbase transaction does not contain details of
    # the merged block. In this case we make the transaction script too short
    # for it to do so.  This test is for the code path with an implicit MM
    # coinbase header.
    def test_should_reject_coinbase_root_too_late(self):
        header = self.deserialize_with_auxpow(header_without_mm)

        input_script = bfh(header['powdata']['auxpow']['parent_coinbase_tx'].inputs()[0]['scriptSig'])

        padded_script = bfh('00') * (auxpow.MAX_INDEX_PC_BACKWARDS_COMPATIBILITY + 4)
        padded_script += input_script

        header['powdata']['auxpow']['parent_coinbase_tx']._inputs[0]['scriptSig'] = bh2u(padded_script)

        self.clear_coinbase_outputs(header['powdata']['auxpow'])

        with self.assertRaises(auxpow.AuxPoWCoinbaseRootTooLate):
            blockchain.Blockchain.verify_header(header, prev_hash_without_mm, target_without_mm)

    # Verifies that the commitment of the auxpow to the block header it is
    # proving for is actually checked.
    def test_should_reject_coinbase_root_missing(self):
        header = self.deserialize_with_auxpow(header_without_mm)
        # Modify the header so that its hash no longer matches the
        # chain Merkle root in the AuxPoW.
        header["timestamp"] = 42
        with self.assertRaises(auxpow.AuxPoWCoinbaseRootMissingError):
            blockchain.Blockchain.verify_header(header, prev_hash_without_mm, target_without_mm)


def update_merkle_root_to_match_coinbase(auxpow_header):
    """Updates the parent block merkle root

    This modifies the merkle root in the auxpow's parent block header to
    match the auxpow coinbase transaction.  We need this after modifying
    the coinbase for tests.

    Note that this also breaks the PoW.  This is fine for tests that
    fail due to an earlier check already."""

    coinbase = auxpow_header['parent_coinbase_tx']

    revised_coinbase_txid = auxpow.fast_txid(coinbase)
    revised_merkle_branch = [revised_coinbase_txid]
    revised_merkle_root = auxpow.calculate_merkle_root(revised_coinbase_txid, revised_merkle_branch, auxpow_header['coinbase_merkle_index'])

    auxpow_header['parent_header']['merkle_root'] = revised_merkle_root
    auxpow_header['coinbase_merkle_branch'] = revised_merkle_branch
