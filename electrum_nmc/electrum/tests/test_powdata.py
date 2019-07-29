# -*- coding: utf-8 -*-
#
# Electrum-CHI - lightweight Xaya client
# Copyright (C) 2019 The Xaya developers
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from electrum import auxpow
from electrum import blockchain
from electrum import constants
from electrum import powdata
from electrum.util import bfh

from . import SequentialTestCase
from . import TestCaseForTestnet
from . import FAST_TESTS


# Xaya block #100, which is Neoscrypt with a fake header.
header_neoscrypt = "00000020fc0261d5ae27dfbfed6e429b73fb7dad01b7d9274e63bbf2736a44912948b6fdbd982b64718798c3ddb1039e386ba4bf42663465c76a2d80440468bc72d1fb3903a9485b000000000000000002c1b64e1d000000000000000000000000000000000000000000000000000000000000000000000000f4613e4c8bafeff8f90324301345ae8b6c912583235b4b344bb226fbb7226c200000000000000000014e95f2"
bits_neoscrypt = 0x1d4eb6c1
prev_hash_neoscrypt \
    = "fdb6482991446a73f2bb634e27d9b701ad7dfb739b426eedbfdf27aed56102fc"

# Xaya block #100,000, which is SHA-256d merge mined.
header_sha256d = "000000206bcd596e7aab01a1e192c5b2072f8866d72b5ee5e4d924a2b3b5ab1db3c6cb8a22e9c44f8b4dc1fe80e73b57bd0b8a92e5820ff2f236b9ba85801f8f5a4a2bbd0f83785b0000000000000000815872341801000000010000000000000000000000000000000000000000000000000000000000000000ffffffff64033c33082cfabe6d6dfe0718afd8c0651b58f14378a128efde085d91bcfa2790de57ec862ad420d90708000000f09f909f000f4d696e6564206279207374636f646500000000000000000000000000000000000000000000000000000000000000000000ff3b9a010320983b4b000000001976a914c825a1ecf2a6830c4401620c3a16f1995057c2ab88ac00000000000000002f6a24aa21a9ed98a08f4c63b7cad2f139005520cf5998e1fa2ad8d53bbad87e0868d8c509149308000000000000000000000000000000002c6a4c2952534b424c4f434b3a88b841b4ba9c30eff483b55f8a520403afac9e2050a769129a76620c51e633615b9cd44700000000000000000000000000000000000000000000000000000000000000000c094ba7af1a3113168b23066f8f6b45778460505669f977ba7f9108f1d458315cd955a774c4ac7d174ae3b31a6ee37c64a3f0401157dde6975445abb9b6f1baeea827caf25ab0efaa15c67fa46bdcb4d578544741d3e29dc94e62cf85cf1f19692f189abea8fe67dc890784001c81e617b33f6fe8983cc84f1853455deedd3049a2412beca7139ba127a286b0d1f79bb7902b6c42f9ff99e997e29778288a643210f8a290e0860fd2449d8d57d94919a7a0a940f5a8f3e21a955feabbd755fdffe0e24c8455fb0457fb09f4ae18ed88f408a2e39afe11942262cb7de41ceedd74f44eaef1a3e84d528fb70c08f08e023cf04ec2695cf3aa26efbd2397da18b0a3e24c68f5b7957ce6da7cfda068356a80a1f4f5af7ab26e9cae43ab1fe7feb0b2dbcb06f33a6b06ba5c09fd6f21b40a34eaf98817720284c1ee8a2b0f900375ca86d6fbfca4edbc180d773893ff54c7f3e1c4833c3e290252ce026615935aba0a0eaeaad68e9d1cba8f2e02ab8188014b5817c7d432bad02616858db597f84c0800000000030bd3078054f6234585a6a98299a6c3f80526c2122057956ffc6947e33cbbad2c77032806e674b9cc358f8a8f78759a4ca893c2c5500ccf28ebff54a47b40c2e51cdeb4b83c713eb2cca3e6872f3d66b4167e64f36bd01674d70fea5b3551cda50700000000000020913d01444f14db2c6ab43ffd0f36af5613423815543c22000000000000000000a2edf8bab99ac19e7f7adaf23bc43570d543054aed83e77694f26d33ec9db2a51e83785ba70d2c17865f3a57"
bits_sha256d = 0x18347258
prev_hash_sha256d \
    = "8acbc6b31dabb5b3a224d9e4e55e2bd766882f07b2c592e1a101ab7a6e59cd6b"


class Test_powdata (SequentialTestCase):

  def check_deserialization (self, fcn, hex_data):
    """
    Runs the deserialisation function fcn on the data given as hex, starting
    from position 80 (after the pure header).  This also verifies the expected
    error if we reach EOF, and returns the parsed dict.
    """

    data = bfh (hex_data)
    start = blockchain.PURE_HEADER_SIZE

    # A too-short auxpow raises an InvalidHeader exception rather than
    # our powdata one.  Just check for any error here.
    with self.assertRaises (Exception):
      fcn (data[:-1], expect_trailing_data=True, start_position=start)

    res, _ = fcn (data, start_position=start)
    return res

  def test_deserialize_base_neoscrypt (self):
    res = self.check_deserialization (powdata.deserialize_base,
                                      header_neoscrypt[:170])
    self.assertEqual (res, {
      "algo": powdata.ALGO_NEOSCRYPT,
      "mergemined": False,
      "bits": bits_neoscrypt,
    })

  def test_deserialize_base_sha256d (self):
    res = self.check_deserialization (powdata.deserialize_base,
                                      header_sha256d[:170])
    self.assertEqual (res, {
      "algo": powdata.ALGO_SHA256D,
      "mergemined": True,
      "bits": bits_sha256d,
    })

  def test_deserialize_neoscrypt (self):
    res = self.check_deserialization (powdata.deserialize, header_neoscrypt)

    fakeheader = res["fakeheader"]
    del res["fakeheader"]

    self.assertEqual (res, {
      "algo": powdata.ALGO_NEOSCRYPT,
      "mergemined": False,
      "bits": bits_neoscrypt,
    })

    self.assertEqual (blockchain.serialize_pure_header (fakeheader),
                      header_neoscrypt[170:])

  def test_deserialize_sha256d (self):
    res = self.check_deserialization (powdata.deserialize, header_sha256d)

    auxpow = res["auxpow"]
    del res["auxpow"]

    self.assertEqual (res, {
      "algo": powdata.ALGO_SHA256D,
      "mergemined": True,
      "bits": bits_sha256d,
    })

    self.assertEqual (auxpow["chain_merkle_index"], 7)
    self.assertEqual (auxpow["coinbase_merkle_branch"][11],
        "084cf897b58d851626d0ba32d4c717584b018881ab022e8fba1c9d8ed6aaae0e")

  def test_serialize_base (self):
    for hex_data in [header_neoscrypt, header_sha256d]:
      base_data = bfh (hex_data)[80 : 85]
      parsed, _ = powdata.deserialize_base (base_data)
      serialised = powdata.serialize_base (parsed)
      self.assertEqual (serialised, base_data.hex ())

  def test_pow_hash_sha256d (self):
    phash = powdata.pow_hash (header_sha256d[-160:], powdata.ALGO_SHA256D)
    self.assertEqual (phash,
        "00000000000000001903108b258887d0258a3e8caf776983069f94b9f47049f6")

  def test_pow_hash_neoscrypt (self):
    phash = powdata.pow_hash (header_neoscrypt[170:], powdata.ALGO_NEOSCRYPT)
    self.assertEqual (phash,
        "00000048e0ea0e9de977078ea296c0caf2dd5f9fa42f4fabb80db2f12914f5f3")

  def test_pow_hash_invalid_algo (self):
    with self.assertRaises (powdata.InvalidAlgoError):
      powdata.pow_hash ("", 42)

  def call_verify_header (self, header, bits=None, prev_hash=None):
    """
    Calls blockchain.verify_header, but fills in the target and prev hash
    from the parsed header if not explicitly set.  We do not want to test that
    part of verify_header here, so there's no need for us having to put the
    right values in all the time in the test calls.  Also makes sure that the
    block height is set so that auxpow is not skipped.
    """

    # Make sure the height is above the latest checkpoint, so that PoW data
    # verification is not skipped.
    header["block_height"] = constants.net.max_checkpoint () + 1

    if prev_hash is None:
      prev_hash = header["prev_block_hash"]
    if bits is None:
      bits = header["powdata"]["bits"]

    target = blockchain.Blockchain.bits_to_target (bits)
    blockchain.Blockchain.verify_header (header, prev_hash, target)

  def test_valid_neoscrypt (self):
    data = blockchain.deserialize_full_header (bfh (header_neoscrypt), None)
    self.call_verify_header (data, bits_neoscrypt, prev_hash_neoscrypt)

  def test_valid_sha256d (self):
    data = blockchain.deserialize_full_header (bfh (header_sha256d), None)
    self.call_verify_header (data, bits_sha256d, prev_hash_sha256d)

  def test_nonzero_header_bits (self):
    data = blockchain.deserialize_full_header (bfh (header_neoscrypt), None)
    data["bits"] = 42
    try:
      self.call_verify_header (data)
    except Exception as exc:
      # Since we modified the header, we would get an invalid commitment error
      # anyway.  Check that this is not why we failed.
      self.assertEqual (type (exc), Exception)

  def test_bits_mismatch (self):
    data = blockchain.deserialize_full_header (bfh (header_neoscrypt), None)
    with self.assertRaises (Exception):
      self.call_verify_header (data, bits=bits_sha256d)

  def test_invalid_algo (self):
    data = blockchain.deserialize_full_header (bfh (header_neoscrypt), None)
    data["powdata"]["algo"] = 42
    with self.assertRaises (powdata.InvalidAlgoError):
      self.call_verify_header (data)

  def test_neoscrypt_mm (self):
    data = blockchain.deserialize_full_header (bfh (header_neoscrypt), None)
    data["powdata"]["mergemined"] = True
    with self.assertRaises (powdata.InvalidAlgoError):
      self.call_verify_header (data)

  def test_sha256d_not_mm (self):
    data = blockchain.deserialize_full_header (bfh (header_sha256d), None)
    data["powdata"]["mergemined"] = False
    with self.assertRaises (powdata.InvalidAlgoError):
      self.call_verify_header (data)

  def test_mm_no_auxpow (self):
    data = blockchain.deserialize_full_header (bfh (header_sha256d), None)
    del data["powdata"]["auxpow"]
    with self.assertRaises (powdata.VerifyError):
      self.call_verify_header (data)

  def test_standalone_no_fakeheader (self):
    data = blockchain.deserialize_full_header (bfh (header_neoscrypt), None)
    del data["powdata"]["fakeheader"]
    with self.assertRaises (powdata.VerifyError):
      self.call_verify_header (data)

  def test_invalid_auxpow (self):
    data = blockchain.deserialize_full_header (bfh (header_sha256d), None)
    data["powdata"]["auxpow"]["coinbase_merkle_index"] = 42
    with self.assertRaises (auxpow.AuxPoWNotGenerateError):
      self.call_verify_header (data)

  def test_auxpow_wrong_commitment (self):
    data = blockchain.deserialize_full_header (bfh (header_sha256d), None)
    data["timestamp"] = 42
    with self.assertRaises (auxpow.AuxPoWCoinbaseRootMissingError):
      self.call_verify_header (data)

  def test_fakeheader_wrong_commitment (self):
    data = blockchain.deserialize_full_header (bfh (header_neoscrypt), None)
    data["timestamp"] = 42
    with self.assertRaises (powdata.InvalidCommitmentError):
      self.call_verify_header (data)

  def test_auxpow_insufficient_pow (self):
    data = blockchain.deserialize_full_header (bfh (header_sha256d), None)
    data["powdata"]["auxpow"]["parent_header"]["nonce"] = 10
    with self.assertRaises (powdata.InsufficientPowError):
      self.call_verify_header (data)

  def test_neoscrypt_insufficient_pow (self):
    data = blockchain.deserialize_full_header (bfh (header_neoscrypt), None)
    data["powdata"]["fakeheader"]["nonce"] = 10
    with self.assertRaises (powdata.InsufficientPowError):
      self.call_verify_header (data)
