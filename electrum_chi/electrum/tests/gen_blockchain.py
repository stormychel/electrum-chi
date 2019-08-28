#!/usr/bin/env python

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

"""
Generator for the test data in blockchain.json.  This uses a regtest Xaya Core
instance to generate a series of valid blocks/headers in the structure
required by test_blockchain.py.
"""

import jsonrpclib

import json
import sys


if len (sys.argv) != 2:
  sys.exit ("USAGE: gen_blockchain.py RPC-URL")

rpc = jsonrpclib.Server (sys.argv[1])

# While building up the test chains of headers, we save the resulting data
# here.  That is what will be stored in the data file in the end.  It is
# a dictionary with the letters that identify the headers in the test mapped
# to the headers as JSON objects with hash and serialised header hex string.
data = {}

# Start by putting in the genesis block.
genesis_hash = rpc.getblockhash (0)
data["A"] = {
  "hash": genesis_hash,
  "header_hex": rpc.getblockheader (genesis_hash, False),
  "height": 0,
  "work": rpc.getblockheader (genesis_hash)["chainwork"],
}

def place_chain (ids, parent_id, algo):
  """
  Constructs a new chain of blocks with the given IDs, building on top of
  the block with parent_id.  It uses the given algorithm for mining it.
  """

  parent_hash = data[parent_id]["hash"]
  parent_data = rpc.getblock (parent_hash)
  if "nextblockhash" in parent_data:
    rpc.invalidateblock (parent_data["nextblockhash"])

  addr = rpc.getnewaddress ()
  hashes = rpc.generatetoaddress (len (ids), addr, None, algo)
  assert len (hashes) == len (ids)

  for i, h in zip (ids, hashes):
    blk = rpc.getblockheader (h)
    data[i] = {
      "hash": h,
      "header_hex": rpc.getblockheader (h, False),
      "height": blk["height"],
      "work": blk["chainwork"],
    }

place_chain (["B", "C", "D", "E", "F", "O", "P", "Q", "R", "S", "T", "U"],
             "A", "sha256d")
place_chain (["G", "H", "I", "J", "K", "L"], "F", "sha256d")
place_chain (["M", "N", "X", "Y", "Z"], "I", "sha256d")
place_chain (["Neo1", "Neo2"], "B", "neoscrypt")

print (json.dumps (data, indent=2))
