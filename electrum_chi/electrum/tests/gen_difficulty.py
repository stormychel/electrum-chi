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
Generator for the test data in difficulty.json.  This queries a Xaya Core
instance by RPC and saves a couple of blocks that we use in the test
to the JSON file.
"""

import jsonrpclib

import json
import sys


if len (sys.argv) != 2:
  sys.exit ("USAGE: gen_difficulty.py RPC-URL")

rpc = jsonrpclib.Server (sys.argv[1])

def get_data (h):
  blk_hash = rpc.getblockhash (h)
  data = rpc.getblock (blk_hash)
  return {
    "height": h,
    "timestamp": data["time"],
    "algo": data["powdata"]["algo"],
    "bits": int (data["powdata"]["bits"], 16),
  }

data = {}

# For the first basic test, we check difficulty on the first 1000 blocks.
for h in range (1000):
  data["%d" % h] = get_data (h)

# We also check it around the post-ICO hard fork, as that affected the
# target times and thus difficulty computation.
for h in range (439900, 440100):
  data["%d" % h] = get_data (h)

print (json.dumps (data, indent=2))
