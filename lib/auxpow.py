# -*- coding: utf-8 -*-
#
# Electrum-NMC - lightweight Namecoin client
# Copyright (C) 2018 The Namecoin developers
#
# License for all components not part of Electrum-DOGE:
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
#
# Based on Electrum-DOGE - lightweight Dogecoin client
# Copyright (C) 2014 The Electrum-DOGE contributors
#
# License for the Electrum-DOGE components:
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

# electrum_nmc.blockchain is an absolute import because cyclic imports must be
# absolute prior to Python 3.5.
import electrum_nmc.blockchain
from .bitcoin import hash_encode
from .transaction import BCDataStream, Transaction
from .util import bfh, bh2u

BLOCK_VERSION_AUXPOW_BIT = 0x100
MIN_AUXPOW_HEIGHT = 19200

def auxpow_active(base_header):
    height_allows_auxpow = base_header['block_height'] >= MIN_AUXPOW_HEIGHT
    version_allows_auxpow = base_header['version'] & BLOCK_VERSION_AUXPOW_BIT

    return height_allows_auxpow and version_allows_auxpow

def deserialize_auxpow_header(base_header, s, expect_trailing_data=False):
    auxpow_header = {}

    # Chain ID is the top 16 bits of the 32-bit version.
    auxpow_header['chain_id'] = base_header['version'] >> 16

    # The parent coinbase transaction is first.
    # Deserialize it and save the trailing data.
    parent_coinbase_tx = Transaction(bh2u(s), expect_trailing_data=True)
    parent_coinbase_tx_dict, s_hex = parent_coinbase_tx.deserialize()
    auxpow_header['parent_coinbase_tx'] = parent_coinbase_tx
    s = bfh(s_hex)

    # Next is the parent block hash.  According to the Bitcoin.it wiki,
    # this field is not actually consensus-critical.  So we don't save it.
    s = s[32:]

    # The coinbase and chain merkle branches/indices are next.
    # Deserialize them and save the trailing data.
    auxpow_header['coinbase_merkle_branch'], auxpow_header['coinbase_merkle_index'], s = deserialize_merkle_branch(s)
    auxpow_header['chain_merkle_branch'], auxpow_header['chain_merkle_index'], s = deserialize_merkle_branch(s)
    
    # Finally there's the parent header.  Deserialize it, along with any
    # trailing data if requested.
    if expect_trailing_data:
        auxpow_header['parent_header'], trailing_data = electrum_nmc.blockchain.deserialize_header(s, 1, expect_trailing_data=expect_trailing_data)
    else:
        auxpow_header['parent_header'] = electrum_nmc.blockchain.deserialize_header(s, 1, expect_trailing_data=expect_trailing_data)
    # The parent block header doesn't have any block height,
    # so delete that field.  (We used 1 as a dummy value above.)
    del auxpow_header['parent_header']['block_height']

    if expect_trailing_data:
        return auxpow_header, trailing_data

    return auxpow_header

# Copied from merkle_branch_from_string in https://github.com/electrumalt/electrum-doge/blob/f74312822a14f59aa8d50186baff74cade449ccd/lib/blockchain.py#L622
# TODO: Audit this function carefully.
def deserialize_merkle_branch(s):
    vds = BCDataStream()
    vds.write(s)
    hashes = []
    n_hashes = vds.read_compact_size()
    for i in range(n_hashes):
        _hash = vds.read_bytes(32)
        hashes.append(hash_encode(_hash))
    index = vds.read_int32()
    return hashes, index, s[vds.read_cursor:]

def hash_parent_header(header):
    if not auxpow_active(header):
        return electrum_nmc.blockchain.hash_header(header)

    verify_auxpow(header)

    return electrum_nmc.blockchain.hash_header(header['auxpow']['parent_header'])

# TODO: Implement this
def verify_auxpow(header):
    pass

