# -*- coding: utf-8 -*-
#
# Electrum-NMC - lightweight Namecoin client
# Copyright (C) 2019 Namecoin Developers
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

"""Conversion of addresses and keys from Bitcoin to Namecoin format

This module provides methods that convert addresses and keys from the
Bitcoin formats to Namecoin versions.  This can be applied in tests
where Bitcoin addresses and keys are used as magic strings upstream,
but the code under test requires the Namecoin forms."""

from electrum import bitcoin
from electrum.constants import BitcoinMainnet, BitcoinTestnet
from electrum import segwit_addr


def frombtc(inp: str) -> str:
    """Given a Bitcoin address or key, converts it to Namecoin format"""

    # If there is a trailing suffix on an URI with an address, remove it
    # and add it back after conversion.
    qm = inp.find("?")
    if qm != -1:
        suffix = inp[qm:]
        stripped = inp[:qm]
        return frombtc(stripped) + suffix

    # If there is a prefix separated by colon, strip it off and add it
    # back later.  For bitcoin: URI's, the prefix is rebranded as well.
    colon = inp.find(":")
    if colon != -1:
        prefix = inp[:colon]
        stripped = inp[colon + 1:]
        if prefix == "bitcoin":
            prefix = "namecoin"
        return prefix + ":" + frombtc(stripped)

    # Handle bech32 segwit data first.
    if inp[:3].lower() == "bc1":
        return convert_bech32(inp, BitcoinMainnet.SEGWIT_HRP)
    if inp[:3].lower() == "tb1":
        return convert_bech32(inp, BitcoinTestnet.SEGWIT_HRP)

    # Otherwise, try to base58-decode it and then look at the version to
    # determine what it could have been.
    try:
        vch = bitcoin.DecodeBase58Check(inp)
        old_version = vch[0]

        if vch[0] == 0:  # P2PKH address
            new_version = BitcoinMainnet.ADDRTYPE_P2PKH
        elif vch[0] == 5:  # P2SH address
            new_version = BitcoinMainnet.ADDRTYPE_P2SH
        elif vch[0] in range (128, 136):  # Privkey with optional script type
            offset = vch[0] - 128
            new_version = BitcoinMainnet.WIF_PREFIX + offset
        else:
            raise AssertionError(f"Unknown Bitcoin base58 version: {old_version}")

        new_vch = bytes([new_version]) + vch[1:]
        outp = bitcoin.EncodeBase58Check(new_vch)

        return outp
    except bitcoin.InvalidChecksum:
        # This is not base58 data, maybe try something else.
        pass

    raise AssertionError(f"Invalid input for format conversion: {inp}")


def convert_bech32(inp: str, new_hrp: str) -> str:
    """Converts a bech32 input to another HRP"""

    _, data = segwit_addr.bech32_decode(inp)
    if data is None:
        raise AssertionError(f"Invalid bech32 for conversion: {inp}")

    return segwit_addr.bech32_encode(new_hrp, data)
