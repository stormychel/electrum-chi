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

"""
Code for handling of PoW data (triple-purpose mining in Xaya).  For details,
see the spec at https://github.com/xaya/xaya/blob/master/doc/xaya/mining.md.
"""

from . import auxpow
from . import blockchain


MM_FLAG = 0x80

ALGO_SHA256D = 1
ALGO_NEOSCRYPT = 2


class SerializedLengthError (Exception):
  def __init__ (self, length):
    super ().__init__ (f"Invalid PoW data length: {length}")


def deserialize_base (s: bytes, start_position=0) -> (dict, int):
  """
  Deserialises the base part (algo and bits) of a PoW data structure from
  input bytes.  This is used both for deserialising a full PoW data, and
  for the part that is stored in the on-disk headers.
  """

  remaining_length = len (s) - start_position
  if remaining_length < 5:
    raise SerializedLengthError (remaining_length)

  algo = s[start_position]

  res = {}
  res["algo"] = algo & ~MM_FLAG
  res["mergemined"] = bool (algo & MM_FLAG)
  res["bits"] = int.from_bytes(s[start_position + 1 : start_position + 5],
                               byteorder="little")
  start_position += 5

  assert start_position <= len (s)
  return res, start_position


def deserialize (s: bytes, start_position=0) -> (dict, int):
  """
  Deserialises a PoW data structure from input bytes.
  """

  remaining_length = len (s) - start_position

  res, start_position = deserialize_base (s, start_position=start_position)

  if res["mergemined"]:
    res["auxpow"], start_position = auxpow.deserialize_auxpow_header (
        s, start_position=start_position)
  else:
    fakeheader = s[start_position : start_position + blockchain.HEADER_SIZE]
    if len (fakeheader) < blockchain.HEADER_SIZE:
      raise SerializedLengthError (remaining_length)
    res["fakeheader"] = blockchain.deserialize_pure_header (fakeheader, None)
    start_position += blockchain.HEADER_SIZE

  return res, start_position
