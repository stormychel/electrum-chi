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

from electrum import difficulty
from electrum import blockchain
from electrum import powdata

import json
import os

from . import SequentialTestCase
from . import TestCaseForTestnet
from . import FAST_TESTS


def int_algo (algo: str) -> int:
  if algo == "sha256d":
    return powdata.ALGO_SHA256D

  if algo == "neoscrypt":
    return powdata.ALGO_NEOSCRYPT

  raise AssertionError (f"Invalid algo string: {algo}")


class Test_difficulty (SequentialTestCase):

  @classmethod
  def setUpClass (cls):
    super ().setUpClass ()
    data_file = os.path.join (os.path.dirname (os.path.realpath (__file__)),
                              "difficulty.json")
    with open (data_file) as f:
      cls.data = json.load (f)

  def get_bits (self, algo: int, h: int) -> int:
    def getter (algo: int, h: int) -> dict:
      key = f"{h}"
      if key not in self.data:
        return None

      cur = self.data[key]
      if int_algo (cur["algo"]) == algo:
        return cur

      return getter (algo, h - 1)

    target = difficulty.get_target (getter, algo, h)
    return blockchain.Blockchain.target_to_bits (target)

  def test_first_blocks (self):
    for h in range (1000):
      blk = self.data[f"{h}"]
      self.assertEqual (self.get_bits (int_algo (blk["algo"]), h), blk["bits"])

  def test_post_ico_fork (self):
    for h in range (439990, 440100):
      blk = self.data[f"{h}"]
      self.assertEqual (self.get_bits (int_algo (blk["algo"]), h), blk["bits"])
