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
The implementation of Xaya's difficulty retargeting with continuous changes
and two independent mining algorithms.
"""

from . import blockchain
from . import powdata


MAX_TARGET_NEOSCRYPT = 0x00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff

NUM_BLOCKS = 24


def algo_log2_weight (algo: int) -> int:
  """
  Returns how much harder the given difficulty algorithm is (as an
  exponent of two) compared to SHA-256d.  This is used to compute chain
  work and also to adjust the minimum difficulty to the different
  algorithms.
  """

  if algo == powdata.ALGO_SHA256D:
    return 0
  if algo == powdata.ALGO_NEOSCRYPT:
    return 10

  raise AssertionError (f"Unknown algorithm: {algo}")


def max_target (algo: int) -> int:
  """
  Returns the maximum target for the given algorithm.
  """

  res = MAX_TARGET_NEOSCRYPT
  diff = algo_log2_weight (powdata.ALGO_NEOSCRYPT) - algo_log2_weight (algo)

  assert diff >= 0, diff
  res >>= diff

  return res


def get_target_spacing (algo: int, h: int) -> int:
  """
  Returns the targeted block time in seconds for the given algorithm at
  the given height.
  """

  # Check for the post-ICO fork.
  if h < 440_000:
    return 60

  if algo == powdata.ALGO_SHA256D:
    return 120
  if algo == powdata.ALGO_NEOSCRYPT:
    return 40

  raise AssertionError (f"Unknown algorithm: {algo}")


def get_target (getter, algo: int, h: int) -> int:
  """
  Returns the difficulty target that should be applied for the given algorithm
  at the given height.  getter must be a function that returns the block data
  needed (height, timestamp and bits) when called with (algo, height) tuples.
  """

  # The genesis block has bits differing slightly from the maximum target.
  # Thus special case it here.
  if h == 0:
    return blockchain.Blockchain.bits_to_target (0x1e0ffff0)

  limit = max_target (algo)

  last = getter (algo, h - 1)
  if last is None:
    return limit

  cur = last
  for n in range (1, NUM_BLOCKS + 1):
    target = blockchain.Blockchain.bits_to_target (cur["bits"])

    if n == 1:
      res = target
    else:
      res = (res * n + target) // (n + 1)

    if n < NUM_BLOCKS:
        cur = getter (algo, cur["height"] - 1)
        if cur is None:
          return limit

  actual_time = last["timestamp"] - cur["timestamp"]
  next_height = last["height"] + 1
  target_time = NUM_BLOCKS * get_target_spacing (algo, next_height)

  if actual_time < target_time // 3:
    actual_time = target_time // 3
  if actual_time > target_time * 3:
    actual_time = target_time * 3

  res *= actual_time
  res //= target_time

  if res > limit:
    res = limit

  return res
