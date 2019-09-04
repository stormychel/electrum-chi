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

from electrum.commands import Commands
from electrum import compatibility_rpc
from electrum import util

from . import SequentialTestCase
from . import FAST_TESTS

import asyncio


# Test address and valid signature.
ADDR = "CQhHcoU6NpD1NcJPPcXwnGAxURctQxdN1f"
SGN = "H8E9NOxy7Hn9YiDmVmER0G0z7It8flVEpEQuU1BbCLTCBB7+P2uGs4WzMCaGJmr2YtSzMYGWJeNZwTEnMHuVgpg="
MSG = "test message"

# Another address (for which the signature is invalid).
OTHER_ADDR = "CM6FDmteB7o3wJ3KiX3o4L66XJ97T3TMDe"


class Test_compatibility_rpc (SequentialTestCase):

  def setUp (self):
    super ().setUp ()
    cmd = Commands (config=None, wallet=None, network=None)
    self.logic = compatibility_rpc.Logic (cmd)
    self.asyncio_loop, self._stop_loop, self._loop_thread \
        = util.create_and_start_event_loop ()

  def tearDown (self):
    super ().tearDown ()
    self.asyncio_loop.call_soon_threadsafe (self._stop_loop.set_result, 1)
    self._loop_thread.join (timeout=1)

  def eval (self, method, *args):
    """
    Runs the given command name on our logic instance, using asyncio properly
    to resolve the coroutines.
    """

    fcn = getattr (self.logic, method)
    coro = fcn (*args)

    future = asyncio.run_coroutine_threadsafe (coro, asyncio.get_event_loop ())
    return future.result ()

  def test_verifymessage_with_address (self):
    self.assertEqual (self.eval ("verifymessage", ADDR, SGN, MSG), True)
    self.assertEqual (self.eval ("verifymessage", OTHER_ADDR, SGN, MSG), False)
    self.assertEqual (self.eval ("verifymessage", "invalid", SGN, MSG), False)
    self.assertEqual (self.eval ("verifymessage", ADDR, SGN, "wrong msg"),
                      False)

  def test_verifymessage_address_recovery (self):
    self.assertEqual (self.eval ("verifymessage", "", SGN, MSG), {
      "valid": True,
      "address": ADDR,
    })

    data = self.eval ("verifymessage", "", SGN, "wrong msg")
    self.assertEqual (data["valid"], True)
    self.assertNotEqual (data["address"], ADDR)
