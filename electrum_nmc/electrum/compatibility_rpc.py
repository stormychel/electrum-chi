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
A JSON-RPC server that implements methods required by games in exactly the
same way as Xaya Core does, executing them based on Electrum.  This server
can be run in addition to the "standard" Electrum JSON-RPC server, and
allows to connect games to Electrum that are originally written for the
Xaya Core JSON-RPC interface.
"""

from .jsonrpc import VerifyingJSONRPCServer


class Server(VerifyingJSONRPCServer):
  """
  The compatibility JSON-RPC server instance.
  """

  def __init__ (self, *args, cmd_runner, **kwargs):
    self.cmd_runner = cmd_runner
    VerifyingJSONRPCServer.__init__ (self, *args, **kwargs)

    self.register_function (self.getbalance, "getbalance")
    self.register_function (self.getnewaddress, "getnewaddress")

    self.register_function (self.name_list, "name_list")
    self.register_function (self.name_pending, "name_pending")
    self.register_function (self.name_register, "name_register")
    self.register_function (self.name_update, "name_update")

  def getbalance (self):
    bal = self.cmd_runner.getbalance ()
    return bal["confirmed"]

  def getnewaddress (self, label="", address_type=None):
    addr = self.cmd_runner.createnewaddress ()

    if address_type is None:
      return addr

    if address_type == "legacy":
      if addr.startswith("chi") or addr[0] not in ['C', 'c']:
        raise RuntimeError ("Cannot produce legacy address from this wallet")
      return addr

    raise RuntimeError (f"Unsupported address type: {address_type}")

  def name_list (self, name=None):
    return self.cmd_runner.name_list (name)

  def name_pending (self, name=None):
    self.logger.warning ("name_pending is not supported properly,"
                         " returning empty mempool")
    return []

  def name_register (self, name, value):
    tx = self.cmd_runner.name_register (name, value)
    return self.cmd_runner.broadcast (tx["hex"])

  def name_update (self, name, value):
    tx = self.cmd_runner.name_update (name, value)
    return self.cmd_runner.broadcast (tx["hex"])
