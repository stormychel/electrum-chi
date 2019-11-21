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

from . import bitcoin
from . import crypto
from . import ecc
from . import util

from .commands import Commands
from .logging import Logger

import jsonrpcserver
from jsonrpcserver import response

from aiohttp import web
import base64


class Logic (Logger):
  """
  The implementation of the actual RPC methods, but separated from the
  server itself.
  """

  def __init__ (self, cmd_runner):
    Logger.__init__ (self)
    self.cmd_runner = cmd_runner
    self.commands = [
      "getbalance",
      "getnewaddress",
      "sendtoaddress",
      "signmessage",
      "verifymessage",
      "name_list",
      "name_pending",
      "name_register",
      "name_update",
    ]

  async def getbalance (self):
    bal = await self.cmd_runner.getbalance ()
    return bal["confirmed"]

  async def getnewaddress (self, label="", address_type=None):
    addr = await self.cmd_runner.createnewaddress ()

    if address_type is None:
      return addr

    if address_type == "legacy":
      if addr.startswith("chi") or addr[0] not in ['C', 'c']:
        raise RuntimeError ("Cannot produce legacy address from this wallet")
      return addr

    raise RuntimeError (f"Unsupported address type: {address_type}")

  async def sendtoaddress (self, address, amount):
    tx = await self.cmd_runner.payto (address, amount)
    return await self.cmd_runner.broadcast (tx["hex"])

  async def signmessage (self, address, message):
    return await self.cmd_runner.signmessage (address, message)

  async def verifymessage (self, address, signature, message):
    # We need to handle the special form with address recovery supported
    # by Xaya Core.
    if address == "":
      sig = base64.b64decode (signature)
      msg_hash = crypto.sha256d (ecc.msg_magic (util.to_bytes (message)))
      pubkey, comp = ecc.ECPubkey.from_signature65 (sig, msg_hash)
      address = bitcoin.public_key_to_p2pkh (pubkey.get_public_key_bytes (comp))
      addr_recovery = True
    else:
      addr_recovery = False

    res = await self.cmd_runner.verifymessage (address, signature, message)
    if not addr_recovery:
      return res

    return {"valid": res, "address": address}

  async def name_list (self, name=None):
    return await self.cmd_runner.name_list (name)

  async def name_pending (self, name=None):
    self.logger.warning ("name_pending is not supported properly,"
                         " returning empty mempool")
    return []

  async def name_register (self, name, value):
    tx = await self.cmd_runner.name_register (name, value)
    return await self.cmd_runner.broadcast (tx["hex"])

  async def name_update (self, name, value):
    tx = await self.cmd_runner.name_update (name, value)
    return await self.cmd_runner.broadcast (tx["hex"])


class Server (Logger):
  """
  The actual JSON-RPC server handling the authentication and requests.
  """

  def __init__ (self, daemon):
    Logger.__init__ (self)
    self.daemon = daemon
    self.config = self.daemon.config
    cmd_runner = Commands (config=self.config, network=self.daemon.network,
                           daemon=self.daemon)
    self.logic = Logic (cmd_runner)

  async def run (self):
    host = self.config.get ('rpchost', 'localhost')
    port = self.config.get ('rpcportcompat')

    self.methods = jsonrpcserver.methods.Methods ()
    for cmdname in self.logic.commands:
      self.methods.add (getattr (self.logic, cmdname))

    app = web.Application ()
    app.router.add_post ("/", self.handle)
    runner = web.AppRunner (app)
    await runner.setup ()
    site = web.TCPSite (runner, host, port)
    await site.start ()

  async def handle (self, request):
    async with self.daemon.auth_lock:
      try:
        await self.daemon.authenticate (request.headers)
      except:
        return web.Response (text='Forbidden', status=403)
    request = await request.text ()
    response = await jsonrpcserver.async_dispatch (request,
                                                   methods=self.methods)
    if isinstance (response, jsonrpcserver.response.ExceptionResponse):
        self.logger.error (f"error handling request: {request}",
                           exc_info=response.exc)
        # this exposes the error message to the client
        response.message = str (response.exc)
    if not response.wanted:
      return web.Response ()
    return web.json_response (response.deserialized (),
                              status=response.http_status)
