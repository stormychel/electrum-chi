#!/usr/bin/env python
#
# Electrum-NMC - lightweight Namecoin client
# Copyright (C) 2018 Namecoin Developers
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

def split_name_script(decoded):
    # This case happens if a script was malformed and couldn't be decoded by
    # transaction.get_address_from_output_script.
    if decoded is None:
        return {"name_op": None, "address_scriptPubKey": decoded}

    # name_register TxOuts look like:
    # NAME_REGISTER (name) (value) 2DROP DROP (Bitcoin TxOut)
    match = [ OP_NAME_REGISTER, OPPushDataGeneric, OPPushDataGeneric, opcodes.OP_2DROP, opcodes.OP_DROP ]
    if match_decoded(decoded[:len(match)], match):
        return {"name_op": {"op": OP_NAME_REGISTER, "name": decoded[1][1], "value": decoded[2][1]}, "address_scriptPubKey": decoded[len(match):]}

    # name_update TxOuts look like:
    # NAME_UPDATE (name) (value) 2DROP DROP (Bitcoin TxOut)
    match = [ OP_NAME_UPDATE, OPPushDataGeneric, OPPushDataGeneric, opcodes.OP_2DROP, opcodes.OP_DROP ]
    if match_decoded(decoded[:len(match)], match):
        return {"name_op": {"op": OP_NAME_UPDATE, "name": decoded[1][1], "value": decoded[2][1]}, "address_scriptPubKey": decoded[len(match):]}

    return {"name_op": None, "address_scriptPubKey": decoded}

def get_name_op_from_output_script(_bytes):
    try:
        decoded = [x for x in script_GetOp(_bytes)]
    except MalformedBitcoinScript:
        decoded = None

    # Extract the name script if one is present.
    return split_name_script(decoded)["name_op"]

def name_op_to_script(name_op):
    if name_op is None:
        script = ''
    elif name_op["op"] == OP_NAME_REGISTER:
        validate_update_length(name_op)
        script = '51'                                 # OP_NAME_REGISTER
        script += push_script(bh2u(name_op["name"]))
        script += push_script(bh2u(name_op["value"]))
        script += '6d'                                # OP_2DROP
        script += '75'                                # OP_DROP
    elif name_op["op"] == OP_NAME_UPDATE:
        validate_update_length(name_op)
        script = '52'                                 # OP_NAME_UPDATE
        script += push_script(bh2u(name_op["name"]))
        script += push_script(bh2u(name_op["value"]))
        script += '6d'                                # OP_2DROP
        script += '75'                                # OP_DROP
    else:
        raise BitcoinException('unknown name op: {}'.format(name_op))
    return script

def validate_update_length(name_op):
    validate_anyupdate_length(name_op)

def validate_anyupdate_length(name_op):
    validate_identifier_length(name_op["name"])
    validate_value_length(name_op["value"])

def validate_identifier_length(identifier):
    identifier_length_limit = 256

    identifier_length = len(identifier)
    if identifier_length > identifier_length_limit:
        raise BitcoinException('identifier length {} exceeds limit of {}'.format(identifier_length, identifier_length_limit))

    # TODO: Xaya has more validation rules, which we should at some point
    # implement here as well.

def validate_value_length(value):
    # Special case:  This is also called when we build the "fake name script"
    # that ElectrumX indexes on.  In this case, the value is empty.  That is
    # not valid for Xaya, but we need to accept it here.
    if len(value) == 0:
        return

    value_length_limit = 2048

    value_length = len(value)
    if value_length > value_length_limit:
        raise BitcoinException('value length {} exceeds limit of {}'.format(value_length, value_length_limit))

    import json
    try:
        parsed = json.loads(value)
        if not isinstance (parsed, dict):
            raise BitcoinException(f"Value is not a JSON object: {value}")
    except json.decoder.JSONDecodeError:
        raise BitcoinException(f"Value is invalid JSON: {value}")

def name_identifier_to_scripthash(identifier_bytes):
    name_op = {"op": OP_NAME_UPDATE, "name": identifier_bytes, "value": bytes([])}
    script = name_op_to_script(name_op)
    script += '6a' # OP_RETURN

    return script_to_scripthash(script)


def format_name_identifier(identifier_bytes):
    try:
        identifier = identifier_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return format_name_identifier_unknown_hex(identifier_bytes)

    if identifier.startswith("p/"):
        return format_name_identifier_player(identifier)

    if identifier.startswith("g/"):
        return format_name_identifier_game(identifier)

    return format_name_identifier_unknown(identifier)


def format_name_identifier_player(identifier):
    label = identifier[len("p/"):]
    return f"Player: {label}"


def format_name_identifier_game(identifier):
    label = identifier[len("g/"):]
    return f"Game: {label}"

def format_name_identifier_unknown(identifier):
    # Check for non-printable characters, and print ASCII if none are found.
    if identifier.isprintable():
        return 'Non-standard name "' + identifier + '"'

    return format_name_identifier_unknown_hex(identifier.encode("ascii"))


def format_name_identifier_unknown_hex(identifier_bytes):
    return "Non-standard hex name " + bh2u(identifier_bytes)


def format_name_value(identifier_bytes):
    try:
        identifier = identifier_bytes.decode("ascii")
    except UnicodeDecodeError:
        return format_name_value_hex(identifier_bytes)

    if not identifier.isprintable():
        return format_name_value_hex(identifier_bytes)

    return "JSON " + identifier


def format_name_value_hex(identifier_bytes):
    return "Hex " + bh2u(identifier_bytes)


def format_name_op(name_op):
    if name_op is None:
        return ''
    if "name" in name_op:
        formatted_name = "Name = " + format_name_identifier(name_op["name"])
    if "value" in name_op:
        formatted_value = "Data = " + format_name_value(name_op["value"])

    if name_op["op"] == OP_NAME_REGISTER:
        return "\tRegistration\n\t\t" + formatted_name + "\n\t\t" + formatted_value
    if name_op["op"] == OP_NAME_UPDATE:
        return "\tUpdate\n\t\t" + formatted_name + "\n\t\t" + formatted_value


def get_default_name_tx_label(wallet, tx):
    for idx, o in enumerate(tx.outputs()):
        name_op = o.name_op
        if name_op is not None:
            # TODO: Handle multiple atomic name ops.
            name_input_is_mine, name_output_is_mine, name_value_is_unchanged = get_wallet_name_delta(wallet, tx)
            if not name_input_is_mine and not name_output_is_mine:
                return None
            if name_op["op"] == OP_NAME_REGISTER:
                return "Registration: " + format_name_identifier(name_op["name"])
            if name_input_is_mine and not name_output_is_mine:
                return "Transfer (Outgoing): " + format_name_identifier(name_op["name"])
            if not name_input_is_mine and name_output_is_mine:
                return "Transfer (Incoming): " + format_name_identifier(name_op["name"])
            if name_op["op"] == OP_NAME_UPDATE:
                return "Update: " + format_name_identifier(name_op["name"])
    return None


def get_wallet_name_delta(wallet, tx):
    name_input_is_mine = False
    name_output_is_mine = False

    name_input_value = None
    name_output_value = None

    for txin in tx.inputs():
        addr = wallet.get_txin_address(txin)
        if wallet.is_mine(addr):
            prev_tx = wallet.db.transactions.get(txin['prevout_hash'])
            if prev_tx.outputs()[txin['prevout_n']].name_op is not None:
                name_input_is_mine = True
                if 'value' in prev_tx.outputs()[txin['prevout_n']].name_op:
                    name_input_value = prev_tx.outputs()[txin['prevout_n']].name_op['value']
    for o in tx.outputs():
        if o.name_op is not None and wallet.is_mine(o.address):
            name_output_is_mine = True
            if 'value' in o.name_op:
                name_output_value = o.name_op['value']

    name_value_is_unchanged = name_input_value == name_output_value

    return name_input_is_mine, name_output_is_mine, name_value_is_unchanged


def get_wallet_name_count(wallet, network):
    confirmed_count = 0
    pending_count = 0

    utxos = wallet.get_utxos()
    for _, x in enumerate(utxos):
        txid = x.get('prevout_hash')
        vout = x.get('prevout_n')
        name_op = wallet.db.transactions[txid].outputs()[vout].name_op
        if name_op is None:
            continue
        height = x.get('height')
        if height <= 0:
            # Transaction isn't mined yet
            if name_op['op'] == OP_NAME_REGISTER:
                # Registration is pending
                pending_count += 1
                continue
            else:
                # name_update is pending
                # TODO: we shouldn't consider it confirmed if it's an incoming
                # or outgoing transfer.
                confirmed_count += 1
                continue
        if 'name' in name_op:
            # name_anyupdate is mined (not expired)
            confirmed_count += 1
            continue
        else:
            # name_new is mined
            pending_count += 1
            continue
    return confirmed_count, pending_count


import binascii
from datetime import datetime, timedelta
import os
import re

from .bitcoin import push_script, script_to_scripthash
from .crypto import hash_160
from .transaction import MalformedBitcoinScript, match_decoded, opcodes, OPPushDataGeneric, script_GetOp, Transaction
from .util import bh2u, BitcoinException

OP_NAME_REGISTER = opcodes.OP_1
OP_NAME_UPDATE = opcodes.OP_2
