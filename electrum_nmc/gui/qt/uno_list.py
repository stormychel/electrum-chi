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

from electrum_nmc.i18n import _
from electrum_nmc.names import format_name_identifier, format_name_value

from .util import *
from .utxo_list import UTXOList

# TODO: It'd be nice if we could further reduce code duplication against
# UTXOList.
class UNOList(UTXOList):
    # TODO: fix this for UNOList
    filter_columns = [0, 2]  # Address, Label

    def __init__(self, parent=None):
        MyTreeWidget.__init__(self, parent, self.create_menu, [ _('Name'), _('Value'), _('Expires In'), _('Status')], 1)
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.setSortingEnabled(True)

    def on_update(self):
        self.wallet = self.parent.wallet
        self.network = self.parent.network
        item = self.currentItem()
        self.clear()
        self.utxos = self.wallet.get_utxos()
        for x in self.utxos:
            txid = x['prevout_hash']
            vout = x['prevout_n']
            name_op = self.wallet.transactions[txid].outputs()[vout].name_op
            if name_op is None:
                continue

            # TODO: Support name_new
            if 'name' in name_op:
                name = format_name_identifier(name_op['name'])
                value = format_name_value(name_op['value'])
            else:
                name = ''
                value = ''

            height = x.get('height')
            chain_height = self.network.blockchain().height()
            expires_in = height - chain_height + 36000

            status = ''

            utxo_item = SortableTreeWidgetItem([name, value, '%d'%expires_in, status])
            utxo_item.setFont(0, QFont(MONOSPACE_FONT))
            utxo_item.setFont(1, QFont(MONOSPACE_FONT))
            utxo_item.setData(0, Qt.UserRole, self.get_name(x))
            utxo_item.setData(1, Qt.UserRole, name)

            address = x.get('address')
            if self.wallet.is_frozen(address):
                utxo_item.setBackground(0, ColorScheme.BLUE.as_color(True))
            self.addChild(utxo_item)

    def create_menu(self, position):
        selected = [x.data(0, Qt.UserRole) for x in self.selectedItems()]
        if not selected:
            return
        menu = QMenu()
        coins = filter(lambda x: self.get_name(x) in selected, self.utxos)

        # TODO: implement Renew
        #menu.addAction(_("Renew"), lambda: self.parent.spend_coins(coins))
        if len(selected) == 1:
            txid = selected[0].split(':')[0]
            tx = self.wallet.transactions.get(txid)
            if tx:
                # TODO: implement Configure
                #menu.addAction(_("Configure"), lambda: self.parent.show_transaction(tx))
                menu.addAction(_("Transaction Details"), lambda: self.parent.show_transaction(tx))

        menu.exec_(self.viewport().mapToGlobal(position))

