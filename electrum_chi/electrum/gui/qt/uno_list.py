#!/usr/bin/env python
#
# Electrum-NMC - lightweight Namecoin client
# Copyright (C) 2018-2019 Namecoin Developers
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

from typing import Optional, List, Set
from enum import IntEnum
import sys
import traceback

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QStandardItemModel, QStandardItem, QFont
from PyQt5.QtWidgets import QAbstractItemView, QMenu

from electrum.i18n import _
from electrum.names import format_name_identifier, format_name_value
from electrum.transaction import PartialTxInput
from electrum.util import NotEnoughFunds, NoDynamicFeeEstimates, bh2u
from electrum.wallet import InternalAddressCorruption

from .configure_name_dialog import show_configure_name
from .util import MyTreeView, ColorScheme, MONOSPACE_FONT
from .utxo_list import UTXOList

USER_ROLE_TXOUT = 0
USER_ROLE_NAME = 1
USER_ROLE_VALUE = 2

# TODO: It'd be nice if we could further reduce code duplication against
# UTXOList.
class UNOList(UTXOList):
    class Columns(IntEnum):
        NAME = 0
        VALUE = 1
        STATUS = 2

    headers = {
        Columns.NAME: _('Name'),
        Columns.VALUE: _('Value'),
        Columns.STATUS: _('Status'),
    }
    filter_columns = [Columns.NAME, Columns.VALUE]
    stretch_column = Columns.VALUE

    def update(self):
        self.network = self.parent.network
        super().update()

    def insert_utxo(self, idx, utxo: PartialTxInput):
        txid = utxo.prevout.txid.hex()
        vout = utxo.prevout.out_idx
        name_op = utxo.name_op
        if name_op is None:
            return

        height = utxo.block_height
        header_at_tip = self.network.blockchain().header_at_tip()

        if height is None or height <= 0:
            # TODO: Namecoin: Take into account the fact that transactions may
            # not be mined in the next block.
            blocks_until_mined = 1

            height_estimated = header_at_tip['block_height'] + blocks_until_mined
        else:
            height_estimated = height

        if 'name' not in name_op:
            # Upstream handles a name_new here, which doesn't exist in Xaya.
            assert False
        else:
            if height is not None and height > 0:
                # utxo is confirmed
                status = ''
            else:
                # utxo is name_update
                status = _('Update Pending')

        if 'name' in name_op:
            # utxo is name_anyupdate or a name_new that we've queued a name_firstupdate for
            name = name_op['name']
            formatted_name = format_name_identifier(name)
            value = name_op['value']
            formatted_value = format_name_value(value)
        else:
            # utxo is a name_new that we haven't queued a name_firstupdate for
            name = None
            formatted_name = ''
            value = None
            formatted_value = ''

        txout = txid + ":%d"%vout

        self._utxo_dict[txout] = utxo

        labels = [formatted_name, formatted_value, status]
        utxo_item = [QStandardItem(x) for x in labels]
        self.set_editability(utxo_item)

        utxo_item[self.Columns.NAME].setFont(QFont(MONOSPACE_FONT))
        utxo_item[self.Columns.VALUE].setFont(QFont(MONOSPACE_FONT))

        utxo_item[self.Columns.NAME].setData(txout, Qt.UserRole)
        utxo_item[self.Columns.NAME].setData(name, Qt.UserRole + USER_ROLE_NAME)
        utxo_item[self.Columns.NAME].setData(value, Qt.UserRole + USER_ROLE_VALUE)

        address = utxo.address
        if self.wallet.is_frozen_address(address) or self.wallet.is_frozen_coin(utxo):
            utxo_item[self.Columns.NAME].setBackground(ColorScheme.BLUE.as_color(True))
            if self.wallet.is_frozen_address(address) and self.wallet.is_frozen_coin(utxo):
                utxo_item[self.Columns.NAME].setToolTip(_('Address and coin are frozen'))
            elif self.wallet.is_frozen_address(address):
                utxo_item[self.Columns.NAME].setToolTip(_('Address is frozen'))
            elif self.wallet.is_frozen_coin(utxo):
                utxo_item[self.Columns.NAME].setToolTip(_('Coin is frozen'))
        self.model().appendRow(utxo_item)

    # TODO: Break out self.selected_in_column argument into its own attribute
    # so that we can subclass it without re-implementing
    # selected_column_0_user_roles
    def selected_column_0_user_roles(self) -> Optional[List[str]]:
        if not self.model():
            return None
        items = self.selected_in_column(self.Columns.NAME)
        if not items:
            return None
        return [x.data(Qt.UserRole) for x in items]

    # TODO: Break out self.selected_in_column argument into its own attribute
    # so that we can subclass it without re-implementing
    # selected_column_0_user_roles
    def selected_column_0_user_role_identifiers(self) -> Optional[List[bytes]]:
        if not self.model():
            return None
        items = self.selected_in_column(self.Columns.NAME)
        if not items:
            return None
        return [x.data(Qt.UserRole + USER_ROLE_NAME) for x in items]

    # TODO: Break out self.selected_in_column argument into its own attribute
    # so that we can subclass it without re-implementing
    # selected_column_0_user_roles
    def selected_column_0_user_role_values(self) -> Optional[List[bytes]]:
        if not self.model():
            return None
        items = self.selected_in_column(self.Columns.NAME)
        if not items:
            return None
        return [x.data(Qt.UserRole + USER_ROLE_VALUE) for x in items]

    # Using Coin Control to choose name inputs doesn't make sense, so disable
    # it.
    def set_spend_list(self, coins: Optional[List[PartialTxInput]]):
        super().set_spend_list(None)

    def create_menu(self, position):
        selected = self.selected_column_0_user_roles()
        if not selected:
            return
        menu = QMenu()

        if len(selected) == 1:
            txid = selected[0].split(':')[0]
            tx = self.wallet.db.transactions.get(txid)
            if tx:
                label = self.wallet.get_label(txid) or None # Prefer None if empty (None hides the Description: field in the window)
                menu.addAction(_("Configure"), lambda: self.configure_selected_item())
                menu.addAction(_("Transaction Details"), lambda: self.parent.show_transaction(tx, tx_desc=label))

        # "Copy ..."

        idx = self.indexAt(position)
        col = idx.column()
        if col == self.Columns.NAME:
            selected_data = self.selected_column_0_user_role_identifiers()
            selected_data_type = "identifier"
        elif col == self.Columns.VALUE:
            selected_data = self.selected_column_0_user_role_values()
            selected_data_type = "value"
        else:
            selected_data = None

        if selected_data is not None and len(selected_data) == 1:
            data = selected_data[0]
            # data will be None if this row is a name_new that we haven't
            # queued a name_firstupdate for, so we don't know the identifier or
            # value.
            if data is not None:
                try:
                    copy_ascii = data.decode('ascii')
                    menu.addAction(_("Copy {} as ASCII").format(selected_data_type), lambda: self.parent.app.clipboard().setText(copy_ascii))
                except UnicodeDecodeError:
                    pass
                copy_hex = bh2u(data)
                menu.addAction(_("Copy {} as hex").format(selected_data_type), lambda: self.parent.app.clipboard().setText(copy_hex))

        menu.exec_(self.viewport().mapToGlobal(position))

    def configure_selected_item(self):
        selected = self.selected_in_column(0)
        if not selected:
            return
        if len(selected) != 1:
            return

        item = selected[0]

        identifier = item.data(Qt.UserRole + USER_ROLE_NAME)
        # In Xaya, we do not want to keep the existing value, as values
        # are not about "state" but about "changes".
        initial_value = b"{}"

        show_configure_name(identifier, initial_value, self.parent, False)

