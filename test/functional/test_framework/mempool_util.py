#!/usr/bin/env python3
# Copyright (c) 2024-present The Bitcoin Core developers
# Copyright (c) 2024-present The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Helpful routines for mempool testing."""
from .messages import CTransaction
from .test_framework import TestNode

ORPHAN_TX_EXPIRE_TIME = 1200


def tx_in_orphanage(node: TestNode, tx: CTransaction) -> bool:
    """Returns true if the transaction is in the orphanage."""
    found = [o for o in node.getorphantxs(verbosity=1) if o["txid"] == tx.get_id()]
    return len(found) > 0
