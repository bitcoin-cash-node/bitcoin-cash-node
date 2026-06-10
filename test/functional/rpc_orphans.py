#!/usr/bin/env python3
# Copyright (c) 2014-2024 The Bitcoin Core developers
# Copyright (c) 2024-present The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Tests for orphan related RPCs."""

import time
from typing import List, NamedTuple, Optional, Tuple

from test_framework.address import scripthash_to_p2sh
from test_framework.mempool_util import ORPHAN_TX_EXPIRE_TIME, tx_in_orphanage
from test_framework.messages import CBlock, COutPoint, CTransaction, CTxIn, CTxOut, FromHex
from test_framework.p2p import P2PDataStore
from test_framework.script import CScript, hash160, OP_DROP, OP_EQUAL, OP_HASH160, OP_RETURN, OP_TRUE
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class UTXO(NamedTuple):
    outpt: COutPoint
    txout: CTxOut


class OrphanRPCsTest(BitcoinTestFramework):

    redeem_script = CScript([b"Some padding for GetOrphanTxsTest", OP_DROP, OP_TRUE])
    addr_hash = hash160(redeem_script)
    p2sh_address = scripthash_to_p2sh(addr_hash)
    spk = CScript([OP_HASH160, addr_hash, OP_EQUAL])
    script_sig = CScript([redeem_script])

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def bootstrap_p2p(self, *, num_connections=1):
        """Add a P2P connection to the node.

        Helper to connect and wait for version handshake."""
        for _ in range(num_connections):
            self.nodes[0].add_p2p_connection(P2PDataStore())
        for p2p in self.nodes[0].p2ps:
            p2p.wait_for_getheaders()

    def update_utxos(self, spend_tx: CTransaction, *, utxos: Optional[List[UTXO]] = None):
        """Updates utxos with the effects of spend_tx. If utxos is None, updates self.utxos
        Deletes spent utxos, creates new UTXOs for spend_tx.vout"""
        if utxos is None:
            utxos = self.utxos  # Update the class attribute it not specified which list to update
        i = 0
        spent_ins = set()
        for inp in spend_tx.vin:
            spent_ins.add((inp.prevout.hash, inp.prevout.n))
        # Delete spends
        while i < len(utxos):
            outpt, txout = utxos[i]
            if (outpt.hash, outpt.n) in spent_ins:
                del utxos[i]
                continue
            i += 1
        # Update new unspents
        spend_tx.calc_sha256()
        for i, txout in enumerate(spend_tx.vout):
            if txout.scriptPubKey == self.spk:
                utxos.append(UTXO(COutPoint(spend_tx.sha256, i), txout))

    def run_test(self):
        node = self.nodes[0]
        # Setup 2 coinbase utxos for us to spend
        blockhashes = node.generatetoaddress(102, self.p2sh_address)
        self.utxos = []
        # Grab coinbase UTXOs from first 2 blocks
        for block_hash in blockhashes[:2]:
            block = FromHex(CBlock(), node.getblock(block_hash, 0))
            tx = block.vtx[0]
            tx.calc_sha256()
            self.update_utxos(tx)

        # Setup p2p
        self.bootstrap_p2p(num_connections=2)

        # Run tests
        self.test_orphan_activity()
        self.test_orphan_details()
        self.test_misc()

    def create_self_send(self, utxo: UTXO, opreturn: Optional[bytes] = None, update_utxos: Optional[List[UTXO]] = None,
                         fee_sats=1000) -> CTransaction:
        tx = CTransaction()
        tx.vin.append(CTxIn(outpoint=utxo.outpt, scriptSig=self.script_sig))
        if opreturn is not None:
            tx.vout.append(CTxOut(nValue=0, scriptPubKey=CScript([OP_RETURN, opreturn])))
        tx.vout.append(CTxOut(nValue=utxo.txout.nValue - fee_sats, scriptPubKey=self.spk))
        tx.rehash()
        if update_utxos is not None:
            self.update_utxos(tx, utxos=update_utxos)
        return tx

    def create_1p_1c_txns(self, tospend: UTXO) -> Tuple[CTransaction, CTransaction]:
        tx_parent = self.create_self_send(utxo=tospend)
        utxo_parent = UTXO(COutPoint(tx_parent.sha256, 0), tx_parent.vout[0])
        tx_child = self.create_self_send(utxo=utxo_parent)
        return tx_parent, tx_child

    def test_orphan_activity(self):
        self.log.info("Check that orphaned transactions are returned with getorphantxs")
        node = self.nodes[0]

        self.log.info("Create two 1P1C packages, but only broadcast the children")
        tx_parent_1, tx_child_1 = self.create_1p_1c_txns(self.utxos[0])
        tx_parent_2, tx_child_2 = self.create_1p_1c_txns(self.utxos[1])

        node.p2p.send_txs_and_test([tx_child_1, tx_child_2], node, success=False)

        self.log.info("Check that neither parent is in the mempool")
        assert_equal(node.getmempoolinfo()["size"], 0)

        self.log.info("Check the size of the orphanage")
        orphanage = node.getorphantxs(verbosity=0)
        assert_equal(len(orphanage), 2)

        self.log.info("Check that undefined verbosity is disallowed")
        assert_raises_rpc_error(-8, "Invalid verbosity value -1", node.getorphantxs, verbosity=-1)
        assert_raises_rpc_error(-8, "Invalid verbosity value 3", node.getorphantxs, verbosity=3)

        self.log.info("Check that both children are in the orphanage")
        assert tx_in_orphanage(node, tx_child_1)
        assert tx_in_orphanage(node, tx_child_2)

        self.log.info("Broadcast parent 1")
        node.p2p.send_txs_and_test([tx_parent_1], node, success=True)
        self.log.info("Check that parent 1 and child 1 are in the mempool")
        raw_mempool = node.getrawmempool()
        assert_equal(len(raw_mempool), 2)
        assert tx_parent_1.get_id() in raw_mempool
        assert tx_child_1.get_id() in raw_mempool

        self.log.info("Check that orphanage only contains child 2")
        orphanage = node.getorphantxs()
        assert_equal(len(orphanage), 1)
        assert tx_in_orphanage(node, tx_child_2)

        node.p2p.send_txs_and_test([tx_parent_2], node, success=True)
        self.log.info("Check that all parents and children are now in the mempool")
        raw_mempool = node.getrawmempool()
        assert_equal(len(raw_mempool), 4)
        assert tx_parent_1.get_id() in raw_mempool
        assert tx_child_1.get_id() in raw_mempool
        assert tx_parent_2.get_id() in raw_mempool
        assert tx_child_2.get_id() in raw_mempool
        self.log.info("Check that the orphanage is empty")
        assert_equal(len(node.getorphantxs()), 0)

        self.log.info("Confirm the transactions (clears mempool)")
        self.generatetoaddress(node, 1, self.p2sh_address)
        assert_equal(node.getmempoolinfo()["size"], 0)

        # Finally, log the utxo changes
        self.update_utxos(tx_parent_1)
        self.update_utxos(tx_child_1)
        self.update_utxos(tx_parent_2)
        self.update_utxos(tx_child_2)

    def test_orphan_details(self):
        self.log.info("Check the transaction details returned from getorphantxs")
        node = self.nodes[0]

        self.log.info("Create two orphans, from different peers")
        tx_parent_1, tx_child_1 = self.create_1p_1c_txns(self.utxos[0])
        tx_parent_2, tx_child_2 = self.create_1p_1c_txns(self.utxos[1])
        peer_1 = node.p2ps[0]
        peer_2 = node.p2ps[1]
        entry_time = int(time.time())
        node.setmocktime(entry_time)
        peer_1.send_txs_and_test([tx_child_1], node, success=False)
        peer_2.send_txs_and_test([tx_child_2], node, success=False)

        orphanage = node.getorphantxs(verbosity=2)
        assert tx_in_orphanage(node, tx_child_1)
        assert tx_in_orphanage(node, tx_child_2)

        self.log.info("Check that orphan 1 and 2 were from different peers")
        assert orphanage[0]["from"][0] != orphanage[1]["from"][0]

        self.log.info("Unorphan child 2")
        peer_2.send_txs_and_test([tx_parent_2], node, success=True)
        assert not tx_in_orphanage(node, tx_child_2)

        self.log.info("Checking orphan details")
        orphanage = node.getorphantxs(verbosity=1)
        assert_equal(len(node.getorphantxs()), 1)
        orphan_1 = orphanage[0]
        self.orphan_details_match(orphan_1, tx_child_1, verbosity=1)
        self.log.info("Checking orphan entry/expiration times")
        assert_equal(orphan_1["entry"], entry_time)
        assert_equal(orphan_1["expiration"], entry_time + ORPHAN_TX_EXPIRE_TIME)

        self.log.info("Checking orphan details (verbosity 2)")
        orphanage = node.getorphantxs(verbosity=2)
        orphan_1 = orphanage[0]
        self.orphan_details_match(orphan_1, tx_child_1, verbosity=2)

    def orphan_details_match(self, orphan: dict, tx: CTransaction, verbosity):
        self.log.info("Check txid of orphan")
        assert_equal(orphan["txid"], tx.get_id())

        self.log.info("Check the sizes of orphan")
        assert_equal(orphan["bytes"], len(tx.serialize()))

        if verbosity == 2:
            self.log.info("Check the transaction hex of orphan")
            assert_equal(orphan["hex"], tx.serialize().hex())

    def test_misc(self):
        node = self.nodes[0]
        assert_raises_rpc_error(-3, "Verbosity was boolean but only integer allowed", node.getorphantxs, verbosity=True)
        assert_raises_rpc_error(-3, "Verbosity was boolean but only integer allowed", node.getorphantxs, verbosity=False)
        help_output = node.help()
        self.log.info("Check that getorphantxs is a hidden RPC")
        assert "getorphantxs" not in help_output
        assert "unknown command: getorphantxs" not in node.help("getorphantxs")


if __name__ == '__main__':
    OrphanRPCsTest().main()
