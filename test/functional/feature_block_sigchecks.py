#!/usr/bin/env python3
# Copyright (c) 2020-present The Bitcoin Developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Test block sigchecks limits
"""

from test_framework.blocktools import (
    create_block,
    create_coinbase,
    make_conform_to_ctor,
)
from test_framework.cdefs import (
    BLOCK_MAXBYTES_MAXSIGCHECKS_RATIO
)
from test_framework.messages import (
    CBlock,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxOut,
    FromHex,
)
from test_framework.p2p import P2PDataStore
from test_framework.script import (
    CScript,
    OP_CHECKDATASIGVERIFY,
    OP_3DUP,
    OP_RETURN,
    OP_TRUE,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.txtools import pad_tx
from test_framework.util import assert_equal
from collections import deque

# We are going to use a tiny block size so we don't need to waste too much
# time with making transactions. (note -- minimum block size is 1000000)
# (just below a multiple, to test edge case)
FORCEBLOCKSIZE = 8000 * BLOCK_MAXBYTES_MAXSIGCHECKS_RATIO - 1
assert FORCEBLOCKSIZE == 1127999
MAXGENERATEDBLOCKSIZE = 1000000

# Blocks with too many sigchecks from cache give this error in log file:
BLOCK_SIGCHECKS_CACHED_ERROR = "blk-bad-inputs, CheckInputs exceeded SigChecks limit"
# Blocks with too many sigchecks discovered during parallel checks give
# this error in log file:
BLOCK_SIGCHECKS_PARALLEL_ERROR = "blk-bad-inputs, parallel script check failed"


def create_transaction(spendfrom, custom_script, amount=None):
    # Fund and sign a transaction to a given output.
    # spendfrom should be a CTransaction with first output to OP_TRUE.

    # custom output will go on position 1, after position 0 which will be
    # OP_TRUE (so it can be reused).
    customout = CTxOut(0, bytes(custom_script))
    # set output amount to required dust if not given
    customout.nValue = amount or (len(customout.serialize()) + 148) * 3

    ctx = CTransaction()
    ctx.vin.append(CTxIn(COutPoint(spendfrom.sha256, 0), b''))
    ctx.vout.append(
        CTxOut(0, bytes([OP_TRUE])))
    ctx.vout.append(customout)
    pad_tx(ctx)

    fee = len(ctx.serialize())
    ctx.vout[0].nValue = spendfrom.vout[0].nValue - customout.nValue - fee
    ctx.rehash()

    return ctx


def check_for_ban_on_rejected_tx(node, tx, reject_reason=None):
    """Check we are disconnected when sending a txn that the node rejects,
    then reconnect after.

    (Can't actually get banned, since bitcoind won't ban local peers.)"""
    node.p2p.send_txs_and_test(
        [tx], node, success=False, expect_disconnect=True, reject_reason=reject_reason)
    node.disconnect_p2ps()
    node.add_p2p_connection(P2PDataStore())


def check_for_ban_on_rejected_block(node, block, reject_reason=None):
    """Check we are disconnected when sending a block that the node rejects,
    then reconnect after.

    (Can't actually get banned, since bitcoind won't ban local peers.)"""
    node.p2p.send_blocks_and_test(
        [block], node, success=False, reject_reason=reject_reason, expect_disconnect=True)
    node.disconnect_p2ps()
    node.add_p2p_connection(P2PDataStore())


def check_for_no_ban_on_rejected_tx(node, tx, reject_reason=None):
    """Check we are not disconnected when sending a txn that the node rejects."""
    node.p2p.send_txs_and_test(
        [tx], node, success=False, reject_reason=reject_reason)


class BlockSigChecksTest(BitcoinTestFramework):

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.block_heights = {}
        self.base_extra_args = ['-acceptnonstdtxn=1']
        # Note that -forceblocksize also disables ABLA
        self.extra_args = [self.base_extra_args +
                           ["-forceblocksize={}".format(FORCEBLOCKSIZE),
                            "-blockmaxsize={}".format(MAXGENERATEDBLOCKSIZE)]]

    def getbestblock(self, node):
        """Get the best block. Register its height so we can use build_block."""
        block_height = node.getblockcount()
        blockhash = node.getblockhash(block_height)
        block = FromHex(CBlock(), node.getblock(blockhash, 0))
        block.calc_sha256()
        self.block_heights[block.sha256] = block_height
        return block

    def build_block(self, parent, transactions=(),
                    nTime=None):
        """Make a new block with an OP_1 coinbase output.

        Requires parent to have its height registered."""
        parent.calc_sha256()
        block_height = self.block_heights[parent.sha256] + 1
        block_time = (parent.nTime + 1) if nTime is None else nTime

        block = create_block(
            parent.sha256, create_coinbase(block_height), block_time)
        block.vtx.extend(transactions)
        make_conform_to_ctor(block)
        block.hashMerkleRoot = block.calc_merkle_root()
        block.solve()
        self.block_heights[block.sha256] = block_height
        return block

    def run_test(self):
        [node] = self.nodes
        node.add_p2p_connection(P2PDataStore())
        # Get out of IBD
        self.generatetoaddress(node, 1, node.get_deterministic_priv_key().address)

        tip = self.getbestblock(node)

        self.log.info("Create some blocks with OP_1 coinbase for spending.")
        blocks = []
        for _ in range(20):
            tip = self.build_block(tip)
            blocks.append(tip)
        node.p2p.send_blocks_and_test(blocks, node, success=True)
        self.spendable_outputs = deque(block.vtx[0] for block in blocks)

        self.log.info("Mature the blocks.")
        self.generatetoaddress(node, 100, node.get_deterministic_priv_key().address)

        tip = self.getbestblock(node)

        # To make compact and fast-to-verify transactions, we'll use
        # CHECKDATASIG over and over with the same data.
        # (Using the same stuff over and over again means we get to hit the
        # node's signature cache and don't need to make new signatures every
        # time.)
        cds_message = b''
        # r=1 and s=1 ecdsa, the minimum values.
        cds_signature = bytes.fromhex('3006020101020101')
        # Recovered pubkey
        cds_pubkey = bytes.fromhex(
            '03089b476b570d66fad5a20ae6188ebbaf793a4c2a228c65f3d79ee8111d56c932')

        def minefunding2(n):
            """ Mine a block with a bunch of outputs that are very dense
            sigchecks when spent (2 sigchecks each); return the inputs that can
            be used to spend. """
            cds_scriptpubkey = CScript(
                [cds_message, cds_pubkey, OP_3DUP, OP_CHECKDATASIGVERIFY, OP_CHECKDATASIGVERIFY])
            # The scriptsig is carefully padded to have size 26, which is the
            # shortest allowed for 2 sigchecks for mempool admission.
            # The resulting inputs have size 67 bytes, 33.5 bytes/sigcheck.
            cds_scriptsig = CScript([b'x' * 16, cds_signature])
            assert_equal(len(cds_scriptsig), 26)

            self.log.debug("Gen {} with locking script {} unlocking script {} .".format(
                n, cds_scriptpubkey.hex(), cds_scriptsig.hex()))

            tx = self.spendable_outputs.popleft()
            usable_inputs = []
            txes = []
            for _ in range(n):
                tx = create_transaction(tx, cds_scriptpubkey)
                txes.append(tx)
                usable_inputs.append(
                    CTxIn(COutPoint(tx.sha256, 1), cds_scriptsig))
            newtip = self.build_block(tip, txes)
            node.p2p.send_blocks_and_test([newtip], node)
            return usable_inputs, newtip

        self.log.info("Funding special coins that have high sigchecks")

        # mine 5000 funded outputs (10000 sigchecks)
        usable_inputs, tip = minefunding2(5000)
        # assemble them into 50 txes with 100 inputs each (200 sigchecks)
        submittxes_1 = []
        while len(usable_inputs) >= 100:
            tx = CTransaction()
            tx.vin = [usable_inputs.pop() for _ in range(100)]
            tx.vout = [CTxOut(0, CScript([OP_RETURN]))]
            tx.rehash()
            submittxes_1.append(tx)

        # mine 5000 funded outputs (10000 sigchecks)
        usable_inputs, tip = minefunding2(5000)
        # assemble them into 50 txes with 100 inputs each (200 sigchecks)
        submittxes_2 = []
        while len(usable_inputs) >= 100:
            tx = CTransaction()
            tx.vin = [usable_inputs.pop() for _ in range(100)]
            tx.vout = [CTxOut(0, CScript([OP_RETURN]))]
            tx.rehash()
            submittxes_2.append(tx)

        node.p2p.send_txs_and_test(submittxes_1, node)

        # Transactions all in pool:
        assert_equal(set(node.getrawmempool()), {t.hash for t in submittxes_1})

        # Send block with all these txes (too much sigchecks)
        badblock = self.build_block(tip, submittxes_1)
        blocksize = len(badblock.serialize())
        assert blocksize < FORCEBLOCKSIZE
        self.log.info("Try sending {}-byte, 10000-sigcheck blocks (limit: {}, {})".format(
            blocksize, FORCEBLOCKSIZE, FORCEBLOCKSIZE // BLOCK_MAXBYTES_MAXSIGCHECKS_RATIO))
        check_for_ban_on_rejected_block(
            node, badblock, reject_reason=BLOCK_SIGCHECKS_CACHED_ERROR)

        self.log.info(
            "There are too many sigchecks in mempool to mine in a single block. Make sure the node won't mine invalid blocks.")
        self.generatetoaddress(node, 1, node.get_deterministic_priv_key().address)
        tip = self.getbestblock(node)
        # only 39 txes got mined.
        assert_equal(len(node.getrawmempool()), 11)

        self.log.info("Try sending 10000-sigcheck block with fresh transactions (limit: {})".format(
            FORCEBLOCKSIZE // BLOCK_MAXBYTES_MAXSIGCHECKS_RATIO))
        # Note: in the following tests we'll be bumping timestamp in order
        # to bypass any kind of 'bad block' cache on the node, and get a
        # fresh evaluation each time.

        # Try another block with 10000 sigchecks but all fresh transactions
        badblock = self.build_block(
            tip, submittxes_2, nTime=tip.nTime + 5)
        check_for_ban_on_rejected_block(
            node, badblock, reject_reason=BLOCK_SIGCHECKS_PARALLEL_ERROR)

        # Send the same txes again with different block hash. Currently we don't
        # cache valid transactions in invalid blocks so nothing changes.
        badblock = self.build_block(
            tip, submittxes_2, nTime=tip.nTime + 6)
        check_for_ban_on_rejected_block(
            node, badblock, reject_reason=BLOCK_SIGCHECKS_PARALLEL_ERROR)

        # Put all the txes in mempool, in order to get them cached:
        node.p2p.send_txs_and_test(submittxes_2, node)
        # Send them again, the node still doesn't like it. But the log
        # error message has now changed because the txes failed from cache.
        badblock = self.build_block(
            tip, submittxes_2, nTime=tip.nTime + 7)
        check_for_ban_on_rejected_block(
            node, badblock, reject_reason=BLOCK_SIGCHECKS_CACHED_ERROR)

        self.log.info("Try sending 8000-sigcheck block (limit: {})".format(
            FORCEBLOCKSIZE // BLOCK_MAXBYTES_MAXSIGCHECKS_RATIO))
        badblock = self.build_block(
            tip, submittxes_2[:40], nTime=tip.nTime + 8)
        check_for_ban_on_rejected_block(
            node, badblock, reject_reason=BLOCK_SIGCHECKS_CACHED_ERROR)

        self.log.info("Bump the forceblocksize limit by 1 byte, and send another block with same txes (new sigchecks limit: {})".format(
            (FORCEBLOCKSIZE + 1) // BLOCK_MAXBYTES_MAXSIGCHECKS_RATIO))
        self.stop_node(0)
        self.extra_args = [self.base_extra_args +
                           ["-forceblocksize={}".format(FORCEBLOCKSIZE + 1),
                            "-blockmaxsize={}".format(MAXGENERATEDBLOCKSIZE)]]
        self.start_node(0)
        node.add_p2p_connection(P2PDataStore())
        self.sync_all()
        tip = self.build_block(
            tip, submittxes_2[:40], nTime=tip.nTime + 9)
        # It should succeed now since limit should be 8000.
        node.p2p.send_blocks_and_test([tip], node)


if __name__ == '__main__':
    BlockSigChecksTest().main()
