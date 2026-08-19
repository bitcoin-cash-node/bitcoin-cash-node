#!/usr/bin/env python3
# Copyright (c) 2014-2015 The Bitcoin Core developers
# Copyright (c) 2015-2017 The Bitcoin Unlimited developers
# Copyright (c) 2020-present The Bitcoin developers
#
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test validateblocktemplate RPC call. Adapted from BCHUnlimited
test for BCHN specific behavior (slightly different error strings
in some cases, not all functionality supported, like setminingmaxblocksize"""

import random
import time

from test_framework.authproxy import JSONRPCException
from test_framework.blocktools import (
    create_block,
    bu_create_coinbase,
)
from test_framework.key import ECKey
from test_framework.messages import (
    CTransaction,
    COutPoint,
    CTxIn,
    CTxOut,
    ToHex,
    COIN,
)
from test_framework.script import (
    CScript,
    OP_1,
    OP_CHECKSIG,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_raises_rpc_error


PADDED_ANY_SPEND = b'\x61' * 50  # add a bunch of OP_NOPs to make sure this tx is long enough


def create_transaction(prevtx, n, sig, value, out=PADDED_ANY_SPEND):
    """
    Create a transaction with an anyone-can-spend output, that spends the
    nth output of prevtx.  pass a single integer value to make one output,
    or a list to create multiple outputs
    """
    prevtx.calc_sha256()
    if not type(value) is list:
        value = [value]
    tx = CTransaction()
    assert n < len(prevtx.vout)
    tx.vin.append(CTxIn(COutPoint(prevtx.sha256, n), sig, 0xffffffff))
    for v in value:
        tx.vout.append(CTxOut(v, out))
    tx.calc_sha256()
    return tx


def create_broken_transaction(prevtx, n, sig, value, out=PADDED_ANY_SPEND):
    """
    Create a transaction with an anyone-can-spend output, that spends the
    nth output of prevtx.  pass a single integer value to make one output,
    or a list to create multiple outputs
    This version allows broken transactions to be constructed which
    refer to inputs indices that are not in the prevtx's vout.
    """
    if not type(value) is list:
        value = [value]
    tx = CTransaction()
    tx.vin.append(CTxIn(COutPoint(prevtx.sha256, n), sig, 0xffffffff))
    for v in value:
        tx.vout.append(CTxOut(v, out))
    tx.calc_sha256()
    return tx


class ValidateblocktemplateTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        # self.extra_args = [["-debug=all"],
        #                    ["-debug=all"]]
        # Need a bit of extra time when running with the thread sanitizer
        self.rpc_timeout = 120

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        # Generate enough blocks to trigger certain block votes and activate BIP65 (version 4 blocks)
        amt = 1352 - self.nodes[0].getblockcount()
        for i in range(int(amt / 100)):
            self.generate(self.nodes[0], 100)
            self.sync_all()

        self.generate(self.nodes[0], 1352 - self.nodes[0].getblockcount())
        self.sync_all()

        self.log.info("checking: not on chain tip")
        badtip = self.nodes[0].getblockhash(self.nodes[0].getblockcount() - 1)
        height = self.nodes[0].getblockcount()
        tip = self.nodes[0].getblockhash(height)

        coinbase = bu_create_coinbase(height + 1)
        cur_time = int(time.time())
        self.nodes[0].setmocktime(cur_time)
        self.nodes[1].setmocktime(cur_time)

        block = create_block(badtip, coinbase, cur_time + 600)
        block.nVersion = 0x20000000
        block.rehash()

        hexblk = ToHex(block)
        assert_raises_rpc_error(-25, "Invalid block: does not build on chain tip",
                                self.nodes[0].validateblocktemplate, hexblk)

        self.log.info("checking: time too far in the past")
        block = create_block(tip, coinbase, cur_time - 100)
        block.nVersion = 0x20000000
        block.rehash()
        hexblk = ToHex(block)
        assert_raises_rpc_error(-25, "Invalid block: time-too-old",
                                self.nodes[0].validateblocktemplate, hexblk)

        self.log.info("checking: time too far in the future")
        block = create_block(tip, coinbase, cur_time + 10000000)
        block.nVersion = 0x20000000
        block.rehash()
        hexblk = ToHex(block)
        assert_raises_rpc_error(-25, "Invalid block: time-too-new",
                                self.nodes[0].validateblocktemplate, hexblk)

        self.log.info("checking: bad version 1")
        block = create_block(tip, coinbase, cur_time + 600)
        block.nVersion = 1
        block.rehash()
        hexblk = ToHex(block)
        assert_raises_rpc_error(-25, "Invalid block: bad-version",
                                self.nodes[0].validateblocktemplate, hexblk)

        self.log.info("checking: bad version 2")
        block = create_block(tip, coinbase, cur_time + 600)
        block.nVersion = 2
        block.rehash()
        hexblk = ToHex(block)
        assert_raises_rpc_error(-25, "Invalid block: bad-version",
                                self.nodes[0].validateblocktemplate, hexblk)

        self.log.info("checking: bad version 3")
        block = create_block(tip, coinbase, cur_time + 600)
        block.nVersion = 3
        block.rehash()
        hexblk = ToHex(block)
        assert_raises_rpc_error(-25, "Invalid block: bad-version",
                                self.nodes[0].validateblocktemplate, hexblk)

        # Note: 'bad-cb-height' test case cannot be tested , because regtest
        #        always has BIP34 checks disabled.

        self.log.info("checking: bad merkle root")
        block = create_block(tip, coinbase, cur_time + 600)
        block.nVersion = 0x20000000
        block.hashMerkleRoot = 0x12345678
        block.rehash()
        hexblk = ToHex(block)
        assert_raises_rpc_error(-25, "Invalid block: bad-txnmrklroot",
                                self.nodes[0].validateblocktemplate, hexblk)

        self.log.info("checking: no tx")
        block = create_block(tip, None, cur_time + 600)
        block.nVersion = 0x20000000
        block.rehash()
        hexblk = ToHex(block)
        assert_raises_rpc_error(-25, "Invalid block: bad-cb-missing",
                                self.nodes[0].validateblocktemplate, hexblk)

        self.log.info("checking: good block")
        block = create_block(tip, coinbase, cur_time + 600)
        block.nVersion = 0x20000000
        block.rehash()
        hexblk = ToHex(block)

        # validate good block
        self.nodes[0].validateblocktemplate(hexblk)
        block.solve()
        hexblk = ToHex(block)
        self.nodes[0].submitblock(hexblk)
        self.sync_all()

        prev_block = block
        # out_value is less than 50BTC because regtest halvings happen every 150 blocks, and is in Satoshis
        out_value = block.vtx[0].vout[0].nValue
        tx1 = create_transaction(prev_block.vtx[0], 0, b'\x61' * 50 + b'\x51', [int(out_value / 2), int(out_value / 2)])
        height = self.nodes[0].getblockcount()
        tip = self.nodes[0].getblockhash(height)
        coinbase = bu_create_coinbase(height + 1)
        next_time = cur_time + 1200

        self.log.info("checking: no coinbase")
        block = create_block(tip, None, next_time, txns=[tx1])
        block.nVersion = 0x20000000
        block.rehash()
        hexblk = ToHex(block)
        assert_raises_rpc_error(-25, "Invalid block: bad-cb-missing",
                                self.nodes[0].validateblocktemplate, hexblk)

        self.log.info("checking: double coinbase")
        coinbase_key = ECKey()
        # coinbase_key.set_secretbytes(b"horsebattery")
        coinbase_key.set(b"horsbatt" * 4, True)
        coinbase_pubkey = coinbase_key.get_pubkey()

        coinbase2 = bu_create_coinbase(height + 1, coinbase_pubkey.get_bytes())
        block = create_block(tip, coinbase, next_time, txns=[coinbase2, tx1])
        block.nVersion = 0x20000000
        block.rehash()
        hexblk = ToHex(block)
        assert_raises_rpc_error(-25, "Invalid block: bad-tx-coinbase",
                                self.nodes[0].validateblocktemplate, hexblk)

        self.log.info("checking: premature coinbase spend")
        block = create_block(tip, coinbase, next_time, txns=[tx1])
        block.nVersion = 0x20000000
        block.rehash()
        hexblk = ToHex(block)
        assert_raises_rpc_error(-25, "Invalid block: bad-txns-premature-spend-of-coinbase",
                                self.nodes[0].validateblocktemplate, hexblk)

        self.generate(self.nodes[0], 100)
        self.sync_all()
        height = self.nodes[0].getblockcount()
        tip = self.nodes[0].getblockhash(height)
        coinbase = bu_create_coinbase(height + 1)
        next_time = cur_time + 1200

        op1 = CScript([OP_1])

        self.log.info("checking: inputs below outputs")
        tx6 = create_transaction(prev_block.vtx[0], 0, op1, [out_value + 1000])
        block = create_block(tip, coinbase, next_time, txns=[tx6])
        block.nVersion = 0x20000000
        block.rehash()
        hexblk = ToHex(block)
        assert_raises_rpc_error(-25, "Invalid block: bad-txns-in-belowout",
                                self.nodes[0].validateblocktemplate, hexblk)

        tx5 = create_transaction(prev_block.vtx[0], 0, op1, [int(21000001 * COIN)])
        self.log.info("checking: money range")
        block = create_block(tip, coinbase, next_time, txns=[tx5])
        block.nVersion = 0x20000000
        block.rehash()
        hexblk = ToHex(block)
        assert_raises_rpc_error(-25, "Invalid block: bad-txns-vout-toolarge",
                                self.nodes[0].validateblocktemplate, hexblk)

        self.log.info("checking: bad tx offset")
        tx_bad = create_broken_transaction(prev_block.vtx[0], 1, op1, [int(out_value / 4)])
        block = create_block(tip, coinbase, next_time, txns=[tx_bad])
        block.nVersion = 0x20000000
        block.rehash()
        hexblk = ToHex(block)
        assert_raises_rpc_error(-25, "Invalid block: bad-txns-inputs-missingorspent",
                                self.nodes[0].validateblocktemplate, hexblk)

        self.log.info("checking: bad tx offset largest number")
        tx_bad = create_broken_transaction(prev_block.vtx[0], 0xffffffff, op1, [int(out_value / 4)])
        block = create_block(tip, coinbase, next_time, txns=[tx_bad])
        block.nVersion = 0x20000000
        block.rehash()
        hexblk = ToHex(block)
        assert_raises_rpc_error(-25, "Invalid block: bad-txns-inputs-missingorspent",
                                self.nodes[0].validateblocktemplate, hexblk)

        self.log.info("checking: double tx")
        tx2 = create_transaction(prev_block.vtx[0], 0, op1, [int(out_value / 4)])
        block = create_block(tip, coinbase, next_time, txns=[tx2, tx2])
        block.nVersion = 0x20000000
        block.rehash()
        hexblk = ToHex(block)
        assert_raises_rpc_error(-25, "Invalid block: tx-duplicate",
                                self.nodes[0].validateblocktemplate, hexblk)

        tx3 = create_transaction(prev_block.vtx[0], 0, op1, [int(out_value / 9), int(out_value / 10)])
        tx4 = create_transaction(prev_block.vtx[0], 0, op1, [int(out_value / 8), int(out_value / 7)])
        self.log.info("checking: double spend")
        block = create_block(tip, coinbase, next_time, txns=[tx3, tx4])
        block.nVersion = 0x20000000
        block.rehash()
        hexblk = ToHex(block)
        assert_raises_rpc_error(-25, "Invalid block: bad-txns-inputs-missingorspent",
                                self.nodes[0].validateblocktemplate, hexblk)

        txes = [tx3, tx4]
        txes.sort(key=lambda x: x.hash, reverse=True)
        self.log.info("checking: bad tx ordering")
        block = create_block(tip, coinbase, next_time, txns=txes, ctor=False)
        block.nVersion = 0x20000000
        block.rehash()
        hexblk = ToHex(block)
        assert_raises_rpc_error(-25, "Invalid block: tx-ordering",
                                self.nodes[0].validateblocktemplate, hexblk)

        tx_good = create_transaction(prev_block.vtx[0], 0, b'\x51', [int(out_value / 50)] * 50, out=b"")
        self.log.info("checking: good tx")
        block = create_block(tip, coinbase, next_time, txns=[tx_good])
        block.nVersion = 0x20000000
        block.rehash()
        block.solve()
        hexblk = ToHex(block)
        self.nodes[0].validateblocktemplate(hexblk)
        self.nodes[0].submitblock(hexblk)

        self.sync_all()

        height = self.nodes[0].getblockcount()
        tip = self.nodes[0].getblockhash(height)
        coinbase = bu_create_coinbase(height + 1)
        next_time = next_time + 600

        coinbase_key = ECKey()
        # coinbase_key.set_secretbytes(b"horsebattery")
        coinbase_key.set(b"horsbatt" * 4, True)
        coinbase_pubkey = coinbase_key.get_pubkey()
        #coinbase3 = bu_create_coinbase(height + 1, coinbase_pubkey)
        bu_create_coinbase(height + 1, coinbase_pubkey.get_bytes())

        txl = []
        for i in range(0, 50):
            ov = block.vtx[1].vout[i].nValue
            txl.append(create_transaction(block.vtx[1], i, op1, [int(ov / 50)] * 50))
        block = create_block(tip, coinbase, next_time, txns=txl)
        block.nVersion = 0x20000000
        block.rehash()
        block.solve()
        hexblk = ToHex(block)
        for n in self.nodes:
            n.validateblocktemplate(hexblk)

        # Note: BCHN does not have RPC method like BU's 'setminingmaxblocksize' yet,
        # therefore we omit some test cases related to excessive block size when
        # modifying that setting on the fly.
        #
        # The related BU error messages that we do not test for here are:
        # - RPC error 25, message: "Invalid block: excessive"
        # - RPC error 25, message: "Sorry, your maximum mined block (1000) is larger than your proposed excessive size (999).  This would cause you to orphan your own blocks."

        # Randomly change bytes
        for it in range(0, 100):
            h2 = hexblk
            pos = random.randint(0, len(hexblk))
            val = random.randint(0, 15)
            h3 = h2[:pos] + ('{:x}'.format(val)) + h2[pos + 1:]
            try:
                self.nodes[0].validateblocktemplate(h3)
            except JSONRPCException as e:
                if e.error["code"] in (-1, -22, -25):
                    self.log.info(f"Got expected exception: " + str(e))
                else:
                    self.log.exception(f"Failed for iteration {it}")
                # its ok we expect garbage

        self.nodes[1].submitblock(hexblk)
        self.sync_all()

        height = self.nodes[0].getblockcount()
        tip = self.nodes[0].getblockhash(height)
        coinbase = bu_create_coinbase(height + 1)
        next_time = next_time + 600
        prev_block = block
        txl = []
        for tx in prev_block.vtx:
            for outp in range(0, len(tx.vout)):
                ov = tx.vout[outp].nValue
                txl.append(create_transaction(tx, outp, CScript([OP_CHECKSIG] * 100), [int(ov / 2)] * 2))
        block = create_block(tip, coinbase, next_time, txns=txl)
        block.nVersion = 0x20000000
        block.rehash()
        block.solve()
        hexblk = ToHex(block)
        for n in self.nodes:
            assert_raises_rpc_error(-25, "Invalid block: bad-txns-premature-spend-of-coinbase",
                                    self.nodes[0].validateblocktemplate, hexblk)


if __name__ == '__main__':
    ValidateblocktemplateTest().main()
