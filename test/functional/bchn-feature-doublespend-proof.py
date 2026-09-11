#!/usr/bin/env python3
# Copyright (c) 2020-present The Bitcoin Cash Node developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
""" Test for the DoubleSpend Proof facility """

import os
from decimal import Decimal

from test_framework.address import base58_to_byte
from test_framework.blocktools import create_raw_transaction, create_tx_with_script
from test_framework.key import ECKey
from test_framework.messages import CTransaction, FromHex, ToHex, COIN, msg_mempool, msg_dsproof
from test_framework.p2p import P2PInterface, p2p_lock
from test_framework.script import CScript, OP_TRUE, OP_FALSE, SignatureHashForkIdFromValues
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_greater_than, assert_equal, assert_raises, assert_raises_rpc_error, connect_nodes, disconnect_nodes,
    find_output, wait_until
)


def getSighashes(prevOutput, spender, fundingtx):
    return SignatureHashForkIdFromValues(
        spender.txVersion,
        spender.hashPrevOutputs,
        spender.hashSequence,
        prevOutput,
        fundingtx.vout[0].scriptPubKey,
        fundingtx.vout[0].nValue,
        spender.outSequence,
        spender.hashOutputs,
        spender.lockTime,
        spender.pushData[0][-1]  # last byte is hashType
    )


class DoubleSpendProofTest(BitcoinTestFramework):
    def set_test_params(self):
        # We need >= 2 nodes because submitting a double spend through a single
        # node will still be refused before reaching mempool
        self.num_nodes = 4
        self.extra_args = [
            ['-acceptnonstdtxn=1'],
            ['-acceptnonstdtxn=1'],
            ['-acceptnonstdtxn=1'],
            ['-acceptnonstdtxn=1', '-doublespendproof=0']]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def getpubkey(self):
        # we will spend a coinbase transaction from node[0] which was
        # pre-mined for us by the framework to the deterministic privkey.
        # We now construct a pubkey for that
        base58privkey = self.nodes[0].get_deterministic_priv_key().key
        privkeybytes, v = base58_to_byte(base58privkey)
        privkey = ECKey()
        privkey.set(privkeybytes[:-1], True)
        return privkey.get_pubkey()

    @staticmethod
    def get_dsp_bytes(node):
        """Returns a tuple of dsproof-msg bytes sent, received"""
        return (sum(x.get('bytessent_per_msg', {}).get('dsproof-beta', 0) for x in node.getpeerinfo()),
                sum(x.get('bytesrecv_per_msg', {}).get('dsproof-beta', 0) for x in node.getpeerinfo()))

    def run_test(self):
        class P2PInterfaceRequestsMempoolOnConnect(P2PInterface):
            mempool_sent = False

            def on_verack(self, message):
                super().on_verack(message)
                if not self.mempool_sent:
                    # We send the mempool message initially because we want to catch a regression.
                    # See issue #481: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/issues/481
                    self.mempool_sent = True
                    self.send_message(msg_mempool())

        # create a p2p receiver
        dspReceiver = P2PInterface()
        dspReceiver2 = P2PInterfaceRequestsMempoolOnConnect()
        self.nodes[0].add_p2p_connection(dspReceiver)
        self.nodes[0].add_p2p_connection(dspReceiver2)
        # workaround - nodes think they're in IBD unless one block is mined
        self.generate(self.nodes[0], 1)
        self.sync_all()
        # Disconnect the third node, will be used later for triple-spend
        disconnect_nodes(self.nodes[1], self.nodes[2])
        # Put fourth node (the non-dsproof-enabled node) with the connected group
        # (we will check its log at the end to ensure it ignored dsproof inv's)
        non_dsproof_node = self.nodes[3]
        disconnect_nodes(self.nodes[2], non_dsproof_node)
        connect_nodes(self.nodes[1], non_dsproof_node)

        for node in self.nodes:
            # Ensure msg byte counts for dsproof-beta messages start out as expected
            assert_equal((0, 0), self.get_dsp_bytes(node))

        # Create and mine a regular non-coinbase transaction for spending
        fundingtxid = self.nodes[0].getblock(self.nodes[0].getblockhash(1))['tx'][0]
        fundingtx = FromHex(CTransaction(), self.nodes[0].getrawtransaction(fundingtxid))

        # Create three conflicting transactions. They are only signed, but not yet submitted to the mempool
        firstDSTx = create_raw_transaction(self.nodes[0], fundingtxid, self.nodes[0].getnewaddress(), 49.95)
        secondDSTx = create_raw_transaction(self.nodes[0], fundingtxid, self.nodes[0].getnewaddress(), 49.95)
        thirdDSTx = create_raw_transaction(self.nodes[0], fundingtxid, self.nodes[0].getnewaddress(), 49.95)

        # Send the two conflicting transactions to the network
        # Submit to two different nodes, because a node would simply reject
        # a double spend submitted through RPC
        firstDSTxId = self.nodes[0].sendrawtransaction(firstDSTx)
        self.nodes[1].call_rpc('sendrawtransaction', secondDSTx, ignore_error='txn-mempool-conflict')
        wait_until(
            lambda: dspReceiver.message_count["dsproof-beta"] == 1 and dspReceiver2.message_count["dsproof-beta"] == 1,
            lock=p2p_lock,
            timeout=25
        )

        b0 = self.get_dsp_bytes(self.nodes[0])
        b1 = self.get_dsp_bytes(self.nodes[1])
        self.log.info(f"Verifying dsproof-beta byte counts: node0={b0} node1={b1} ...")
        assert_greater_than(b0[0], 0)  # Ensure that node0 sent byte count > 0 (it send to python p2p nodes)
        assert_greater_than(b0[1] + b1[1], 0)  # Either node0 or node1 received a dsproof, ensure byte count went up.
        assert_equal(self.get_dsp_bytes(non_dsproof_node)[1], 0)  # non-dsproof node should not have gotten any dsproof

        # 1. The DSP message is well-formed and contains all fields
        # If the message arrived and was deserialized successfully, then 1. is satisfied
        dsp = dspReceiver.last_message["dsproof-beta"].dsproof
        dsp_other = dspReceiver2.last_message["dsproof-beta"].dsproof
        assert_equal(dsp.serialize().hex(), dsp_other.serialize().hex())
        # Check that the node complains in the log if given a dsp it already knows about
        with self.nodes[0].assert_debug_log(expected_msgs=["a DSP already exists for this outpoint"], timeout=10):
            dspReceiver.send_message(msg_dsproof(dsp))
        dsps = set()
        dsps.add(dsp.serialize())

        # Check that it is valid, both spends are signed with the same key
        # NB: pushData is made of the sig + one last byte for hashtype
        pubkey = self.getpubkey()
        sighash1 = getSighashes(dsp.getPrevOutput(), dsp.spender1, fundingtx)
        sighash2 = getSighashes(dsp.getPrevOutput(), dsp.spender2, fundingtx)
        assert pubkey.verify_ecdsa(dsp.spender1.pushData[0][:-1], sighash1)
        assert pubkey.verify_ecdsa(dsp.spender2.pushData[0][:-1], sighash2)

        # 2. For p2pkh these is exactly one pushdata per spender
        assert_equal(1, len(dsp.spender1.pushData))
        assert_equal(1, len(dsp.spender2.pushData))

        # 3. The two spenders are different, specifically the signature (push data) has to be different.
        assert dsp.spender1.pushData != dsp.spender2.pushData

        # 4. The first & double spenders are sorted with two hashes as keys.
        assert dsp.spender1.hashOutputs < dsp.spender2.hashOutputs

        # 5. The double spent output is still available in the UTXO database,
        #    implying no spending transaction has been mined.
        assert_equal(self.nodes[0].gettransaction(firstDSTxId)["confirmations"], 0)

        # The original fundingtx is the same as the transaction being spent reported by the DSP
        assert_equal(hex(dsp.prevTxId)[2:], fundingtxid)
        assert_equal(dsp.prevOutIndex, 0)

        # 6. No other valid proof is known.
        #    IE if a valid proof is known, no new proofs will be constructed
        #    We submit a _triple_ spend transaction to the third node
        connect_nodes(self.nodes[0], self.nodes[2])
        self.nodes[2].call_rpc('sendrawtransaction', thirdDSTx, ignore_error='txn-mempool-conflict')
        #    Await for a new dsp to be relayed to the node
        #    if such a dsp (or the double or triple spending tx) arrives, the test fails
        assert_raises(
            AssertionError,
            wait_until,
            lambda: dspReceiver.message_count["dsproof-beta"] == 2 or dspReceiver.message_count["tx"] == 2,
            lock=p2p_lock,
            timeout=5
        )

        # Only P2PKH inputs are protected
        # Check that a non-P2PKH output is not protected
        self.generate(self.nodes[0], 1)
        fundingtxid = self.nodes[0].getblock(self.nodes[0].getblockhash(2))['tx'][0]
        fundingtx = FromHex(CTransaction(), self.nodes[0].getrawtransaction(fundingtxid))
        fundingtx.rehash()
        nonP2PKHTx = create_tx_with_script(fundingtx, 0, b'', int(49.95 * COIN), CScript([OP_TRUE]))
        signedNonP2PKHTx = self.nodes[0].signrawtransactionwithwallet(ToHex(nonP2PKHTx))
        self.nodes[0].sendrawtransaction(signedNonP2PKHTx['hex'])
        self.sync_all()

        tx = FromHex(CTransaction(), signedNonP2PKHTx['hex'])
        tx.rehash()

        firstDSTx = create_tx_with_script(tx, 0, b'', int(49.90 * COIN), CScript([OP_TRUE]))
        secondDSTx = create_tx_with_script(tx, 0, b'', int(49.90 * COIN), CScript([OP_FALSE]))

        self.nodes[0].sendrawtransaction(ToHex(firstDSTx))
        self.nodes[1].call_rpc('sendrawtransaction', ToHex(secondDSTx), ignore_error='txn-mempool-conflict')

        assert_raises(
            AssertionError,
            wait_until,
            lambda: dspReceiver.message_count["dsproof-beta"] == 2 and dspReceiver2.message_count["dsproof-beta"] == 2,
            lock=p2p_lock,
            timeout=5
        )

        # Check that unconfirmed outputs are also protected
        self.generate(self.nodes[0], 1)
        unconfirmedtx = self.nodes[0].sendtoaddress(self.nodes[0].getnewaddress(), 25)
        self.sync_all()

        firstDSTx = create_raw_transaction(self.nodes[0], unconfirmedtx, self.nodes[0].getnewaddress(), 24.9)
        secondDSTx = create_raw_transaction(self.nodes[0], unconfirmedtx, self.nodes[0].getnewaddress(), 24.9)

        self.nodes[0].sendrawtransaction(firstDSTx)
        self.nodes[1].call_rpc('sendrawtransaction', secondDSTx, ignore_error='txn-mempool-conflict')

        wait_until(
            lambda: dspReceiver.message_count["dsproof-beta"] == 2 and dspReceiver2.message_count["dsproof-beta"] == 2,
            lock=p2p_lock,
            timeout=5
        )
        dsp2 = dspReceiver.last_message["dsproof-beta"].dsproof
        dsps.add(dsp2.serialize())
        assert len(dsps) == 2

        # Check that a double spent tx, which has some non-P2PKH inputs
        # in its ancestor, still results in a dsproof being emitted.
        self.generate(self.nodes[0], 1)
        # Create a 1-of-2 multisig address which will be an in-mempool
        # ancestor to a double-spent tx
        pubkey0 = self.nodes[0].getaddressinfo(
            self.nodes[0].getnewaddress())['pubkey']
        pubkey1 = self.nodes[1].getaddressinfo(
            self.nodes[1].getnewaddress())['pubkey']
        p2sh = self.nodes[0].addmultisigaddress(1, [pubkey0, pubkey1], "")['address']
        # Fund the p2sh address
        fundingtxid = self.nodes[0].sendtoaddress(p2sh, 49)
        vout = find_output(self.nodes[0], fundingtxid, Decimal('49'))
        self.sync_all()

        # Spend from the P2SH to a P2PKH, which we will double spend from
        # in the next step.
        p2pkh1 = self.nodes[0].getnewaddress()
        rawtx1 = create_raw_transaction(self.nodes[0], fundingtxid, p2pkh1, 48.999, vout)
        signed_tx1 = self.nodes[0].signrawtransactionwithwallet(rawtx1)
        txid1 = self.nodes[0].sendrawtransaction(signed_tx1['hex'])
        vout1 = find_output(self.nodes[0], txid1, Decimal('48.999'))
        self.sync_all()

        # Now double spend the P2PKH which has a P2SH ancestor.
        firstDSTx = create_raw_transaction(self.nodes[0], txid1, self.nodes[0].getnewaddress(), 48.9, vout1)
        secondDSTx = create_raw_transaction(self.nodes[0], txid1, self.nodes[1].getnewaddress(), 48.9, vout1)
        self.nodes[0].sendrawtransaction(firstDSTx)
        self.nodes[1].call_rpc('sendrawtransaction', secondDSTx, ignore_error='txn-mempool-conflict')

        # We still get a dsproof, showing that not all ancestors have
        # to be P2PKH.
        wait_until(
            lambda: dspReceiver.message_count["dsproof-beta"] == 3 and dspReceiver2.message_count["dsproof-beta"] == 3,
            lock=p2p_lock,
            timeout=5
        )
        dsp3 = dspReceiver.last_message["dsproof-beta"].dsproof
        dsps.add(dsp3.serialize())
        assert len(dsps) == 3

        # Check that a double spent tx, which has some unconfirmed ANYONECANPAY
        # transactions in its ancestry, still results in a dsproof being emitted.
        self.generate(self.nodes[0], 1)
        fundingtxid = self.nodes[0].getblock(self.nodes[0].getblockhash(5))['tx'][0]
        vout1 = find_output(self.nodes[0], fundingtxid, Decimal('50'))
        addr = self.nodes[1].getnewaddress()
        pubkey = self.nodes[1].getaddressinfo(addr)['pubkey']
        inputs = [
            {'txid': fundingtxid,
             'vout': vout1, 'amount': 49.99,
             'scriptPubKey': pubkey}
        ]
        outputs = {addr: 49.99}
        rawtx = self.nodes[0].createrawtransaction(inputs, outputs)
        signed = self.nodes[0].signrawtransactionwithwallet(rawtx,
                                                            None,
                                                            "NONE|FORKID|ANYONECANPAY")
        assert 'complete' in signed
        assert_equal(signed['complete'], True)
        assert 'errors' not in signed
        txid = self.nodes[0].sendrawtransaction(signed['hex'])
        self.sync_all()
        # The ANYONECANPAY is still unconfirmed, but let's create some
        # double spends from it.
        vout2 = find_output(self.nodes[0], txid, Decimal('49.99'))
        firstDSTx = create_raw_transaction(self.nodes[1], txid, self.nodes[0].getnewaddress(), 49.98, vout2)
        secondDSTx = create_raw_transaction(self.nodes[1], txid, self.nodes[1].getnewaddress(), 49.98, vout2)
        self.nodes[0].sendrawtransaction(firstDSTx)
        self.nodes[1].call_rpc('sendrawtransaction', secondDSTx, ignore_error='txn-mempool-conflict')
        # We get a dsproof.
        wait_until(
            lambda: dspReceiver.message_count["dsproof-beta"] == 4 and dspReceiver2.message_count["dsproof-beta"] == 4,
            lock=p2p_lock,
            timeout=5
        )
        dsp4 = dspReceiver.last_message["dsproof-beta"].dsproof
        dsps.add(dsp4.serialize())
        assert len(dsps) == 4

        # Create a P2SH to double-spend directly (1-of-1 multisig)
        self.generate(self.nodes[0], 1)
        self.sync_all()
        pubkey2 = self.nodes[0].getaddressinfo(
            self.nodes[0].getnewaddress())['pubkey']
        p2sh = self.nodes[0].addmultisigaddress(1, [pubkey2, ], "")['address']
        fundingtxid = self.nodes[0].sendtoaddress(p2sh, 49)
        vout = find_output(self.nodes[0], fundingtxid, Decimal('49'))
        self.sync_all()
        # Now double spend it
        firstDSTx = create_raw_transaction(self.nodes[0], fundingtxid, self.nodes[0].getnewaddress(), 48.9, vout)
        secondDSTx = create_raw_transaction(self.nodes[0], fundingtxid, self.nodes[1].getnewaddress(), 48.9, vout)
        self.nodes[0].sendrawtransaction(firstDSTx)
        self.nodes[1].call_rpc('sendrawtransaction', secondDSTx, ignore_error='txn-mempool-conflict')
        # No dsproof is generated.
        assert_raises(
            AssertionError,
            wait_until,
            lambda: dspReceiver.message_count["dsproof-beta"] == 5 and dspReceiver2.message_count["dsproof-beta"] == 5,
            lock=p2p_lock,
            timeout=5
        )

        # Check end conditions - still only 4 DSPs
        last_dsp = dspReceiver.last_message["dsproof-beta"].dsproof
        dsps.add(last_dsp.serialize())
        assert len(dsps) == 4

        # Next, test that submitting a double-spend via the RPC interface also results in a broadcasted
        # dsproof
        self.generate(self.nodes[0], 1)
        self.sync_all()
        fundingtxid = self.nodes[0].getblock(self.nodes[0].getblockhash(6))['tx'][0]
        # Create 2 new double-spends
        firstDSTx = create_raw_transaction(self.nodes[0], fundingtxid, self.nodes[0].getnewaddress(), 49.95)
        secondDSTx = create_raw_transaction(self.nodes[0], fundingtxid, self.nodes[0].getnewaddress(), 49.95)

        # Send the two conflicting transactions to the same node via RPC
        assert_equal(dspReceiver.message_count["dsproof-beta"], 4)
        firstDSTxId = self.nodes[0].sendrawtransaction(firstDSTx)
        # send second tx to same node via RPC
        # -- it's normal for it to reject the tx, but it should still generate a dsproof broadcast
        assert_raises_rpc_error(
            -26,
            "txn-mempool-conflict (code 18)",
            self.nodes[0].sendrawtransaction,
            secondDSTx
        )
        wait_until(
            lambda: dspReceiver.message_count["dsproof-beta"] == 5 and dspReceiver2.message_count["dsproof-beta"] == 5,
            lock=p2p_lock,
            timeout=5
        )

        # Ensure that the non-dsproof node has the messages we expect in its log
        # (this checks that dsproof was disabled for this node)
        debug_log = os.path.join(non_dsproof_node.datadir, self.chain, 'debug.log')
        dsp_inv_ctr = 0
        with open(debug_log, encoding='utf-8') as dl:
            for line in dl.readlines():
                if "Got DSProof INV" in line:
                    # Ensure that if this node did see a dsproof inv, it explicitly ignored it
                    assert "(ignored, -doublespendproof=0)" in line
                    dsp_inv_ctr += 1
                else:
                    # Ensure this node is not processing dsproof messages and not requesting them via getdata
                    assert ("received: dsproof-beta" not in line and "Good DSP" not in line
                            and "DSP broadcasting" not in line and "bad-dsproof" not in line)
        # We expect it to have received at least some DSP inv broadcasts
        assert_greater_than(dsp_inv_ctr, 0)

        # Finally test that restarting the node persists the dsproof
        # - ensure nodes 0 & 1 saw the dsp
        assert self.nodes[0].getdsproof(firstDSTxId) is not None
        wait_until(
            lambda: self.nodes[1].getdsproof(firstDSTxId) is not None,
            timeout=10
        )

        # Node 1 will have a deleted dsproofs.dat, check that we get the error message we expect
        # and that the proof won't come back.
        with self.nodes[1].assert_debug_log(
                expected_msgs=['Imported mempool transactions from disk',
                               'Failed to open dsproofs file on disk. Continuing anyway.'],
                timeout=60):
            dsproofs_dat = os.path.join(self.nodes[1].datadir, self.chain, 'dsproofs.dat')
            self.stop_node(1)
            # remove the dsproofs.dat file to keep the proof from coming back
            os.remove(dsproofs_dat)
            self.start_node(1, self.extra_args[1])
        # Node 1 has no dsproofs.dat it should forget the dsproof after a restart.
        assert self.nodes[1].getdsproof(firstDSTxId) is None

        # Node 0 -- default behavior; it should still see the dsproof for the txid after a restart.
        # Wait for the debug log to say that the expected number of dsproofs were loaded without error
        with self.nodes[0].assert_debug_log(expected_msgs=['Imported dsproofs from disk: 5'], timeout=60):
            self.restart_node(0, self.extra_args[0])
        wait_until(
            lambda: self.nodes[0].getdsproof(firstDSTxId) is not None,
            timeout=60,
        )


if __name__ == '__main__':
    DoubleSpendProofTest().main()
