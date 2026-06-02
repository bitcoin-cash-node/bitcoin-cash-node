#!/usr/bin/env python3
# Copyright (c) 2025-2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test support for p2s which activates with Upgrade12."""
import random
from typing import List, NamedTuple, Optional

from test_framework import cashaddr
from test_framework.cdefs import MAX_P2S_SCRIPT_SIZE
from test_framework.blocktools import create_block, create_coinbase
from test_framework.key import ECKey
from test_framework.messages import (
    CBlock,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxOut,
    FromHex,
)
from test_framework.p2p import P2PDataStore
from test_framework import schnorr
from test_framework.script import (
    CScript,
    hash160,
    OP_CHECKSIG, OP_DROP, OP_DUP, OP_EQUALVERIFY, OP_FALSE, OP_HASH160, OP_TRUE,
    SIGHASH_ALL, SIGHASH_FORKID,
    SignatureHashForkId,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_not_equal


class UTXO(NamedTuple):
    outpt: COutPoint
    txout: CTxOut


class P2STest(BitcoinTestFramework):

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.base_extra_args = ['-acceptnonstdtxn=0', '-expire=0', '-whitelist=127.0.0.1']
        self.extra_args = [['-upgrade12activationheight=2000000000'] + self.base_extra_args]

    @staticmethod
    def get_rand_bytes(n_bytes: int = 32) -> bytes:
        assert n_bytes >= 0
        n_bits = n_bytes * 8
        return random.getrandbits(n_bits).to_bytes(length=n_bytes, byteorder='little')

    def run_test(self):
        node = self.nodes[0]  # convenience reference to the node
        self.bootstrap_p2p()  # add one p2p connection to the node

        # Setup a private key and address we will use for all transactions
        self.priv_key = ECKey()
        self.priv_key.set(secret=b'PayToScript!!!!!' * 2, compressed=True)
        self.pub_key = self.priv_key.get_pubkey().get_bytes()
        self.spk = CScript([OP_DUP, OP_HASH160, hash160(self.pub_key), OP_EQUALVERIFY, OP_CHECKSIG])
        self.p2pkh_addr = cashaddr.encode("bchreg", cashaddr.PUBKEY_TYPE, hash160(self.pub_key))

        # Some p2s scripts to test
        spk_op_false = CScript([self.get_rand_bytes(), OP_DROP, OP_FALSE])
        spk_op_true = CScript([self.get_rand_bytes(), OP_DROP, OP_TRUE])
        spk_op_true_at_limit = CScript([self.get_rand_bytes(MAX_P2S_SCRIPT_SIZE - 4), OP_DROP, OP_TRUE])
        assert_equal(len(spk_op_true_at_limit), MAX_P2S_SCRIPT_SIZE)
        spk_op_true_past_limit = CScript([self.get_rand_bytes(MAX_P2S_SCRIPT_SIZE + 1 - 4), OP_DROP, OP_TRUE])
        assert_equal(len(spk_op_true_past_limit), MAX_P2S_SCRIPT_SIZE + 1)

        # Attempt to send from the p2pkh in blocks above *to* a p2s; these will be rejected as non-standard
        p2s_spks = [spk_op_true, spk_op_false, spk_op_true_at_limit, spk_op_true_past_limit]
        p2s_spks_standard_spendable = [spk_op_true, spk_op_true_at_limit]
        p2s_spks_nonstandard_spendable = [spk_op_true_past_limit]
        p2s_spks_unspendable = [spk_op_false]

        # Generate blocks to our p2pkh for spending: p2pkh -> p2s
        blockhashes = node.generatetoaddress(len(p2s_spks), self.p2pkh_addr)

        # Generate blocks to our p2s spk's for spending: p2s -> p2kh
        p2s_blocks = []
        for spk in p2s_spks:
            if not p2s_blocks:
                prev_block = FromHex(CBlock(), node.getblock(blockhashes[-1], 0))
            else:
                prev_block = p2s_blocks[-1]
            p2s_blocks.append(self.create_block(prev_block, len(blockhashes) + len(p2s_blocks), scriptPubKey=spk))
        self.send_blocks(p2s_blocks)
        p2s_blockhashes = [b.hash for b in p2s_blocks]
        blockhashes += p2s_blockhashes

        # Generate 100 blocks to ensure maturity of above
        blockhashes += node.generatetoaddress(100, self.p2pkh_addr)

        def create_a_txn_spending_from_block(blockhash, from_spk, to_spk, *, sign=True) -> CTransaction:
            block = FromHex(CBlock(), node.getblock(blockhash, 0))
            tx = block.vtx[0]
            tx.calc_sha256()
            assert_equal(tx.vout[0].scriptPubKey.hex(), from_spk.hex())  # Sanity check
            utxo = UTXO(outpt=COutPoint(tx.sha256, 0), txout=tx.vout[0])
            return self.create_tx([utxo], [CTxOut(utxo.txout.nValue - 500, to_spk)], sign=sign)

        # Attempt to send from the p2pkh in blocks above *to* a p2s
        # Pre-activation: these will be rejected for non-standard outputs
        txns_send_to_p2s = []
        txns_send_to_standard_spendable_p2s = []
        txns_send_to_nonstandard_spendable_p2s = []
        txns_send_to_unspendable_p2s = []
        for i, p2s_spk in enumerate(p2s_spks):
            # Create the txn that spends from our p2pkh *to* a p2s
            tx = create_a_txn_spending_from_block(blockhashes[i], from_spk=self.spk, to_spk=p2s_spk)
            # Rejected as non-standard output (send to p2s is non-standard pre-activation)
            self.send_txs([tx], success=False, reject_reason='scriptpubkey')
            txns_send_to_p2s.append(tx)
            if p2s_spk in p2s_spks_standard_spendable:
                txns_send_to_standard_spendable_p2s.append(tx)
            elif p2s_spk in p2s_spks_nonstandard_spendable:
                txns_send_to_nonstandard_spendable_p2s.append(tx)
            else:
                assert p2s_spk in p2s_spks_unspendable
                txns_send_to_unspendable_p2s.append(tx)

        assert (txns_send_to_standard_spendable_p2s and txns_send_to_nonstandard_spendable_p2s
                and txns_send_to_unspendable_p2s)

        # Attempt to send *from* our p2s created above in blocks to a p2pkh
        # Pre-activation: these will be rejected for non-standard inputs
        txns_spend_from_p2s = []
        txns_spend_from_p2s_standard_spendable = []
        txns_spend_from_p2s_nonstandard_spendable = []
        txns_spend_from_p2s_unspendable = []
        for i, p2s_spk in enumerate(p2s_spks):
            # Create the txn that spends *from* a p2s to our p2pkh
            tx = create_a_txn_spending_from_block(p2s_blockhashes[i], from_spk=p2s_spk, to_spk=self.spk, sign=False)
            # Rejected as non-standard input (spend from p2s is non-standard pre-activation)
            self.send_txs([tx], success=False, reject_reason='bad-txns-nonstandard-inputs')
            txns_spend_from_p2s.append(tx)
            if p2s_spk in p2s_spks_standard_spendable:
                txns_spend_from_p2s_standard_spendable.append(tx)
            elif p2s_spk in p2s_spks_nonstandard_spendable:
                txns_spend_from_p2s_nonstandard_spendable.append(tx)
            else:
                assert p2s_spk in p2s_spks_unspendable
                txns_spend_from_p2s_unspendable.append(tx)

        # Ensure we have at least 1 txn in each set above
        assert (txns_spend_from_p2s_standard_spendable and txns_spend_from_p2s_nonstandard_spendable
                and txns_spend_from_p2s_unspendable)

        # Next, activate the upgrade

        # Get the current tip height and hash
        tip_hash = node.getblockchaininfo()["bestblockhash"]
        tip_height = node.getblockheader(tip_hash)["height"]
        # Restart the node, enabling upgrade12 as of the tip
        self.restart_node(0, extra_args=[f"-upgrade12activationheight={tip_height}"] + self.base_extra_args)
        self.reconnect_p2p()


        # Now, the txns that send to p2s standard should be accepted ok as "standard" post-activation
        self.send_txs(txns_send_to_standard_spendable_p2s)
        # Also txns that send to the "unspendable" spk are ok, even if the funds are forever "lost"
        self.send_txs(txns_send_to_unspendable_p2s)
        # Send to p2s that is beyond length limit should be rejected as non-standard
        for tx in txns_send_to_nonstandard_spendable_p2s:
            self.send_txs([tx], success=False, reject_reason='scriptpubkey')

        # Now, the txns that spend from p2s standard should be accepted ok as "standard"
        self.send_txs(txns_spend_from_p2s_standard_spendable)
        # Spend from p2s that is beyond length limit should be rejected as non-standard
        for tx in txns_spend_from_p2s_nonstandard_spendable:
            self.send_txs([tx], success=False, reject_reason='bad-txns-nonstandard-inputs')

        # Sanity check: spending the unspendable OP_FALSE p2s should be forbidden
        for tx in txns_spend_from_p2s_unspendable:
            self.send_txs([tx], success=False, reject_reason='Script evaluated without error but finished with a '
                                                             'false/empty top stack element')

        assert len(node.getrawmempool()) > 0

        # Confirm the above txns
        blockhashes += node.generatetoaddress(1, self.p2pkh_addr)

        assert len(node.getrawmempool()) == 0  # Ensure mempool is now empty (above txns confirmed in block)

        txns_nonstandard = txns_spend_from_p2s_nonstandard_spendable + txns_send_to_nonstandard_spendable_p2s

        # Now, create a block containing the spendable non-standard txns (All are p2s > 201 byte scriptPubKey)
        block = self.create_block(
            prev_block=FromHex(CBlock(), node.getblock(blockhashes[-1], 0)),
            height=node.getblockchaininfo()['blocks'],
            txns=txns_nonstandard)

        self.send_blocks([block], success=True, timeout=5)
        blockhashes.append(block.hash)

        # Now, create a block containing the unspendable txns -- should be rejected!
        block = self.create_block(
            prev_block=FromHex(CBlock(), node.getblock(blockhashes[-1], 0)),
            height=node.getblockchaininfo()['blocks'],
            txns=txns_spend_from_p2s_unspendable)

        self.send_blocks([block], success=False, timeout=5)
        assert_not_equal(block.hash, node.getbestblockhash())

    def create_tx(self, inputs: List[UTXO], outputs: List[CTxOut], *, sign=True, sigtype='schnorr'):
        """Assumption: all inputs owned by self.priv_key"""
        tx = CTransaction()
        total_value = 0
        utxos = []
        for outpt, txout in inputs:
            utxos.append(txout)
            total_value += txout.nValue
            tx.vin.append(CTxIn(outpt))
        for out in outputs:
            total_value -= out.nValue
            assert total_value >= 0
            tx.vout.append(out)
        if sign:
            hashtype = SIGHASH_ALL | SIGHASH_FORKID
            for i in range(len(tx.vin)):
                inp = tx.vin[i]
                utxo = utxos[i]
                # Sign the transaction
                hashbyte = bytes([hashtype & 0xff])
                scriptcode = utxo.scriptPubKey
                sighash = SignatureHashForkId(scriptcode, tx, i, hashtype, utxo.nValue)
                txsig = b''
                if sigtype == 'schnorr':
                    txsig = schnorr.sign(self.priv_key.get_bytes(), sighash) + hashbyte
                elif sigtype == 'ecdsa':
                    txsig = self.priv_key.sign_ecdsa(sighash) + hashbyte
                pushes = [txsig, self.priv_key.get_pubkey().get_bytes()]
                inp.scriptSig = CScript(pushes)
        tx.rehash()
        return tx

    @staticmethod
    def create_block(prev_block: CBlock, height: int, *, nTime: Optional[int] = None, txns=None, scriptPubKey=None) -> CBlock:
        if prev_block.sha256 is None:
            prev_block.rehash()
        assert prev_block.sha256 is not None  # Satisfy linter with this assertion
        prev_block_hash = prev_block.sha256
        block_time = prev_block.nTime + 1 if nTime is None else nTime
        # Create the coinbase (pays out to OP_TRUE or scriptPubKey)
        coinbase = create_coinbase(height, scriptPubKey=scriptPubKey)

        txns = txns or []
        block = create_block(prev_block_hash, coinbase, block_time, txns=txns)
        block.solve()
        return block

    def bootstrap_p2p(self):
        """Add a P2P connection to the node.

        Helper to connect and wait for version handshake."""
        self.nodes[0].add_p2p_connection(P2PDataStore())
        # We need to wait for the initial getheaders from the peer before we
        # start populating our blockstore. If we don't, then we may run ahead
        # to the next subtest before we receive the getheaders. We'd then send
        # an INV for the next block and receive two getheaders - one for the
        # IBD and one for the INV. We'd respond to both and could get
        # unexpectedly disconnected if the DoS score for that error is 50.
        self.nodes[0].p2p.wait_for_getheaders(timeout=5)

    def reconnect_p2p(self):
        """Tear down and bootstrap the P2P connection to the node.

        The node gets disconnected several times in this test. This helper
        method reconnects the p2p and restarts the network thread."""
        bs, lbh, ts, p2p = None, None, None, None
        if self.nodes[0].p2ps:
            p2p = self.nodes[0].p2p
            bs, lbh, ts = p2p.block_store, p2p.last_block_hash, p2p.tx_store
        self.nodes[0].disconnect_p2ps()
        self.bootstrap_p2p()
        if p2p and (bs or lbh or ts):
            # Set up the block store again so that p2p node can adequately send headers again for everything
            # node might want after a restart
            p2p = self.nodes[0].p2p
            p2p.block_store, p2p.last_block_hash, p2p.tx_store = bs, lbh, ts

    def send_txs(self, txs, success=True, reject_reason=None, reconnect=False):
        """Sends txns to test node. Syncs and verifies that txns are in mempool

        Call with success = False if the txns should be rejected."""
        self.nodes[0].p2p.send_txs_and_test(txs, self.nodes[0], success=success, expect_disconnect=reconnect,
                                            reject_reason=reject_reason)
        if reconnect:
            self.reconnect_p2p()

    def send_blocks(self, blocks, success=True, reject_reason=None,
                    request_block=True, reconnect=False, timeout=60):
        """Sends blocks to test node. Syncs and verifies that tip has advanced to most recent block.

        Call with success = False if the tip shouldn't advance to the most recent block."""
        self.nodes[0].p2p.send_blocks_and_test(blocks, self.nodes[0], success=success,
                                               reject_reason=reject_reason, request_block=request_block,
                                               timeout=timeout, expect_disconnect=reconnect)
        if reconnect:
            self.reconnect_p2p()


if __name__ == '__main__':
    P2STest().main()
