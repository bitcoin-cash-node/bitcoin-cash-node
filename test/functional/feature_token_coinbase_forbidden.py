#!/usr/bin/env python3
# Copyright (c) 2022-2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test that ensures coinbase txns may create "fake" token data outputs pre-activation, as well as outputs that send to
token.PREFIX_BYTE scriptPubKeys, but post-activation no tokens or scriptPubKeys that begins with token.PREFIX_BYTE may
be mined. Also the "fake" tokens created pre-activation are PATFOs and cannot be spent either pre or post-activation."""
from collections import defaultdict, namedtuple
import random
from typing import DefaultDict, List, Union

from test_framework import address
from test_framework.blocktools import create_block, create_coinbase
from test_framework.key import ECKey
from test_framework.messages import (
    CBlock,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxOut,
    FromHex,
    token,
    TokenOutputData,
    uint256_from_str,
    ser_uint256,
)
from test_framework.p2p import P2PDataStore
from test_framework import schnorr
from test_framework.script import (
    CScript,
    hash160,
    OP_CHECKSIG, OP_DUP, OP_EQUALVERIFY, OP_HASH160, OP_TRUE, SPECIAL_TOKEN_PREFIX,
    SIGHASH_ALL, SIGHASH_FORKID,
    SignatureHashForkId,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal, assert_greater_than, assert_greater_than_or_equal,
    wait_until,
)

DUST = 546


def uint256_from_hex(h: str) -> int:
    return uint256_from_str(bytes.fromhex(h)[::-1])


def uint256_to_hex(u: int) -> str:
    return ser_uint256(u)[::-1].hex()


class UTXO(namedtuple("UTXO", "outpt, txout")):
    pass


class TokenCoinbaseForbiddenTest(BitcoinTestFramework):

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.base_extra_args = ['-acceptnonstdtxn=0', '-expire=0', '-whitelist=127.0.0.1']
        # Need to force-disable upgrade12 as it interferes with the pre-activation portion of this test
        self.base_extra_args += ['-upgrade12activationheight=999999999']
        self.extra_args = [['-upgrade9activationheight=999999999'] + self.base_extra_args]

    def run_test(self):

        node = self.nodes[0]  # convenience reference to the node
        self.bootstrap_p2p()  # add one p2p connection to the node

        # Setup a private key and address we will use for all transactions
        self.priv_key = ECKey()
        self.priv_key.set(secret=b'TokensInCoinbaseAreDisallowedBud', compressed=True)
        self.addr = address.key_to_p2pkh(self.priv_key.get_pubkey().get_bytes())
        self.spk = CScript([OP_DUP, OP_HASH160,
                            hash160(self.priv_key.get_pubkey().get_bytes()),
                            OP_EQUALVERIFY, OP_CHECKSIG])

        # Mine a block to get out of IBD
        blockhashes = node.generatetoaddress(1, self.addr)
        nTime = FromHex(CBlock(), node.getblock(blockhashes[-1], 0)).nTime + 1
        height = node.getblockchaininfo()["blocks"] + 1


        # Create a PATFO in coinbase pre-activation, should work ok
        bad_token = TokenOutputData(id=random.getrandbits(256), amount=1000, commitment=b'Bad!!',
                                    bitfield=token.Structure.HasAmount | token.Structure.HasNFT
                                             | token.Structure.HasCommitmentLength | token.Capability.Mutable)
        block = self.create_block(blockhashes[-1], height, nTime=nTime, token_data=bad_token)
        bad_token_coinbase_tx = block.vtx[0]
        bad_token_coinbase_tx.calc_sha256()
        self.send_blocks([block])
        wait_until(lambda: block.hash == node.getbestblockhash(), timeout=60)
        blockhashes.append(block.hash)
        height += 1
        nTime += 1

        # Create an output in coinbase that pays out to a scriptPubKey that contains unparseable token data
        unparseable_token_data_spk = CScript([SPECIAL_TOKEN_PREFIX, OP_TRUE])
        block = self.create_block(blockhashes[-1], height, nTime=nTime, script_pub_key=unparseable_token_data_spk)
        unparseable_token_coinbase_tx = block.vtx[0]
        unparseable_token_coinbase_tx.calc_sha256()
        self.send_blocks([block])
        wait_until(lambda: block.hash == node.getbestblockhash(), timeout=60)
        blockhashes.append(block.hash)
        height += 1
        nTime += 1

        # Generate 101 blocks to allow for our coinbase txns to be mature
        blockhashes += node.generatetoaddress(101, self.addr)
        nTime = FromHex(CBlock(), node.getblock(blockhashes[-1], 0)).nTime + 1
        height = node.getblockchaininfo()["blocks"] + 1

        # Attempt to spend the coinbase txns that contain token data/unparseable token data via mempool path
        send_bad_token_coinbase_tx = self.create_tx(inputs=[UTXO(COutPoint(bad_token_coinbase_tx.sha256, 0),
                                                                 bad_token_coinbase_tx.vout[0])],
                                                    outputs=[CTxOut(bad_token_coinbase_tx.vout[0].nValue-500,
                                                                    self.spk, tokenData=bad_token)])
        self.send_txs([send_bad_token_coinbase_tx], success=False, reject_reason='txn-tokens-before-activation')
        burn_bad_token_coinbase_tx = self.create_tx(inputs=[UTXO(COutPoint(bad_token_coinbase_tx.sha256, 0),
                                                                 bad_token_coinbase_tx.vout[0])],
                                                    outputs=[CTxOut(bad_token_coinbase_tx.vout[0].nValue-500,
                                                                    self.spk)])
        self.send_txs([burn_bad_token_coinbase_tx], success=False, reject_reason='bad-txns-nonstandard-inputs')
        send_unparseable_token_coinbase_tx = self.create_tx(inputs=[UTXO(COutPoint(unparseable_token_coinbase_tx.sha256,
                                                                                   0),
                                                                         unparseable_token_coinbase_tx.vout[0])],
                                                            outputs=[CTxOut(unparseable_token_coinbase_tx.vout[0].nValue
                                                                            - 500,
                                                                            self.spk)])
        self.send_txs([send_unparseable_token_coinbase_tx], success=False, reject_reason='bad-txns-nonstandard-inputs')

        # Attempt to spend the coinbase txns that contain token data/unparseable token data via mining to blocks
        block = self.create_block(blockhashes[-1], height, nTime=nTime, txns=[send_bad_token_coinbase_tx])
        self.send_blocks([block], success=False, reject_reason='bad-txns-vin-tokenprefix-preactivation')
        block = self.create_block(blockhashes[-1], height, nTime=nTime, txns=[burn_bad_token_coinbase_tx])
        self.send_blocks([block], success=False, reject_reason='bad-txns-vin-tokenprefix-preactivation')
        block = self.create_block(blockhashes[-1], height, nTime=nTime, txns=[send_unparseable_token_coinbase_tx])
        self.send_blocks([block], success=False, reject_reason='bad-txns-vin-tokenprefix-preactivation')

        # --- Activate Upgrade9 ---

        # 1. Set the activation MTP height a bit forward of the current tip's height
        activation_height = node.getblockchaininfo()["blocks"] + 1
        self.log.info(f"ACTIVATION HEIGHT: {activation_height}")
        # 2. Restart the node, enabling upgrade9
        self.restart_node(0, extra_args=[f"-upgrade9activationheight={activation_height}"] + self.base_extra_args)
        self.reconnect_p2p()

        # Mine blocks until it activates
        def mine_a_block():
            nonlocal height, nTime
            ablock = self.create_block(blockhashes[-1], height=height, nTime=nTime)
            height += 1
            nTime += 1
            self.send_blocks([ablock])
            assert_equal(node.getbestblockhash(), ablock.hash)
            blockhashes.append(ablock.hash)

        while node.getblockchaininfo()["blocks"] < activation_height:
            mine_a_block()

        # Ensure it activated exactly on this block
        assert_greater_than_or_equal(node.getblockchaininfo()["blocks"], activation_height)
        assert_greater_than(activation_height, node.getblockheader(blockhashes[-2], True)["height"])

        # Post-activation: attempt to spend the coinbase txns that contain token data/unparseable token data via
        # mempool path
        self.send_txs([send_bad_token_coinbase_tx], success=False,
                      reject_reason='bad-txns-vin-token-created-pre-activation')
        self.send_txs([burn_bad_token_coinbase_tx], success=False,
                      reject_reason='bad-txns-vin-token-created-pre-activation')
        self.send_txs([send_unparseable_token_coinbase_tx], success=False, reject_reason='bad-txns-nonstandard-inputs')

        # Post-activation: Attempt to spend the coinbase txns that contain token data/unparseable token data via mining
        # to blocks
        block = self.create_block(blockhashes[-1], height, nTime=nTime, txns=[send_bad_token_coinbase_tx])
        self.send_blocks([block], success=False, reject_reason='bad-txns-vin-token-created-pre-activation')
        block = self.create_block(blockhashes[-1], height, nTime=nTime, txns=[burn_bad_token_coinbase_tx])
        self.send_blocks([block], success=False, reject_reason='bad-txns-vin-token-created-pre-activation')
        block = self.create_block(blockhashes[-1], height, nTime=nTime, txns=[send_unparseable_token_coinbase_tx])
        self.send_blocks([block], success=False, reject_reason='bad-txns-vin-tokenprefix')

        # Next, attempt to mine some coinbase txns that have token data or unparseable token data in them
        block = self.create_block(blockhashes[-1], height, nTime=nTime, token_data=bad_token)
        self.send_blocks([block], success=False, reject_reason='bad-txns-coinbase-has-tokens')
        block = self.create_block(blockhashes[-1], height, nTime=nTime, script_pub_key=unparseable_token_data_spk)
        self.send_blocks([block], success=False, reject_reason='bad-txns-vout-tokenprefix')

    def create_tx(self, inputs: List[UTXO], outputs: List[CTxOut],
                  *, sign=True, hashtype=SIGHASH_ALL | SIGHASH_FORKID, sigtype='schnorr'):
        """Assumption: all inputs owned by self.priv_key"""
        tx = CTransaction()
        total_value = 0
        total_token_values: DefaultDict[int, int] = defaultdict(int)
        utxos = []
        for outpt, txout in inputs:
            utxos.append(txout)
            total_value += txout.nValue
            if isinstance(txout.tokenData, TokenOutputData):
                total_token_values[txout.tokenData.id] += txout.tokenData.amount
            if outpt.n == 0:
                total_token_values[outpt.hash] = 9223372036854775808
            tx.vin.append(CTxIn(outpt))
        for out in outputs:
            total_value -= out.nValue
            assert total_value >= 0
            if isinstance(out.tokenData, TokenOutputData):
                total_token_values[out.tokenData.id] -= out.tokenData.amount
                assert total_token_values[out.tokenData.id] >= 0
            tx.vout.append(out)
        if sign:
            assert hashtype & SIGHASH_FORKID
            for i in range(len(tx.vin)):
                inp = tx.vin[i]
                utxo = utxos[i]
                # Sign the transaction
                hashbyte = bytes([hashtype & 0xff])
                sighash = SignatureHashForkId(utxo.scriptPubKey, tx, i, hashtype, utxo.nValue, utxos=utxos)
                txsig = b''
                if sigtype == 'schnorr':
                    txsig = schnorr.sign(self.priv_key.get_bytes(), sighash) + hashbyte
                elif sigtype == 'ecdsa':
                    txsig = self.priv_key.sign_ecdsa(sighash) + hashbyte
                inp.scriptSig = CScript([txsig, self.priv_key.get_pubkey().get_bytes()])
        tx.rehash()
        return tx

    def create_block(self, prev_block_hash: Union[int, str], height: int, script_pub_key=None, txns=None,
                     nTime=None, token_data=None) -> CBlock:
        if isinstance(prev_block_hash, str):
            prev_block_hash = uint256_from_hex(prev_block_hash)
        block_time = nTime or FromHex(CBlock(), self.nodes[0].getblock(uint256_to_hex(prev_block_hash), 0)).nTime + 1

        # First create the coinbase
        coinbase = create_coinbase(height, scriptPubKey=script_pub_key or self.spk, tokenData=token_data)
        coinbase.rehash()

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

    def send_blocks(self, blocks, success=True, reject_reason=None,
                    request_block=True, reconnect=False, timeout=60):
        """Sends blocks to test node. Syncs and verifies that tip has advanced to most recent block.

        Call with success = False if the tip shouldn't advance to the most recent block."""
        self.nodes[0].p2p.send_blocks_and_test(blocks, self.nodes[0], success=success,
                                               reject_reason=reject_reason, request_block=request_block,
                                               timeout=timeout, expect_disconnect=reconnect)
        if reconnect:
            self.reconnect_p2p()

    def send_txs(self, txs, success=True, reject_reason=None, reconnect=False):
        """Sends txns to test node. Syncs and verifies that txns are in mempool

        Call with success = False if the txns should be rejected."""
        self.nodes[0].p2p.send_txs_and_test(txs, self.nodes[0], success=success, expect_disconnect=reconnect,
                                            reject_reason=reject_reason)
        if reconnect:
            self.reconnect_p2p()


if __name__ == '__main__':
    TokenCoinbaseForbiddenTest().main()
