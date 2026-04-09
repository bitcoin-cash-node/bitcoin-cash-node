#!/usr/bin/env python3
# Copyright (c) 2014-2019 The Bitcoin Core developers
# Copyright (c) 2021-2025 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Test RPCs related to blockchainstate.

Test the following RPCs:
    - getblockchaininfo
    - gettxoutsetinfo
    - getdifficulty
    - getbestblockhash
    - getblockhash
    - getblockheader
    - getchaintxstats
    - getnetworkhashps
    - verifychain

Tests correspond to code in rpc/blockchain.cpp.
"""

from decimal import Decimal
import http.client
import os
import subprocess
import string
from io import BytesIO

from test_framework import authproxy, cashaddr, script
from test_framework.test_framework import BitcoinTestFramework, get_datadir_path
from test_framework.util import (
    assert_equal,
    assert_fee_amount,
    assert_greater_than,
    assert_greater_than_or_equal,
    assert_raises,
    assert_raises_rpc_error,
    assert_is_hash_string,
    assert_is_hex_string,
    hex_str_to_bytes,
)
from test_framework.blocktools import (
    create_block,
    create_coinbase,
)
from test_framework.messages import (
    CBlockHeader,
    COIN,
    msg_block,
)
from test_framework.p2p import (
    P2PInterface,
)


class BlockchainTest(BitcoinTestFramework):

    def set_test_params(self):
        self.num_nodes = 1

    def run_test(self):
        # Set extra args with pruning after rescan is complete
        self.restart_node(0, extra_args=['-stopatheight=207', '-prune=1'])

        self._test_getblockchaininfo()
        self._test_getchaintxstats()
        self._test_gettxoutsetinfo()
        self._test_getblockheader()
        self._test_getdifficulty()
        self._test_getnetworkhashps()
        self._test_stopatheight()
        self._test_waitforblockheight()
        if self.is_wallet_compiled():
            self._test_getblock()
        assert self.nodes[0].verifychain(4, 0)

    def _test_getblockchaininfo(self):
        self.log.info("Test getblockchaininfo")

        keys = [
            'bestblockhash',
            'blocks',
            'chain',
            'chainwork',
            'difficulty',
            'headers',
            'initialblockdownload',
            'mediantime',
            'pruned',
            'size_on_disk',
            'upgrade_status',
            'verificationprogress',
            'warnings',
        ]
        res = self.nodes[0].getblockchaininfo()

        # result should have these additional pruning keys if manual pruning is
        # enabled
        assert_equal(sorted(res.keys()), sorted(
            ['pruneheight', 'automatic_pruning'] + keys))

        # size_on_disk should be > 0
        assert_greater_than(res['size_on_disk'], 0)

        # pruneheight should be greater or equal to 0
        assert_greater_than_or_equal(res['pruneheight'], 0)

        # check other pruning fields given that prune=1
        assert res['pruned']
        assert not res['automatic_pruning']
        self._assert_upgrade_status(res['upgrade_status'])

        self.restart_node(0, ['-stopatheight=207'])
        res = self.nodes[0].getblockchaininfo()
        # should have exact keys
        assert_equal(sorted(res.keys()), keys)
        self._assert_upgrade_status(res['upgrade_status'])

        self.restart_node(0, ['-stopatheight=207', '-prune=550'])
        res = self.nodes[0].getblockchaininfo()
        # result should have these additional pruning keys if prune=550
        assert_equal(sorted(res.keys()), sorted(
            ['pruneheight', 'automatic_pruning', 'prune_target_size'] + keys))

        # check related fields
        assert res['pruned']
        assert_equal(res['pruneheight'], 0)
        assert res['automatic_pruning']
        assert_equal(res['prune_target_size'], 576716800)
        assert_greater_than(res['size_on_disk'], 0)
        self._assert_upgrade_status(res['upgrade_status'])

    def _assert_upgrade_status(self, status):
        expect_fields = {
            'name': str,
            'mempool_activated': bool,
            'mempool_activation_mtp': int,
            'block_preactivation_height': (int, type(None)),
            'block_preactivation_hash': (str, type(None)),
            'block_postactivation_height': (int, type(None)),
            'block_postactivation_hash': (str, type(None)),
            'software_expiration_time': (int, type(None)),
        }
        assert_equal(sorted(status.keys()), sorted(expect_fields))
        for field, field_type in expect_fields.items():
            assert isinstance(status[field], field_type), f"{field} has wrong type"

        def _check_block(height_key, hash_key):
            height = status[height_key]
            block_hash = status[hash_key]
            if height is None:
                assert block_hash is None
            else:
                assert block_hash is not None
                assert_equal(len(block_hash), 64)

        _check_block('block_preactivation_height', 'block_preactivation_hash')
        _check_block('block_postactivation_height', 'block_postactivation_hash')

    def _test_getchaintxstats(self):
        self.log.info("Test getchaintxstats")

        # Test `getchaintxstats` invalid extra parameters
        assert_raises_rpc_error(
            -1, 'getchaintxstats', self.nodes[0].getchaintxstats, 0, '', 0)

        # Test `getchaintxstats` invalid `nblocks`
        assert_raises_rpc_error(
            -1, "JSON value is not an integer as expected", self.nodes[0].getchaintxstats, '')
        assert_raises_rpc_error(
            -8, "Invalid block count: should be between 0 and the block's height - 1", self.nodes[0].getchaintxstats, -1)
        assert_raises_rpc_error(-8, "Invalid block count: should be between 0 and the block's height - 1", self.nodes[
                                0].getchaintxstats, self.nodes[0].getblockcount())

        # Test `getchaintxstats` invalid `blockhash`
        assert_raises_rpc_error(
            -1, "JSON value is not a string as expected", self.nodes[0].getchaintxstats, blockhash=0)
        assert_raises_rpc_error(-8,
                                "blockhash must be of length 64 (not 1, for '0')",
                                self.nodes[0].getchaintxstats,
                                blockhash='0')
        assert_raises_rpc_error(
            -8,
            "blockhash must be hexadecimal string (not 'ZZZ0000000000000000000000000000000000000000000000000000000000000')",
            self.nodes[0].getchaintxstats,
            blockhash='ZZZ0000000000000000000000000000000000000000000000000000000000000')
        assert_raises_rpc_error(
            -5,
            "Block not found",
            self.nodes[0].getchaintxstats,
            blockhash='0000000000000000000000000000000000000000000000000000000000000000')
        blockhash = self.nodes[0].getblockhash(200)
        self.nodes[0].invalidateblock(blockhash)
        assert_raises_rpc_error(
            -8, "Block is not in main chain", self.nodes[0].getchaintxstats, blockhash=blockhash)
        # Check consistency between headers and blocks count
        assert_equal(self.nodes[0].getblockchaininfo()['headers'], self.nodes[0].getblockchaininfo()['blocks'])

        self.nodes[0].reconsiderblock(blockhash)

        chaintxstats = self.nodes[0].getchaintxstats(nblocks=1)
        # 200 txs plus genesis tx
        assert_equal(chaintxstats['txcount'], 201)
        # tx rate should be 1 per 10 minutes, or 1/600
        # we have to round because of binary math
        assert_equal(round(chaintxstats['txrate'] * 600, 10), Decimal(1))

        b1_hash = self.nodes[0].getblockhash(1)
        b1 = self.nodes[0].getblock(b1_hash)
        b200_hash = self.nodes[0].getblockhash(200)
        b200 = self.nodes[0].getblock(b200_hash)
        time_diff = b200['mediantime'] - b1['mediantime']

        chaintxstats = self.nodes[0].getchaintxstats()
        assert_equal(chaintxstats['time'], b200['time'])
        assert_equal(chaintxstats['txcount'], 201)
        assert_equal(chaintxstats['window_final_block_hash'], b200_hash)
        assert_equal(chaintxstats['window_final_block_height'], 200)
        assert_equal(chaintxstats['window_block_count'], 199)
        assert_equal(chaintxstats['window_tx_count'], 199)
        assert_equal(chaintxstats['window_interval'], time_diff)
        assert_equal(
            round(chaintxstats['txrate'] * time_diff, 10), Decimal(199))

        chaintxstats = self.nodes[0].getchaintxstats(blockhash=b1_hash)
        assert_equal(chaintxstats['time'], b1['time'])
        assert_equal(chaintxstats['txcount'], 2)
        assert_equal(chaintxstats['window_final_block_hash'], b1_hash)
        assert_equal(chaintxstats['window_final_block_height'], 1)
        assert_equal(chaintxstats['window_block_count'], 0)
        assert 'window_tx_count' not in chaintxstats
        assert 'window_interval' not in chaintxstats
        assert 'txrate' not in chaintxstats

    def _test_gettxoutsetinfo(self):
        node = self.nodes[0]
        res = node.gettxoutsetinfo()

        assert_equal(res['total_amount'], Decimal('8725.00000000'))
        assert_equal(res['transactions'], 200)
        assert_equal(res['height'], 200)
        assert_equal(res['txouts'], 200)
        assert_equal(res['bogosize'], 15000),
        assert_equal(res['bestblock'], node.getblockhash(200))
        size = res['disk_size']
        assert size > 6400
        assert size < 64000
        assert_equal(len(res['bestblock']), 64)
        assert_equal(len(res['hash_serialized_3']), 64)

        self.log.info(
            "Test that gettxoutsetinfo() works for blockchain with just the genesis block")
        b1hash = node.getblockhash(1)
        node.invalidateblock(b1hash)

        res2 = node.gettxoutsetinfo()
        assert_equal(res2['transactions'], 0)
        assert_equal(res2['total_amount'], Decimal('0'))
        assert_equal(res2['height'], 0)
        assert_equal(res2['txouts'], 0)
        assert_equal(res2['bogosize'], 0),
        assert_equal(res2['bestblock'], node.getblockhash(0))
        assert_equal(len(res2['hash_serialized_3']), 64)

        self.log.info(
            "Test that gettxoutsetinfo() returns the same result after invalidate/reconsider block")
        node.reconsiderblock(b1hash)

        res3 = node.gettxoutsetinfo()
        # The field 'disk_size' is non-deterministic and can thus not be
        # compared between res and res3.  Everything else should be the same.
        del res['disk_size'], res3['disk_size']
        assert_equal(res, res3)

        self.log.info("Test gettxoutsetinfo hash_type option")
        # Adding hash_type 'hash_serialized_3', which is the default, should
        # not change the result.
        res4 = node.gettxoutsetinfo(hash_type='hash_serialized_3')
        del res4['disk_size']
        assert_equal(res, res4)

        # hash_type none should not return a UTXO set hash.
        res5 = node.gettxoutsetinfo(hash_type='none')
        assert 'hash_serialized_3' not in res5

        # hash_type muhash_testing should return a different UTXO set hash.
        res6 = node.gettxoutsetinfo(hash_type='muhash_testing')
        assert 'muhash_testing' in res6
        assert res['hash_serialized_3'] != res6['muhash_testing']

        # hash_type muhash_testing should return a different UTXO set hash.
        res7 = node.gettxoutsetinfo(hash_type='ecmh')
        assert 'ecmh' in res7
        assert 'ecmh_pubkey' in res7
        assert 'muhash_testing' not in res7
        assert res['hash_serialized_3'] != res7['ecmh']
        assert res6['muhash_testing'] != res7['ecmh']

        # muhash and/or ecmh should not be returned unless requested.
        for r in [res, res2, res3, res4, res5]:
            assert 'muhash_testing' not in r
            assert 'ecmh' not in r
            assert 'ecmh_pubkey' not in r

        # Unknown hash_type raises an error
        assert_raises_rpc_error(-8, "'foo hash' is not a valid hash_type", node.gettxoutsetinfo, "foo hash")

    def _test_getblockheader(self):
        node = self.nodes[0]

        assert_raises_rpc_error(-8,
                                "hash_or_height must be of length 64 (not 8, for 'nonsense')",
                                node.getblockheader,
                                "nonsense")
        assert_raises_rpc_error(
            -8,
            "hash_or_height must be hexadecimal string (not 'ZZZ7bb8b1697ea987f3b223ba7819250cae33efacb068d23dc24859824a77844')",
            node.getblockheader,
            "ZZZ7bb8b1697ea987f3b223ba7819250cae33efacb068d23dc24859824a77844")
        assert_raises_rpc_error(-5, "Block not found", node.getblockheader,
                                "0cf7bb8b1697ea987f3b223ba7819250cae33efacb068d23dc24859824a77844")
        assert_raises_rpc_error(
            -8,
            "Target block height 201 after current tip 200",
            node.getblockheader,
            201)
        assert_raises_rpc_error(
            -8,
            "Target block height -10 is negative",
            node.getblockheader,
            -10)

        besthash = node.getbestblockhash()
        secondbesthash = node.getblockhash(199)
        header = node.getblockheader(hash_or_height=besthash)

        assert_equal(header['hash'], besthash)
        assert_equal(header['height'], 200)
        assert_equal(header['confirmations'], 1)
        assert_equal(header['previousblockhash'], secondbesthash)
        assert_is_hex_string(header['chainwork'])
        assert_equal(header['nTx'], 1)
        assert_is_hash_string(header['hash'])
        assert_is_hash_string(header['previousblockhash'])
        assert_is_hash_string(header['merkleroot'])
        assert_is_hash_string(header['bits'], length=None)
        assert isinstance(header['time'], int)
        assert isinstance(header['mediantime'], int)
        assert isinstance(header['nonce'], int)
        assert isinstance(header['version'], int)
        assert isinstance(int(header['versionHex'], 16), int)
        assert isinstance(header['difficulty'], Decimal)

        header_by_height = node.getblockheader(hash_or_height=200)
        assert_equal(header, header_by_height)

        # Next, check that the old alias 'blockhash' still works
        # and is interchangeable with hash_or_height
        # First, make sure errors work as expected for unknown named params
        self.log.info("Testing that getblockheader(blockhashhh=\"HEX\") produces the proper error")
        assert_raises_rpc_error(
            -8,
            "Unknown named parameter blockhashhh",
            node.getblockheader,
            blockhashhh=header['hash'])
        # Next, actually try the old legacy blockhash="xx" style arg
        self.log.info("Testing that legacy getblockheader(blockhash=\"HEX\") still works ok")
        header_by_hash2 = node.getblockheader(blockhash=header['hash'])
        assert_equal(header, header_by_hash2)
        header_by_height2 = node.getblockheader(blockhash=200)
        assert_equal(header, header_by_height2)

        # check that we actually get a hex string back from getblockheader
        # if verbose is set to false.
        header_verbose_false = node.getblockheader(200, False)
        assert not isinstance(header_verbose_false, dict)
        assert isinstance(header_verbose_false, str)
        assert (c in string.hexdigits for c in header_verbose_false)
        assert_is_hex_string(header_verbose_false)

        # check that header_verbose_false is the same header we get via
        # getblockheader(hash_or_height=besthash) just in a different "form"
        h = CBlockHeader()
        h.deserialize(BytesIO(hex_str_to_bytes(header_verbose_false)))
        h.calc_sha256()

        assert_equal(header['version'], h.nVersion)
        assert_equal(header['time'], h.nTime)
        assert_equal(header['previousblockhash'], "{:064x}".format(h.hashPrevBlock))
        assert_equal(header['merkleroot'], "{:064x}".format(h.hashMerkleRoot))
        assert_equal(header['hash'], h.hash)

        # check that we get the same header by hash and by height in
        # the case verbose is set to False
        header_verbose_false_by_hash = node.getblockheader(besthash, False)
        assert_equal(header_verbose_false_by_hash, header_verbose_false)

    def _test_getdifficulty(self):
        difficulty = self.nodes[0].getdifficulty()
        # 1 hash in 2 should be valid, so difficulty should be 1/2**31
        # binary => decimal => binary math is why we do this check
        assert abs(difficulty * 2**31 - 1) < 0.0001

    def _test_getnetworkhashps(self):
        hashes_per_second = self.nodes[0].getnetworkhashps()
        # This should be 2 hashes every 10 minutes or 1/300
        assert abs(hashes_per_second * 300 - 1) < 0.0001
        assert_equal(hashes_per_second, self.nodes[0].getnetworkhashps(None, self.nodes[0].getblockcount()))
        for not_positive in (-1, 0):
            assert_raises_rpc_error(
                -8,
                "Number of blocks must be positive (using blocks since last difficulty change is no longer possible, because difficulty changes every block)",
                self.nodes[0].getnetworkhashps,
                not_positive)

    def _test_stopatheight(self):
        assert_equal(self.nodes[0].getblockcount(), 200)
        self.generatetoaddress(self.nodes[0],
                               6, self.nodes[0].get_deterministic_priv_key().address)
        assert_equal(self.nodes[0].getblockcount(), 206)
        self.log.debug('Node should not stop at this height')
        assert_raises(subprocess.TimeoutExpired,
                      lambda: self.nodes[0].process.wait(timeout=3))
        try:
            self.generatetoaddress(self.nodes[0],
                                   1, self.nodes[0].get_deterministic_priv_key().address)
        except (ConnectionError, http.client.BadStatusLine):
            pass  # The node already shut down before response
        self.log.debug('Node should stop at this height...')
        self.nodes[0].wait_until_stopped()
        self.start_node(0)
        assert_equal(self.nodes[0].getblockcount(), 207)

    def _test_waitforblockheight(self):
        self.log.info("Test waitforblockheight")
        node = self.nodes[0]
        node.add_p2p_connection(P2PInterface())

        current_height = node.getblock(node.getbestblockhash())['height']

        # Create a fork somewhere below our current height, invalidate the tip
        # of that fork, and then ensure that waitforblockheight still
        # works as expected.
        #
        # (Previously this was broken based on setting
        # `rpc/blockchain.cpp:latestblock` incorrectly.)
        #
        b20hash = node.getblockhash(20)
        b20 = node.getblock(b20hash)

        def solve_and_send_block(prevhash, height, time):
            b = create_block(prevhash, create_coinbase(height), time)
            b.solve()
            node.p2p.send_and_ping(msg_block(b))
            return b

        b21f = solve_and_send_block(int(b20hash, 16), 21, b20['time'] + 1)
        b22f = solve_and_send_block(b21f.sha256, 22, b21f.nTime + 1)

        node.invalidateblock(b22f.hash)

        def assert_waitforheight(height, timeout=2):
            assert_equal(
                node.waitforblockheight(
                    height=height, timeout=timeout)['height'],
                current_height)

        assert_waitforheight(0)
        assert_waitforheight(current_height - 1)
        assert_waitforheight(current_height)
        assert_waitforheight(current_height + 1)

    def _test_getblock(self):
        # Checks for getblock verbose outputs
        node = self.nodes[0]
        blockinfo = node.getblock(node.getblockhash(1), 2)
        transactioninfo = node.gettransaction(blockinfo['tx'][0]['txid'])
        blockheaderinfo = node.getblockheader(node.getblockhash(1), True)

        assert_equal(blockinfo['hash'], transactioninfo['blockhash'])
        assert_equal(
            blockinfo['confirmations'],
            transactioninfo['confirmations'])
        assert_equal(blockinfo['height'], blockheaderinfo['height'])
        assert_equal(blockinfo['versionHex'], blockheaderinfo['versionHex'])
        assert_equal(blockinfo['version'], blockheaderinfo['version'])
        assert_equal(blockinfo['size'], 178)
        assert_equal(blockinfo['merkleroot'], blockheaderinfo['merkleroot'])
        # Verify transaction data by check the hex values
        for tx in blockinfo['tx']:
            rawtransaction = node.getrawtransaction(tx['txid'], True)
            assert_equal(tx['hex'], rawtransaction['hex'])
        assert_equal(blockinfo['time'], blockheaderinfo['time'])
        assert_equal(blockinfo['mediantime'], blockheaderinfo['mediantime'])
        assert_equal(blockinfo['nonce'], blockheaderinfo['nonce'])
        assert_equal(blockinfo['bits'], blockheaderinfo['bits'])
        assert_equal(blockinfo['difficulty'], blockheaderinfo['difficulty'])
        assert_equal(blockinfo['chainwork'], blockheaderinfo['chainwork'])
        assert_equal(
            blockinfo['previousblockhash'],
            blockheaderinfo['previousblockhash'])
        assert_equal(
            blockinfo['nextblockhash'],
            blockheaderinfo['nextblockhash'])

        def wallet_create_new_p2pkh_and_p2sh_address_pair():
            """Create a new p2pkh address and a p2sh wrapping it."""
            p2pkh_addr = node.getnewaddress()
            p2pkh_spk = node.validateaddress(p2pkh_addr)['scriptPubKey']
            p2pkh_spk_h160 = script.hash160(bytes.fromhex(p2pkh_spk))
            p2sh_addr = cashaddr.encode_full("bchreg", cashaddr.SCRIPT_TYPE, p2pkh_spk_h160)
            try:
                # Hack to add a p2sh wrapping a p2pkh
                node.importaddress(p2pkh_spk, "", False, True)
            except authproxy.JSONRPCException as e:
                """Due to bugs in the node, the above throws, but before it fails,
                as a side-effect, it *does* end up registering the redeemScript for
                the p2sh which wraps the p2pkh. Now the node is tracking the p2sh
                and knows how to sign for it."""
                if 'wallet already contains' in str(e):
                    pass
                else:
                    raise e  # Some other unexpected exception occurred
            return p2pkh_addr, p2sh_addr

        # Set the fee slightly higher
        fee_per_byte = 2.5
        node.settxfee(Decimal(fee_per_byte * 1e3) / Decimal(COIN))

        # Set up the following txn chain, given N coins in wallet:
        #
        #     /--> tx1: N-2 coins sent to p2sh_addr -----\
        # ---|                                            |--> tx_child: Everything merged to 1 coin.
        #     \--> tx2: 2 coins to sent to p2pkh_addr ---/
        #
        p2pkh_addr, p2sh_addr = wallet_create_new_p2pkh_and_p2sh_address_pair()
        # We should have at least 4 coins, so all txns have >=2 inputs
        assert_greater_than_or_equal(len(node.listunspent(0)), 4)
        # Merge all N coins of our funds into 2 coins: one coin to p2pkh_addr and one to p2sh_addr
        bal = node.getbalance()
        assert_greater_than(bal, Decimal("100.0"))
        # Send all but 2 of our unspent coins to p2sh_addr
        txid_to_p2sh = node.sendtoaddress(p2sh_addr, bal - Decimal("100.0"), "", "", True)
        bal_conf = node.getbalance("*", 1)
        assert_equal(bal_conf, Decimal("100.0"))
        assert_equal(len(node.listunspent(1)), 2)  # 2 confirmed coins are left
        # Send remaining 2 confirmed coins to p2pkh_addr. NOTE: this relies on coin selection to work as we expect.
        txid_to_p2pkh = node.sendtoaddress(p2pkh_addr, bal_conf, "", "", True)
        # All of the above should have generated precisely 2 coins
        assert_equal(len(node.listunspent(0)), 2)

        bal = node.getbalance()
        txid_child = node.sendtoaddress(node.getnewaddress(), bal, "", "", True)  # Send both coins
        assert_equal(set(node.getrawmempool(False)), {txid_to_p2pkh, txid_to_p2sh, txid_child})
        assert_equal(len(node.listunspent(0)), 1)  # txid_child should have merged 2 coins to 1
        blockhash, = node.generate(1)
        # Find the index of all 3 txns above, ensure they all appear in block
        block_txns = node.getblock(blockhash, 1)['tx']
        assert_equal(len(block_txns), 4)  # 3 + coinbase
        assert_equal({block_txns.index(txid_child), block_txns.index(txid_to_p2sh), block_txns.index(txid_to_p2pkh)},
                     {1, 2, 3})

        def assert_fee_not_in_block(verbosity, patterns=False):
            block = node.getblock(blockhash, verbosity, patterns)
            for tx in block['tx'][1:]:
                if isinstance(tx, str):
                    # In verbosity level 1, only the transaction hashes are written
                    pass
                else:
                    assert isinstance(tx, dict) and 'fee' not in tx

        def assert_fee_in_block(verbosity, patterns=False):
            block = node.getblock(blockhash, verbosity, patterns)
            for tx in block['tx'][1:]:
                assert 'fee' in tx
                assert_fee_amount(tx['fee'], tx['size'], fee_per_byte * 1000 / COIN)

        def assert_vin_contains_prevout(verbosity, patterns=False):
            block = node.getblock(blockhash, verbosity, patterns)
            for tx in block['tx'][1:]:
                total_vin = Decimal("0.00000000")
                total_vout = Decimal("0.00000000")
                for vin in tx["vin"]:
                    assert "prevout" in vin
                    assert_equal(set(vin["prevout"].keys()), {"value", "height", "generated", "scriptPubKey"})
                    expect_generated = tx['txid'] != txid_child
                    assert_equal(vin["prevout"]["generated"], expect_generated)
                    total_vin += vin["prevout"]["value"]
                for vout in tx["vout"]:
                    total_vout += vout["value"]
                assert_equal(total_vin, total_vout + tx["fee"])

        def assert_vin_does_not_contain_prevout(verbosity, patterns=False):
            block = node.getblock(blockhash, verbosity, patterns)
            for tx in block['tx'][1:]:
                if isinstance(tx, str):
                    # In verbosity level 1, only the transaction hashes are written
                    pass
                else:
                    for vin in tx["vin"]:
                        assert "prevout" not in vin

        def assert_scripts_contain_bytecodepattern(verbosity, patterns=False):
            def check_bcp_keys(bcp, *extra_keys):
                """Check that byteCodePattern dict has at least these 4 keys"""
                assert_equal({'fingerprint', 'pattern', 'patternAsm', 'data', *extra_keys} - set(bcp.keys()), set())

            redeem_script_count = 0
            block = node.getblock(blockhash, verbosity, patterns)
            for tx in block["tx"]:
                for vin in tx["vin"]:
                    if "coinbase" in vin:
                        assert isinstance(vin["coinbase"], str)
                        continue

                    assert "scriptSig" in vin
                    assert "byteCodePattern" in vin["scriptSig"]
                    check_bcp_keys(vin["scriptSig"]["byteCodePattern"])
                    if "redeemScript" in vin["scriptSig"]:
                        redeem_script_count += 1
                        assert_equal({'asm', 'hex', 'byteCodePattern'} - set(vin["scriptSig"]["redeemScript"].keys()),
                                     set())
                        check_bcp_keys(vin["scriptSig"]["redeemScript"]["byteCodePattern"], "p2shType")

                    if verbosity > 2:
                        assert "byteCodePattern" in vin["prevout"]["scriptPubKey"]
                        check_bcp_keys(vin["prevout"]["scriptPubKey"]["byteCodePattern"])

                for vout in tx["vout"]:
                    assert "scriptPubKey" in vout
                    assert "byteCodePattern" in vout["scriptPubKey"]
                    check_bcp_keys(vout["scriptPubKey"]["byteCodePattern"])
            return redeem_script_count

        def assert_scripts_do_not_contain_bytecodepattern(verbosity, patterns=False):
            block = node.getblock(blockhash, verbosity, patterns)
            for tx in block["tx"]:
                if isinstance(tx, str):
                    continue
                for vin in tx["vin"]:
                    if "coinbase" in vin:
                        assert isinstance(vin["coinbase"], str)
                        continue

                    assert "scriptSig" in vin
                    assert "byteCodePattern" not in vin["scriptSig"]
                    assert "redeemScript" not in vin["scriptSig"]
                    if "prevout" in vin:
                        assert "byteCodePattern" not in vin["prevout"]["scriptPubKey"]

                for vout in tx["vout"]:
                    assert "scriptPubKey" in vout
                    assert "byteCodePattern" not in vout["scriptPubKey"]


        self.log.info("Test that getblock with verbosity 1 doesn't include fee")
        assert_fee_not_in_block(1)

        self.log.info('Test that getblock with verbosity 2 and 3 includes expected fee')
        assert_fee_in_block(2)
        assert_fee_in_block(2, True)
        assert_fee_in_block(3)
        assert_fee_in_block(3, True)

        self.log.info("Test that getblock with verbosity 1 and 2 does not include prevout")
        assert_vin_does_not_contain_prevout(1)
        assert_vin_does_not_contain_prevout(2)
        assert_vin_does_not_contain_prevout(2, True)

        self.log.info("Test that getblock with verbosity 3 includes prevout")
        assert_vin_contains_prevout(3)
        assert_vin_contains_prevout(3, True)

        self.log.info("Test that getblock with verbosity 1, 2, and 3 does not include byteCodePattern for any script")
        assert_scripts_do_not_contain_bytecodepattern(1)
        assert_scripts_do_not_contain_bytecodepattern(2)
        assert_scripts_do_not_contain_bytecodepattern(3)

        self.log.info("Test that getblock with verbosity pattern flag includes byteCodePattern in all scripts")
        rs_count = assert_scripts_contain_bytecodepattern(2, True)
        self.log.info("Test that we didn't see any p2sh redeemScript entries at verbosity 2, as they need prevouts")
        assert_equal(rs_count, 0)
        rs_count = assert_scripts_contain_bytecodepattern(3, True)
        self.log.info("Test that we saw at least some p2sh redeemScript entries at verbosity 3")
        assert_greater_than(rs_count, 0)

        self.log.info("Test that getblock with verbosity 2 and 3 still works with pruned Undo data")
        datadir = get_datadir_path(self.options.tmpdir, 0)

        self.log.info("Test getblock with invalid verbosity type returns proper error message")
        assert_raises_rpc_error(-1, "JSON value is not an integer as expected", node.getblock, blockhash, "2")

        self.log.info("Test getblock with invalid patterns type returns proper error message")
        assert_raises_rpc_error(-1, "JSON value is not a boolean as expected", node.getblock, blockhash, 2, "True")

        def move_block_file(old, new):
            old_path = os.path.join(datadir, self.chain, 'blocks', old)
            new_path = os.path.join(datadir, self.chain, 'blocks', new)
            os.rename(old_path, new_path)

        # Move instead of deleting so we can restore chain state afterwards
        move_block_file('rev00000.dat', 'rev_wrong')

        assert_fee_not_in_block(2)
        assert_fee_not_in_block(2, True)
        assert_fee_not_in_block(3)
        assert_fee_not_in_block(3, True)
        assert_vin_does_not_contain_prevout(2)
        assert_vin_does_not_contain_prevout(2, True)
        assert_vin_does_not_contain_prevout(3)
        assert_vin_does_not_contain_prevout(3, True)

        # Restore chain state
        move_block_file('rev_wrong', 'rev00000.dat')
        assert 'previousblockhash' not in node.getblock(node.getblockhash(0))
        assert 'nextblockhash' not in node.getblock(node.getbestblockhash())


if __name__ == '__main__':
    BlockchainTest().main()
