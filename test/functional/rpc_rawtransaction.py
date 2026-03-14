#!/usr/bin/env python3
# Copyright (c) 2014-2019 The Bitcoin Core developers
# Copyright (c) 2020-2025 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the rawtranscation RPCs.

Test the following RPCs:
   - createrawtransaction
   - signrawtransactionwithwallet
   - sendrawtransaction
   - decoderawtransaction
   - getrawtransaction
"""

import os
from decimal import Decimal

from collections import OrderedDict
from io import BytesIO
from test_framework.messages import (
    COutPoint,
    CTransaction,
    CTxIn,
    CTxOut,
    ToHex,
)
from test_framework.script import CScript
from test_framework.test_framework import BitcoinTestFramework, get_datadir_path
from test_framework.txtools import pad_raw_tx
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_raises_rpc_error,
    connect_nodes_bi,
    disconnect_nodes,
    hex_str_to_bytes,
)


class multidict(dict):
    """Dictionary that allows duplicate keys.
    Constructed with a list of (key, value) tuples. When dumped by the json module,
    will output invalid json with repeated keys, eg:
    >>> json.dumps(multidict([(1,2),(1,2)])
    '{"1": 2, "1": 2}'
    Used to test calls to rpc methods with repeated keys in the json object."""

    def __init__(self, x):
        dict.__init__(self, x)
        self.x = x

    def items(self):
        return self.x


# Create one-input, one-output, no-fee transaction:
class RawTransactionsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 5
        # node 0 has txindex
        # 1 and 2 have txindex enabled
        # 3 is in manual pruning mode
        # 4 is to be disconnected and not contain queried transactions and blocks
        self.extra_args = [[], ['-txindex'], ['-txindex'], ['-prune=1'], ['-txindex']]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self):
        super().setup_network()
        connect_nodes_bi(self.nodes[0], self.nodes[2])
        connect_nodes_bi(self.nodes[0], self.nodes[4])

    def run_test(self):
        synced_nodes = self.nodes[:4]
        self.log.info(
            'prepare some coins for multiple *rawtransaction commands')
        self.generate(self.nodes[2], 1)
        self.sync_all()
        self.generate(self.nodes[0], 101)
        self.sync_all()
        self.nodes[0].sendtoaddress(self.nodes[2].getnewaddress(), 1.5)
        self.nodes[0].sendtoaddress(self.nodes[2].getnewaddress(), 1.0)
        self.nodes[0].sendtoaddress(self.nodes[2].getnewaddress(), 5.0)

        # disconnect node 4
        disconnect_nodes(self.nodes[0], self.nodes[4])
        disconnect_nodes(self.nodes[1], self.nodes[4])
        disconnect_nodes(self.nodes[2], self.nodes[4])
        disconnect_nodes(self.nodes[3], self.nodes[4])
        disconnect_nodes(self.nodes[4], self.nodes[0])
        disconnect_nodes(self.nodes[4], self.nodes[1])
        disconnect_nodes(self.nodes[4], self.nodes[2])
        disconnect_nodes(self.nodes[4], self.nodes[3])

        self.sync_all(synced_nodes)
        self.generate(self.nodes[0], 5)
        self.sync_all(synced_nodes)

        self.log.info(
            'Test getrawtransaction on genesis block coinbase returns an error')
        block = self.nodes[0].getblock(self.nodes[0].getblockhash(0))
        assert_raises_rpc_error(-5, "The genesis block coinbase is not considered an ordinary transaction",
                                self.nodes[0].getrawtransaction, block['merkleroot'])

        self.log.info(
            'Check parameter types and required parameters of createrawtransaction')
        # Test `createrawtransaction` required parameters
        assert_raises_rpc_error(-1, "createrawtransaction",
                                self.nodes[0].createrawtransaction)
        assert_raises_rpc_error(-1, "createrawtransaction",
                                self.nodes[0].createrawtransaction, [])

        # Test `createrawtransaction` invalid extra parameters
        assert_raises_rpc_error(-1, "createrawtransaction",
                                self.nodes[0].createrawtransaction, [], {}, 0, 'foo')

        # Test `createrawtransaction` invalid `inputs`
        txid = '1d1d4e24ed99057e84c3f80fd8fbec79ed9e1acee37da269356ecea000000000'
        assert_raises_rpc_error(-3, "Expected type array",
                                self.nodes[0].createrawtransaction, 'foo', {})
        assert_raises_rpc_error(-1, "Cannot look up keys in JSON string, expected object with key: txid",
                                self.nodes[0].createrawtransaction, ['foo'], {})
        assert_raises_rpc_error(-1, "Key not found in JSON object: txid",
                                self.nodes[0].createrawtransaction, [{}], {})
        assert_raises_rpc_error(-8,
                                "txid must be of length 64 (not 3, for 'foo')",
                                self.nodes[0].createrawtransaction,
                                [{'txid': 'foo'}],
                                {})
        assert_raises_rpc_error(-8,
                                "txid must be hexadecimal string (not 'ZZZ7bb8b1697ea987f3b223ba7819250cae33efacb068d23dc24859824a77844')",
                                self.nodes[0].createrawtransaction,
                                [{'txid': 'ZZZ7bb8b1697ea987f3b223ba7819250cae33efacb068d23dc24859824a77844'}],
                                {})
        assert_raises_rpc_error(-8, "Invalid parameter, missing vout key",
                                self.nodes[0].createrawtransaction, [{'txid': txid}], {})
        assert_raises_rpc_error(-8, "Invalid parameter, vout must be a number",
                                self.nodes[0].createrawtransaction, [{'txid': txid, 'vout': 'foo'}], {})
        assert_raises_rpc_error(-8, "Invalid parameter, vout must be positive",
                                self.nodes[0].createrawtransaction, [{'txid': txid, 'vout': -1}], {})
        assert_raises_rpc_error(-8, "Invalid parameter, sequence number is out of range",
                                self.nodes[0].createrawtransaction, [{'txid': txid, 'vout': 0, 'sequence': -1}], {})

        # Test `createrawtransaction` invalid `outputs`
        address = self.nodes[0].getnewaddress()
        address2 = self.nodes[0].getnewaddress()
        assert_raises_rpc_error(-3, "Expected type object/array at index 1, got string",
                                self.nodes[0].createrawtransaction, [], 'foo')
        # Should not throw for backwards compatibility
        self.nodes[0].createrawtransaction(inputs=[], outputs={})
        self.nodes[0].createrawtransaction(inputs=[], outputs=[])
        assert_raises_rpc_error(-8, "data must be hexadecimal string",
                                self.nodes[0].createrawtransaction, [], {'data': 'foo'})
        assert_raises_rpc_error(-8, "data must be either a hexadecimal string or an array of hexadecimal strings",
                                self.nodes[0].createrawtransaction, [], {'data': None})
        assert_raises_rpc_error(-8, "data must be either a hexadecimal string or an array of hexadecimal strings",
                                self.nodes[0].createrawtransaction, [], {'data': 1234})
        assert_raises_rpc_error(-8, "data must be hexadecimal string",
                                self.nodes[0].createrawtransaction, [], {'data': '9'})
        assert_raises_rpc_error(-8, "data must be hexadecimal string",
                                self.nodes[0].createrawtransaction, [], {'data': ''})
        assert_raises_rpc_error(-8, "data array element must be hexadecimal string",
                                self.nodes[0].createrawtransaction, [], {'data': [1234]})
        assert_raises_rpc_error(-8, "data array element must be hexadecimal string",
                                self.nodes[0].createrawtransaction, [], {'data': ['9']})
        assert_raises_rpc_error(-8, "data array must contain at least one element",
                                self.nodes[0].createrawtransaction, [], {'data': []})
        assert_raises_rpc_error(-5, "Invalid Bitcoin Cash address",
                                self.nodes[0].createrawtransaction, [], {'foo': 0})
        assert_raises_rpc_error(-3, "Invalid amount",
                                self.nodes[0].createrawtransaction, [], {address: 'foo'})
        assert_raises_rpc_error(-3, "Amount out of range",
                                self.nodes[0].createrawtransaction, [], {address: -1})
        assert_raises_rpc_error(-8, "Invalid parameter, duplicated address: {}".format(
            address), self.nodes[0].createrawtransaction, [], multidict([(address, 1), (address, 1)]))
        assert_raises_rpc_error(-8, "Invalid parameter, duplicated address: {}".format(
            address), self.nodes[0].createrawtransaction, [], [{address: 1}, {address: 1}])
        assert_raises_rpc_error(-8, "Invalid parameter, key-value pair must contain exactly one key",
                                self.nodes[0].createrawtransaction, [], [{'a': 1, 'b': 2}])
        assert_raises_rpc_error(-8, "Invalid parameter, key-value pair not an object as expected",
                                self.nodes[0].createrawtransaction, [], [['key-value pair1'], ['2']])

        # Test `createrawtransaction` invalid `locktime`
        assert_raises_rpc_error(-3, "Expected type null/number at index 2, got string",
                                self.nodes[0].createrawtransaction, [], {}, 'foo')
        assert_raises_rpc_error(-8, "Invalid parameter, locktime out of range",
                                self.nodes[0].createrawtransaction, [], {}, -1)
        assert_raises_rpc_error(-8, "Invalid parameter, locktime out of range",
                                self.nodes[0].createrawtransaction, [], {}, 4294967296)

        self.log.info(
            'Check that createrawtransaction accepts an array and object as outputs')
        tx = CTransaction()
        # One output
        tx.deserialize(BytesIO(hex_str_to_bytes(self.nodes[2].createrawtransaction(
            inputs=[{'txid': txid, 'vout': 9}], outputs={address: 99}))))
        assert_equal(len(tx.vout), 1)
        assert_equal(
            tx.serialize().hex(),
            self.nodes[2].createrawtransaction(
                inputs=[{'txid': txid, 'vout': 9}], outputs=[{address: 99}]),
        )
        # Two outputs
        tx.deserialize(BytesIO(hex_str_to_bytes(self.nodes[2].createrawtransaction(inputs=[
                       {'txid': txid, 'vout': 9}], outputs=OrderedDict([(address, 99), (address2, 99)])))))
        assert_equal(len(tx.vout), 2)
        assert_equal(
            tx.serialize().hex(),
            self.nodes[2].createrawtransaction(inputs=[{'txid': txid, 'vout': 9}], outputs=[
                                               {address: 99}, {address2: 99}]),
        )
        # Two data outputs
        tx.deserialize(BytesIO(hex_str_to_bytes(self.nodes[2].createrawtransaction(inputs=[
                       {'txid': txid, 'vout': 9}], outputs=multidict([('data', '99'), ('data', '99')])))))
        assert_equal(len(tx.vout), 2)
        assert_equal(
            tx.serialize().hex(),
            self.nodes[2].createrawtransaction(inputs=[{'txid': txid, 'vout': 9}], outputs=[
                                               {'data': '99'}, {'data': '99'}]),
        )
        # Multiple mixed outputs
        tx.deserialize(BytesIO(hex_str_to_bytes(self.nodes[2].createrawtransaction(inputs=[
                       {'txid': txid, 'vout': 9}], outputs=multidict([(address, 99), ('data', '99'), ('data', '99')])))))
        assert_equal(len(tx.vout), 3)
        assert_equal(
            tx.serialize().hex(),
            self.nodes[2].createrawtransaction(inputs=[{'txid': txid, 'vout': 9}], outputs=[
                                               {address: 99}, {'data': '99'}, {'data': '99'}]),
        )

        self.log.info('sendrawtransaction with missing input')
        # won't exists
        inputs = [
            {'txid': "1d1d4e24ed99057e84c3f80fd8fbec79ed9e1acee37da269356ecea000000000", 'vout': 1}]
        outputs = {self.nodes[0].getnewaddress(): 4.998}
        rawtx = self.nodes[2].createrawtransaction(inputs, outputs)
        rawtx = pad_raw_tx(rawtx)
        rawtx = self.nodes[2].signrawtransactionwithwallet(rawtx)

        # This will raise an exception since there are missing inputs
        assert_raises_rpc_error(
            -25, "Missing inputs", self.nodes[2].sendrawtransaction, rawtx['hex'])

        #####################################
        # getrawtransaction with block hash #
        #####################################

        # make a tx by sending then generate 2 blocks; block1 has the tx in it
        tx = self.nodes[2].sendtoaddress(self.nodes[1].getnewaddress(), 1)
        block1, block2 = self.generate(self.nodes[2], 2)
        self.sync_all(synced_nodes)
        # We should be able to get the raw transaction by providing the correct
        # block
        gottx = self.nodes[0].getrawtransaction(tx, True, block1)
        assert_equal(gottx['txid'], tx)
        assert_equal(gottx['in_active_chain'], True)
        # We should not have the 'in_active_chain' flag when we don't provide a
        # block
        gottx = self.nodes[0].getrawtransaction(tx, True)
        assert_equal(gottx['txid'], tx)
        assert 'in_active_chain' not in gottx
        # We should not get the tx if we provide an unrelated block
        assert_raises_rpc_error(-5, "No such transaction found",
                                self.nodes[0].getrawtransaction, tx, True, block2)
        # An invalid block hash should raise the correct errors
        assert_raises_rpc_error(-1,
                                "JSON value is not a string as expected",
                                self.nodes[0].getrawtransaction,
                                tx,
                                True,
                                True)
        assert_raises_rpc_error(-8,
                                "parameter 3 must be of length 64 (not 6, for 'foobar')",
                                self.nodes[0].getrawtransaction,
                                tx,
                                True,
                                "foobar")
        assert_raises_rpc_error(-8,
                                "parameter 3 must be of length 64 (not 8, for 'abcd1234')",
                                self.nodes[0].getrawtransaction,
                                tx,
                                True,
                                "abcd1234")
        assert_raises_rpc_error(
            -8,
            "parameter 3 must be hexadecimal string (not 'ZZZ0000000000000000000000000000000000000000000000000000000000000')",
            self.nodes[0].getrawtransaction,
            tx,
            True,
            "ZZZ0000000000000000000000000000000000000000000000000000000000000")
        assert_raises_rpc_error(-5, "Block hash not found", self.nodes[0].getrawtransaction,
                                tx, True, "0000000000000000000000000000000000000000000000000000000000000000")
        # Undo the blocks and check in_active_chain
        self.nodes[0].invalidateblock(block1)
        gottx = self.nodes[0].getrawtransaction(
            txid=tx, verbose=True, blockhash=block1)
        assert_equal(gottx['in_active_chain'], False)
        self.nodes[0].reconsiderblock(block1)
        assert_equal(self.nodes[0].getbestblockhash(), block2)

        #
        # RAW TX MULTISIG TESTS #
        #
        # 2of2 test
        addr1 = self.nodes[2].getnewaddress()
        addr2 = self.nodes[2].getnewaddress()

        addr1Obj = self.nodes[2].getaddressinfo(addr1)
        addr2Obj = self.nodes[2].getaddressinfo(addr2)

        # Tests for createmultisig and addmultisigaddress
        assert_raises_rpc_error(-5, "Invalid public key",
                                self.nodes[0].createmultisig, 1, ["01020304"])
        # createmultisig can only take public keys
        self.nodes[0].createmultisig(
            2, [addr1Obj['pubkey'], addr2Obj['pubkey']])
        # addmultisigaddress can take both pubkeys and addresses so long as
        # they are in the wallet, which is tested here.
        assert_raises_rpc_error(-5, "Invalid public key",
                                self.nodes[0].createmultisig, 2, [addr1Obj['pubkey'], addr1])

        mSigObj = self.nodes[2].addmultisigaddress(
            2, [addr1Obj['pubkey'], addr1])['address']

        # use balance deltas instead of absolute values
        bal = self.nodes[2].getbalance()

        # send 1.2 BCH to msig adr
        txId = self.nodes[0].sendtoaddress(mSigObj, 1.2)
        self.sync_all(synced_nodes)
        self.generate(self.nodes[0], 1)
        self.sync_all(synced_nodes)
        # node2 has both keys of the 2of2 ms addr., tx should affect the
        # balance
        assert_equal(self.nodes[2].getbalance(), bal + Decimal('1.20000000'))

        # 2of3 test from different nodes
        bal = self.nodes[2].getbalance()
        addr1 = self.nodes[1].getnewaddress()
        addr2 = self.nodes[2].getnewaddress()
        addr3 = self.nodes[2].getnewaddress()

        addr1Obj = self.nodes[1].getaddressinfo(addr1)
        addr2Obj = self.nodes[2].getaddressinfo(addr2)
        addr3Obj = self.nodes[2].getaddressinfo(addr3)

        mSigObj = self.nodes[2].addmultisigaddress(
            2, [addr1Obj['pubkey'], addr2Obj['pubkey'], addr3Obj['pubkey']])['address']

        txId = self.nodes[0].sendtoaddress(mSigObj, 2.2)
        decTx = self.nodes[0].gettransaction(txId)
        rawTx = self.nodes[0].decoderawtransaction(decTx['hex'])
        self.sync_all(synced_nodes)
        self.generate(self.nodes[0], 1)
        self.sync_all(synced_nodes)

        # THIS IS AN INCOMPLETE FEATURE
        # NODE2 HAS TWO OF THREE KEY AND THE FUNDS SHOULD BE SPENDABLE AND
        # COUNT AT BALANCE CALCULATION
        # for now, assume the funds of a 2of3 multisig tx are not marked as
        # spendable
        assert_equal(self.nodes[2].getbalance(), bal)

        txDetails = self.nodes[0].gettransaction(txId, True)
        rawTx = self.nodes[0].decoderawtransaction(txDetails['hex'])
        vout = False
        for outpoint in rawTx['vout']:
            if outpoint['value'] == Decimal('2.20000000'):
                vout = outpoint
                break

        bal = self.nodes[0].getbalance()
        inputs = [{
            "txid": txId,
            "vout": vout['n'],
            "scriptPubKey": vout['scriptPubKey']['hex'],
            "amount": vout['value'],
        }]
        outputs = {self.nodes[0].getnewaddress(): 2.19}
        rawTx = self.nodes[2].createrawtransaction(inputs, outputs)
        rawTxPartialSigned = self.nodes[1].signrawtransactionwithwallet(
            rawTx, inputs)
        # node1 only has one key, can't comp. sign the tx
        assert_equal(rawTxPartialSigned['complete'], False)

        rawTxSigned = self.nodes[2].signrawtransactionwithwallet(rawTx, inputs)
        # node2 can sign the tx compl., own two of three keys
        assert_equal(rawTxSigned['complete'], True)
        hash = self.nodes[2].sendrawtransaction(rawTxSigned['hex'])
        rawTx = self.nodes[0].decoderawtransaction(rawTxSigned['hex'])
        self.sync_all(synced_nodes)
        self.generate(self.nodes[0], 1)
        self.sync_all(synced_nodes)
        firstSentTx = self.nodes[2].getrawtransaction(hash, True)
        assert_equal(self.nodes[0].getbalance(), bal + Decimal(
            '50.00000000') + Decimal('2.19000000'))  # block reward + tx

        rawTxBlock = self.nodes[0].getblock(self.nodes[0].getbestblockhash())

        # 2of2 test for combining transactions
        bal = self.nodes[2].getbalance()
        addr1 = self.nodes[1].getnewaddress()
        addr2 = self.nodes[2].getnewaddress()

        addr1Obj = self.nodes[1].getaddressinfo(addr1)
        addr2Obj = self.nodes[2].getaddressinfo(addr2)

        self.nodes[1].addmultisigaddress(
            2, [addr1Obj['pubkey'], addr2Obj['pubkey']])['address']
        mSigObj = self.nodes[2].addmultisigaddress(
            2, [addr1Obj['pubkey'], addr2Obj['pubkey']])['address']
        mSigObjValid = self.nodes[2].getaddressinfo(mSigObj)

        txId = self.nodes[0].sendtoaddress(mSigObj, 2.2)
        decTx = self.nodes[0].gettransaction(txId)
        rawTx2 = self.nodes[0].decoderawtransaction(decTx['hex'])
        self.sync_all(synced_nodes)
        self.generate(self.nodes[0], 1)
        self.sync_all(synced_nodes)

        # the funds of a 2of2 multisig tx should not be marked as spendable
        assert_equal(self.nodes[2].getbalance(), bal)

        txDetails = self.nodes[0].gettransaction(txId, True)
        rawTx2 = self.nodes[0].decoderawtransaction(txDetails['hex'])
        vout = False
        for outpoint in rawTx2['vout']:
            if outpoint['value'] == Decimal('2.20000000'):
                vout = outpoint
                break

        bal = self.nodes[0].getbalance()
        inputs = [{"txid": txId, "vout": vout['n'], "scriptPubKey": vout['scriptPubKey']
                   ['hex'], "redeemScript": mSigObjValid['hex'], "amount": vout['value']}]
        outputs = {self.nodes[0].getnewaddress(): 2.19}
        rawTx2 = self.nodes[2].createrawtransaction(inputs, outputs)
        rawTxPartialSigned1 = self.nodes[1].signrawtransactionwithwallet(
            rawTx2, inputs)
        self.log.debug(rawTxPartialSigned1)
        # node1 only has one key, can't comp. sign the tx
        assert_equal(rawTxPartialSigned1['complete'], False)

        rawTxPartialSigned2 = self.nodes[2].signrawtransactionwithwallet(
            rawTx2, inputs)
        self.log.debug(rawTxPartialSigned2)
        # node2 only has one key, can't comp. sign the tx
        assert_equal(rawTxPartialSigned2['complete'], False)
        rawTxComb = self.nodes[2].combinerawtransaction(
            [rawTxPartialSigned1['hex'], rawTxPartialSigned2['hex']])
        self.log.debug(rawTxComb)
        hash = self.nodes[2].sendrawtransaction(rawTxComb)
        multisigTxHash = hash # we will use it later for patterns test
        rawTx2 = self.nodes[0].decoderawtransaction(rawTxComb)

        self.sync_all(synced_nodes)
        self.generate(self.nodes[0], 1)
        self.sync_all(synced_nodes)
        lastSentTx = self.nodes[2].getrawtransaction(hash, True)
        assert_equal(self.nodes[0].getbalance(
        ), bal + Decimal('50.00000000') + Decimal('2.19000000'))  # block reward + tx

        # getrawtransaction tests
        # 1. valid parameters - only supply txid
        txHash = rawTx["hash"]
        assert_equal(
            self.nodes[0].getrawtransaction(txHash), rawTxSigned['hex'])

        # 2. valid parameters - supply txid and 0 for non-verbose
        assert_equal(
            self.nodes[0].getrawtransaction(txHash, 0), rawTxSigned['hex'])

        # 3. valid parameters - supply txid and False for non-verbose
        assert_equal(self.nodes[0].getrawtransaction(
            txHash, False), rawTxSigned['hex'])

        # 4. valid parameters - supply txid and 1 for verbose.
        # We only check the "hex" field of the output so we don't need to
        # update this test every time the output format changes.
        assert_equal(self.nodes[0].getrawtransaction(
            txHash, 1)["hex"], rawTxSigned['hex'])

        # 5. valid parameters - supply txid and True for non-verbose
        assert_equal(self.nodes[0].getrawtransaction(
            txHash, True)["hex"], rawTxSigned['hex'])

        # 6. invalid parameters - supply txid and string "Flase"
        assert_raises_rpc_error(
            -1, "not an integer", self.nodes[0].getrawtransaction, txHash, "False")

        # 7. invalid parameters - supply txid and empty array
        assert_raises_rpc_error(
            -1, "not an integer", self.nodes[0].getrawtransaction, txHash, [])

        # 8. invalid parameters - supply txid and empty dict
        assert_raises_rpc_error(
            -1, "not an integer", self.nodes[0].getrawtransaction, txHash, {})

        # Sanity checks on verbose getrawtransaction output
        rawTxOutput = self.nodes[0].getrawtransaction(txHash, True)
        assert_equal(rawTxOutput["hex"], rawTxSigned["hex"])
        assert_equal(rawTxOutput["txid"], txHash)
        assert_equal(rawTxOutput["hash"], txHash)
        assert_greater_than(rawTxOutput["size"], 300)
        assert_equal(rawTxOutput["version"], 0x02)
        assert_equal(rawTxOutput["locktime"], 0)
        assert_equal(len(rawTxOutput["vin"]), 1)
        assert_equal(len(rawTxOutput["vout"]), 1)
        assert_equal(rawTxOutput["blockhash"], rawTxBlock["hash"])
        assert_equal(rawTxOutput["confirmations"], 3)
        assert_equal(rawTxOutput["time"], rawTxBlock["time"])
        assert_equal(rawTxOutput["blocktime"], rawTxBlock["time"])

        inputs = [
            {'txid': "1d1d4e24ed99057e84c3f80fd8fbec79ed9e1acee37da269356ecea000000000", 'sequence': 1000}]
        outputs = {self.nodes[0].getnewaddress(): 1}
        assert_raises_rpc_error(
            -8, 'Invalid parameter, missing vout key',
            self.nodes[0].createrawtransaction, inputs, outputs)

        inputs[0]['vout'] = "1"
        assert_raises_rpc_error(
            -8, 'Invalid parameter, vout must be a number',
            self.nodes[0].createrawtransaction, inputs, outputs)

        inputs[0]['vout'] = -1
        assert_raises_rpc_error(
            -8, 'Invalid parameter, vout must be positive',
            self.nodes[0].createrawtransaction, inputs, outputs)

        inputs[0]['vout'] = 1
        rawtx = self.nodes[0].createrawtransaction(inputs, outputs)
        decrawtx = self.nodes[0].decoderawtransaction(rawtx)
        assert_equal(decrawtx['vin'][0]['sequence'], 1000)

        # 9. invalid parameters - sequence number out of range
        inputs[0]['sequence'] = -1
        assert_raises_rpc_error(
            -8, 'Invalid parameter, sequence number is out of range',
            self.nodes[0].createrawtransaction, inputs, outputs)

        # 10. invalid parameters - sequence number out of range
        inputs[0]['sequence'] = 4294967296
        assert_raises_rpc_error(
            -8, 'Invalid parameter, sequence number is out of range',
            self.nodes[0].createrawtransaction, inputs, outputs)

        inputs[0]['sequence'] = 4294967294
        rawtx = self.nodes[0].createrawtransaction(inputs, outputs)
        decrawtx = self.nodes[0].decoderawtransaction(rawtx)
        assert_equal(decrawtx['vin'][0]['sequence'], 4294967294)

        ####################################
        # TRANSACTION VERSION NUMBER TESTS #
        ####################################

        # Test the minimum transaction version number that fits in a signed
        # 32-bit integer.
        tx = CTransaction()
        tx.nVersion = -0x80000000
        rawtx = ToHex(tx)
        decrawtx = self.nodes[0].decoderawtransaction(rawtx)
        assert_equal(decrawtx['version'], -0x80000000)

        # Test the maximum transaction version number that fits in a signed
        # 32-bit integer.
        tx = CTransaction()
        tx.nVersion = 0x7fffffff
        rawtx = ToHex(tx)
        decrawtx = self.nodes[0].decoderawtransaction(rawtx)
        assert_equal(decrawtx['version'], 0x7fffffff)

        ##########################################
        # Decoding weird scripts in transactions #
        ##########################################

        self.log.info('Decode correctly-formatted but weird transactions')
        tx = CTransaction()
        # empty
        self.nodes[0].decoderawtransaction(ToHex(tx))
        # truncated push
        tx.vin.append(CTxIn(COutPoint(42, 0), b'\x4e\x00\x00'))
        tx.vin.append(CTxIn(COutPoint(42, 0), b'\x4c\x10TRUNC'))
        tx.vout.append(CTxOut(0, b'\x4e\x00\x00'))
        tx.vout.append(CTxOut(0, b'\x4c\x10TRUNC'))
        self.nodes[0].decoderawtransaction(ToHex(tx))
        # giant pushes and long scripts
        tx.vin.append(
            CTxIn(COutPoint(42, 0), CScript([b'giant push' * 10000])))
        tx.vout.append(CTxOut(0, CScript([b'giant push' * 10000])))
        self.nodes[0].decoderawtransaction(ToHex(tx))

        self.log.info('Refuse garbage after transaction')
        assert_raises_rpc_error(-22, 'TX decode failed',
                                self.nodes[0].decoderawtransaction, ToHex(tx) + '00')

        # 11. getrawtransaction verbosity level 2
        # confirm all pending transactions
        self.generate(self.nodes[0], 1)
        self.sync_all(synced_nodes)

        def assert_raises_if_no_undo_but_works_otherwise(code, msg, node_num, *args):
            datadir = get_datadir_path(self.options.tmpdir, node_num)
            node = self.nodes[0]

            def move_undo_file(old, new):
                old_path = os.path.join(datadir, self.chain, 'blocks', old)
                new_path = os.path.join(datadir, self.chain, 'blocks', new)
                os.rename(old_path, new_path)
                self.log.info(f"Moved {old} -> {new} (node {node_num})")

            # Move undo file(s) out of the way
            files = []
            for i in range(99999):
                try:
                    old, new = f'rev{i:05}.dat', f'rev_wrong_{i:05}'
                    move_undo_file(old, new)
                    files.append((old, new))
                except FileNotFoundError:
                    break  # Break out of loop on first missing undo file
            try:
                assert_raises_rpc_error(code, msg, node.getrawtransaction, *args)
            finally:
                # restore undo file(s)
                for old, new in files:
                    move_undo_file(new, old)

            # Finally, try the above again and it should not raise
            return node.getrawtransaction(*args)

        # 11.1 working with past transaction, prevout of which is in past block, also not present in coin database
        # no -txindex enabled node
        result0_no_bh = assert_raises_if_no_undo_but_works_otherwise(
            -5, "for fee calculation. An input's transaction was not found in the mempool or blockchain. Use -txindex",
            0, firstSentTx["hash"], 2)
        result0_bh = assert_raises_if_no_undo_but_works_otherwise(
            -5, "for fee calculation. An input's transaction was not found in the mempool or blockchain. Use -txindex",
            0, firstSentTx["hash"], 2, firstSentTx["blockhash"])

        # disconnected node
        assert_raises_rpc_error(
            -5, "No such mempool or blockchain transaction. Use gettransaction for wallet transactions",
            self.nodes[4].getrawtransaction, firstSentTx["hash"], 2)
        assert_raises_rpc_error(
            -5, "Block hash not found", self.nodes[4].getrawtransaction, firstSentTx["hash"], 2, firstSentTx["blockhash"])

        # -txindex enabled node
        result_no_bh = result = self.nodes[1].getrawtransaction(firstSentTx["hash"], 2)
        assert_equal(result0_no_bh, result_no_bh)
        assert_equal(result["vin"][0]["value"], Decimal('2.20'))
        assert_equal(result["vout"][0]["value"], Decimal('2.19'))
        assert_equal(result["fee"], Decimal('0.01'))
        result_bh = result = self.nodes[1].getrawtransaction(firstSentTx["hash"], 2, firstSentTx["blockhash"])
        assert_equal(result0_bh, result_bh)
        assert_equal(result["vin"][0]["value"], Decimal('2.20'))
        assert_equal(result["vout"][0]["value"], Decimal('2.19'))
        assert_equal(result["fee"], Decimal('0.01'))

        # pruning node
        assert_equal(result_no_bh, self.nodes[3].getrawtransaction(firstSentTx["hash"], 2))
        assert_equal(result_bh, self.nodes[3].getrawtransaction(firstSentTx["hash"], 2, firstSentTx["blockhash"]))

        # 11.2 make new mempool transaction spending confirmed transaction
        inputs = [{'txid': lastSentTx["hash"], 'vout': 0}]
        input_0 = lastSentTx["vout"][0]
        outputs = multidict([(self.nodes[0].getnewaddress(), 2.00), (self.nodes[0].getnewaddress(), 0.18)])
        rawtx = self.nodes[0].createrawtransaction(inputs, outputs)
        rawtx = self.nodes[0].signrawtransactionwithwallet(rawtx)
        rawtx, rawtx['hex'] = (self.nodes[0].decoderawtransaction(rawtx['hex']),rawtx['hex'])
        hash = self.nodes[0].sendrawtransaction(rawtx['hex'])
        lastSentTx = self.nodes[0].getrawtransaction(hash, True)
        self.sync_all(synced_nodes)

        # 11.3 checks
        # no -txindex enabled node, tx is in mempool and prevout is in coin database
        self.nodes[0].getrawtransaction(lastSentTx["hash"], 2)

        # disconnected node
        assert_raises_rpc_error(
            -5, "No such mempool or blockchain transaction. Use gettransaction for wallet transactions", self.nodes[4].getrawtransaction, lastSentTx["hash"], 2)

        # -txindex enabled node
        result = self.nodes[1].getrawtransaction(lastSentTx["hash"], 2)
        # Check verbosity=2 "value" on inputs
        assert_equal(result["vin"][0]["value"], Decimal('2.19'))
        # Check verbosity=2 "scriptPubKey" on inputs
        assert_equal(result["vin"][0]["scriptPubKey"]["address"], input_0["scriptPubKey"]["addresses"][0])
        assert_equal(result["vin"][0]["scriptPubKey"]["asm"], input_0["scriptPubKey"]["asm"])
        assert_equal(result["vin"][0]["scriptPubKey"]["hex"], input_0["scriptPubKey"]["hex"])
        assert_equal(result["vin"][0]["scriptPubKey"]["type"], input_0["scriptPubKey"]["type"])
        assert_equal(result["vout"][0]["value"], Decimal('2.00'))
        assert_equal(result["vout"][1]["value"], Decimal('0.18'))
        assert_equal(result["fee"], Decimal('0.01'))

        # pruning node, tx is in mempool and prevout is in coin database
        self.nodes[3].getrawtransaction(lastSentTx["hash"], 2)

        # 11.4 send another transaction to mempool, which spends the previous tx already in mempool
        # this transaction also spends two inputs from previous one, allowing to hit the tx cache
        inputs = [{'txid': lastSentTx["hash"], 'vout': 0}, {'txid': lastSentTx["hash"], 'vout': 1}]
        outputs = {self.nodes[0].getnewaddress(): 2.17}
        rawtx = self.nodes[0].createrawtransaction(inputs, outputs)
        rawtx = self.nodes[0].signrawtransactionwithwallet(rawtx)
        rawtx, rawtx['hex'] = (self.nodes[0].decoderawtransaction(rawtx['hex']),rawtx['hex'])
        hash = self.nodes[0].sendrawtransaction(rawtx['hex'])
        lastSentTx = self.nodes[0].getrawtransaction(hash, True)
        self.sync_all(synced_nodes)

        # 11.5 checks
        # no -txindex enabled node, both transaction are findable, no exception
        self.nodes[0].getrawtransaction(rawtx["hash"], 2)

        # disconnected node
        assert_raises_rpc_error(
            -5, "No such mempool or blockchain transaction. Use gettransaction for wallet transactions", self.nodes[4].getrawtransaction, rawtx["hash"], 2)

        # -txindex enabled node
        result = self.nodes[1].getrawtransaction(rawtx["hash"], 2)
        assert_equal(result["vin"][0]["value"], Decimal('2.00'))
        assert_equal(result["vin"][1]["value"], Decimal('0.18'))
        assert_equal(result["vout"][0]["value"], Decimal('2.17'))
        assert_equal(result["fee"], Decimal('0.01'))

        # pruning node, both transaction are findable in mempool, no exception
        self.nodes[3].getrawtransaction(lastSentTx["hash"], 2)


        # 11.6 same block
        # confirm all pending transactions
        # now we have a spending transaction and output being spent in the same block
        self.generate(self.nodes[0], 1)
        self.sync_all(synced_nodes)

        lastSentTx = self.nodes[0].getrawtransaction(hash, True)

        # no -txindex enabled node, will not find all input to tx without undo info, but works otherwise
        res = assert_raises_if_no_undo_but_works_otherwise(
            -5, "for fee calculation. An input's transaction was not found in the mempool or blockchain. Use -txindex",
            0, lastSentTx["hash"], 2)
        # Test also with blockhash param
        res2 = self.nodes[0].getrawtransaction(lastSentTx["hash"], 2, lastSentTx["blockhash"])

        # disconnected node
        assert_raises_rpc_error(
            -5, "No such mempool or blockchain transaction. Use gettransaction for wallet transactions", self.nodes[4].getrawtransaction, lastSentTx["hash"], 2)
        assert_raises_rpc_error(
            -5, "Block hash not found", self.nodes[4].getrawtransaction, lastSentTx["hash"], 2, lastSentTx["blockhash"])

        # -txindex enabled node
        result = result_no_bh = self.nodes[1].getrawtransaction(lastSentTx["hash"], 2)
        assert_equal(result["vin"][0]["value"], Decimal('2.00'))
        assert_equal(result["vin"][1]["value"], Decimal('0.18'))
        assert_equal(result["vout"][0]["value"], Decimal('2.17'))
        assert_equal(result["fee"], Decimal('0.01'))
        assert_equal(res, result)
        result = result_bh = self.nodes[1].getrawtransaction(lastSentTx["hash"], 2, lastSentTx["blockhash"])
        assert_equal(result["vin"][0]["value"], Decimal('2.00'))
        assert_equal(result["vin"][1]["value"], Decimal('0.18'))
        assert_equal(result["vout"][0]["value"], Decimal('2.17'))
        assert_equal(result["fee"], Decimal('0.01'))
        assert_equal(res2, result)

        # pruning node, will find tx due to lookup in coins db
        res = self.nodes[3].getrawtransaction(lastSentTx["hash"], 2)
        assert_equal(res, result_no_bh)
        # will find all txs in the same block as well if given a blockhash
        res = self.nodes[3].getrawtransaction(lastSentTx["hash"], 2, lastSentTx["blockhash"])
        assert_equal(res, result_bh)

        # Test coinbase txn always is missing fee, never has an error
        for node in synced_nodes:
            block_hash = node.getbestblockhash()
            cb_txid = node.getblock(block_hash, 1)["tx"][0]
            result = node.getrawtransaction(cb_txid, 2, block_hash)
            assert "fee" not in result

        # 11.7 Bytecode patterns tests
        # Note: we use the multisig tx created above so we're sure to have a redeemScript
        def check_bcp_keys(bcp, *extra_keys):
            """Check that byteCodePattern dict has at least these 4 keys"""
            assert_equal({'fingerprint', 'pattern', 'patternAsm', 'data', *extra_keys} - set(bcp.keys()), set())
        # Check verbosity=1 patterns=True
        result = self.nodes[1].getrawtransaction(multisigTxHash, 1, "", True)
        check_bcp_keys(result["vin"][0]["scriptSig"]["byteCodePattern"])
        check_bcp_keys(result["vout"][0]["scriptPubKey"]["byteCodePattern"])
        # Check verbosity=2 patterns=True
        result = self.nodes[1].getrawtransaction(multisigTxHash, 2, "", True)
        check_bcp_keys(result["vin"][0]["scriptSig"]["byteCodePattern"])
        check_bcp_keys(result["vin"][0]["scriptPubKey"]["byteCodePattern"])
        check_bcp_keys(result["vout"][0]["scriptPubKey"]["byteCodePattern"])
        result = self.nodes[1].getrawtransaction(multisigTxHash, 2, "", True)
        check_bcp_keys(result["vin"][0]["scriptSig"]["redeemScript"]["byteCodePattern"])

        # Check patterns=False has no patterns for verbosity 1 and 2
        def assert_scripts_do_not_contain_bytecodepattern(tx):
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

        assert_scripts_do_not_contain_bytecodepattern(self.nodes[1].getrawtransaction(multisigTxHash, 1))
        assert_scripts_do_not_contain_bytecodepattern(self.nodes[1].getrawtransaction(multisigTxHash, 1, ""))
        assert_scripts_do_not_contain_bytecodepattern(self.nodes[1].getrawtransaction(multisigTxHash, 1, "", False))
        assert_scripts_do_not_contain_bytecodepattern(self.nodes[1].getrawtransaction(multisigTxHash, 2))
        assert_scripts_do_not_contain_bytecodepattern(self.nodes[1].getrawtransaction(multisigTxHash, 2, ""))
        assert_scripts_do_not_contain_bytecodepattern(self.nodes[1].getrawtransaction(multisigTxHash, 2, "", False))


if __name__ == '__main__':
    RawTransactionsTest().main()
