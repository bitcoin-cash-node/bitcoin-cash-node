#!/usr/bin/env python3
# Copyright (c) 2018-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the Partially Signed Transaction RPCs.
"""

import json
import os

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
    connect_nodes_bi,
    find_output,
)

# Create one-input, one-output, no-fee transaction:


class PSBTTest(BitcoinTestFramework):

    def set_test_params(self):
        self.setup_clean_chain = False
        self.num_nodes = 3

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        # Create and fund a raw tx for sending 10 BTC
        psbtx1 = self.nodes[0].walletcreatefundedpsbt(
            [], {self.nodes[2].getnewaddress(): 10})['psbt']

        # Node 1 should not be able to add anything to it but still return the
        # psbtx same as before
        psbtx = self.nodes[1].walletprocesspsbt(psbtx1)['psbt']
        assert_equal(psbtx1, psbtx)

        # Sign the transaction and send
        signed_tx = self.nodes[0].walletprocesspsbt(psbtx)['psbt']
        final_tx = self.nodes[0].finalizepsbt(signed_tx)['hex']
        self.nodes[0].sendrawtransaction(final_tx)

        # Create p2sh, p2pkh addresses
        pubkey0 = self.nodes[0].getaddressinfo(
            self.nodes[0].getnewaddress())['pubkey']
        pubkey1 = self.nodes[1].getaddressinfo(
            self.nodes[1].getnewaddress())['pubkey']
        pubkey2 = self.nodes[2].getaddressinfo(
            self.nodes[2].getnewaddress())['pubkey']
        p2sh = self.nodes[1].addmultisigaddress(
            2, [pubkey0, pubkey1, pubkey2], "")['address']
        p2pkh = self.nodes[1].getnewaddress("")

        # fund those addresses
        rawtx = self.nodes[0].createrawtransaction([], {p2sh: 10, p2pkh: 10})
        rawtx = self.nodes[0].fundrawtransaction(rawtx, {"changePosition": 0})
        signed_tx = self.nodes[0].signrawtransactionwithwallet(rawtx['hex'])[
            'hex']
        txid = self.nodes[0].sendrawtransaction(signed_tx)
        self.generate(self.nodes[0], 6)
        self.sync_all()

        # Find the output pos
        p2sh_pos = -1
        p2pkh_pos = -1
        decoded = self.nodes[0].decoderawtransaction(signed_tx)
        for out in decoded['vout']:
            if out['scriptPubKey']['addresses'][0] == p2sh:
                p2sh_pos = out['n']
            elif out['scriptPubKey']['addresses'][0] == p2pkh:
                p2pkh_pos = out['n']

        # spend single key from node 1
        rawtx = self.nodes[1].walletcreatefundedpsbt([{"txid": txid, "vout": p2pkh_pos}], {
                                                     self.nodes[1].getnewaddress(): 9.99})['psbt']
        walletprocesspsbt_out = self.nodes[1].walletprocesspsbt(rawtx)
        assert_equal(walletprocesspsbt_out['complete'], True)
        self.nodes[1].sendrawtransaction(
            self.nodes[1].finalizepsbt(walletprocesspsbt_out['psbt'])['hex'])

        # partially sign multisig things with node 1
        psbtx = self.nodes[1].walletcreatefundedpsbt([{"txid": txid, "vout": p2sh_pos}], {
                                                     self.nodes[1].getnewaddress(): 9.99})['psbt']
        walletprocesspsbt_out = self.nodes[1].walletprocesspsbt(psbtx)
        psbtx = walletprocesspsbt_out['psbt']
        assert_equal(walletprocesspsbt_out['complete'], False)

        # partially sign with node 2. This should be complete and sendable
        walletprocesspsbt_out = self.nodes[2].walletprocesspsbt(psbtx)
        assert_equal(walletprocesspsbt_out['complete'], True)
        self.nodes[2].sendrawtransaction(
            self.nodes[2].finalizepsbt(walletprocesspsbt_out['psbt'])['hex'])

        # check that walletprocesspsbt fails to decode a non-psbt
        rawtx = self.nodes[1].createrawtransaction([{"txid": txid, "vout": p2pkh_pos}], {
                                                   self.nodes[1].getnewaddress(): 9.99})
        assert_raises_rpc_error(-22, "TX decode failed",
                                self.nodes[1].walletprocesspsbt, rawtx)

        # Convert a non-psbt to psbt and make sure we can decode it
        rawtx = self.nodes[0].createrawtransaction(
            [], {self.nodes[1].getnewaddress(): 10})
        rawtx = self.nodes[0].fundrawtransaction(rawtx)
        new_psbt = self.nodes[0].converttopsbt(rawtx['hex'])
        self.nodes[0].decodepsbt(new_psbt)

        # Explicilty allow converting non-empty txs
        new_psbt = self.nodes[0].converttopsbt(rawtx['hex'])
        self.nodes[0].decodepsbt(new_psbt)

        # Create outputs to nodes 1 and 2
        node1_addr = self.nodes[1].getnewaddress()
        node2_addr = self.nodes[2].getnewaddress()
        txid1 = self.nodes[0].sendtoaddress(node1_addr, 13)
        txid2 = self.nodes[0].sendtoaddress(node2_addr, 13)
        self.generate(self.nodes[0], 6)
        self.sync_all()
        vout1 = find_output(self.nodes[1], txid1, 13)
        vout2 = find_output(self.nodes[2], txid2, 13)

        # Create a psbt spending outputs from nodes 1 and 2
        psbt_orig = self.nodes[0].createpsbt([{"txid": txid1, "vout": vout1}, {
                                             "txid": txid2, "vout": vout2}], {self.nodes[0].getnewaddress(): 25.999})

        # Update psbts, should only have data for one input and not the other
        psbt1 = self.nodes[1].walletprocesspsbt(psbt_orig)['psbt']
        psbt1_decoded = self.nodes[0].decodepsbt(psbt1)
        assert psbt1_decoded['inputs'][0] and not psbt1_decoded['inputs'][1]
        psbt2 = self.nodes[2].walletprocesspsbt(psbt_orig)['psbt']
        psbt2_decoded = self.nodes[0].decodepsbt(psbt2)
        assert not psbt2_decoded['inputs'][0] and psbt2_decoded['inputs'][1]

        # Combine, finalize, and send the psbts
        combined = self.nodes[0].combinepsbt([psbt1, psbt2])
        finalized = self.nodes[0].finalizepsbt(combined)['hex']
        self.nodes[0].sendrawtransaction(finalized)
        self.generate(self.nodes[0], 6)
        self.sync_all()

        block_height = self.nodes[0].getblockcount()
        unspent = self.nodes[0].listunspent()[0]

        # Make sure change address wallet does not have P2SH innerscript access to results in success
        # when attempting BnB coin selection
        self.nodes[0].walletcreatefundedpsbt(
            [],
            [{self.nodes[2].getnewaddress():unspent["amount"] + 1}],
            block_height + 2,
            {"changeAddress": self.nodes[1].getnewaddress()},
            False)

        # Regression test for 14473 (mishandling of already-signed
        # transaction):
        psbtx_info = self.nodes[0].walletcreatefundedpsbt([{"txid": unspent["txid"], "vout":unspent["vout"]}], [
                                                          {self.nodes[2].getnewaddress():unspent["amount"] + 1}])
        complete_psbt = self.nodes[0].walletprocesspsbt(psbtx_info["psbt"])
        double_processed_psbt = self.nodes[0].walletprocesspsbt(
            complete_psbt["psbt"])
        assert_equal(complete_psbt, double_processed_psbt)
        # We don't care about the decode result, but decoding must succeed.
        self.nodes[0].decodepsbt(double_processed_psbt["psbt"])

        # Make sure unsafe inputs are included if specified
        self.nodes[2].createwallet(wallet_name="unsafe")
        wunsafe = self.nodes[2].get_wallet_rpc("unsafe")
        self.nodes[0].sendtoaddress(wunsafe.getnewaddress(), 2)
        self.sync_all()
        assert_raises_rpc_error(-4, "Insufficient funds", wunsafe.walletcreatefundedpsbt, [], [{self.nodes[0].getnewaddress(): 1}])
        wunsafe.walletcreatefundedpsbt([], [{self.nodes[0].getnewaddress(): 1}], 0, {"include_unsafe": True})

        # BIP 174 Test Vectors

        # Check that unknown values are just passed through
        unknown_psbt = "cHNidP8BAD8CAAAAAf//////////////////////////////////////////AAAAAAD/////AQAAAAAAAAAAA2oBAAAAAAAACg8BAgMEBQYHCAkPAQIDBAUGBwgJCgsMDQ4PAAA="
        unknown_out = self.nodes[0].walletprocesspsbt(unknown_psbt)['psbt']
        assert_equal(unknown_psbt, unknown_out)

        # Open the data file
        with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data/rpc_psbt.json'), encoding='utf-8') as f:
            d = json.load(f)
            invalids = d['invalid']
            valids = d['valid']
            creators = d['creator']
            signers = d['signer']
            combiners = d['combiner']
            finalizers = d['finalizer']
            extractors = d['extractor']

        # Invalid PSBTs
        for invalid in invalids:
            assert_raises_rpc_error(-22, "TX decode failed",
                                    self.nodes[0].decodepsbt, invalid)

        # Valid PSBTs
        for valid in valids:
            self.nodes[0].decodepsbt(valid)

        # Creator Tests
        for creator in creators:
            created_tx = self.nodes[0].createpsbt(
                creator['inputs'], creator['outputs'])
            assert_equal(created_tx, creator['result'])

        # The remainder of these tests must use ECDSA signing since that's what the vectors were created with
        self.restart_node(2, ["-nosignschnorr"])

        # Signer tests
        for i, signer in enumerate(signers):
            self.nodes[2].createwallet("wallet{}".format(i))
            wrpc = self.nodes[2].get_wallet_rpc("wallet{}".format(i))
            for key in signer['privkeys']:
                wrpc.importprivkey(key)
            signed_tx = wrpc.walletprocesspsbt(signer['psbt'])['psbt']
            assert_equal(signed_tx, signer['result'])

        # Combiner test
        for combiner in combiners:
            combined = self.nodes[2].combinepsbt(combiner['combine'])
            assert_equal(combined, combiner['result'])

        # Empty combiner test
        assert_raises_rpc_error(-8,
                                "Parameter 'txs' cannot be empty",
                                self.nodes[0].combinepsbt,
                                [])

        # Finalizer test
        for finalizer in finalizers:
            finalized = self.nodes[2].finalizepsbt(
                finalizer['finalize'], False)['psbt']
            assert_equal(finalized, finalizer['result'])

        # Extractor test
        for extractor in extractors:
            extracted = self.nodes[2].finalizepsbt(
                extractor['extract'], True)['hex']
            assert_equal(extracted, extractor['result'])

        # Test decoding error: invalid base64
        assert_raises_rpc_error(-22,
                                "TX decode failed invalid base64",
                                self.nodes[0].decodepsbt,
                                ";definitely not base64;")

        # Test that psbts with p2pkh outputs are created properly
        p2pkh = self.nodes[0].getnewaddress()
        psbt = self.nodes[1].walletcreatefundedpsbt(
            [], [{p2pkh: 1}], 0, {"includeWatching": True}, True)
        self.nodes[0].decodepsbt(psbt['psbt'])


class BCHNIssue440Test (BitcoinTestFramework):
    '''
    Regression test for bugfix (backport of D6029, D6030) for BCHN issue #440
    https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/issues/440
    '''
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self, split=False):
        self.setup_nodes()
        connect_nodes_bi(self.nodes[0], self.nodes[1])

    def run_test(self):
        self.log.info("Mining blocks...")
        self.generate(self.nodes[1], 101)
        #self.sync_all(self.nodes[0:1])
        self.sync_all()
        # Node 1 sync test
        assert_equal(self.nodes[1].getblockcount(), 101)
        assert_equal(self.nodes[1].getbalance(), 50)
        timestamp = self.nodes[1].getblock(
            self.nodes[1].getbestblockhash())['mediantime']

        # get two addresses on node 0, for import as watchonly on node 1.
        # the first will later be be funded, and the second
        # will be a change address for walletcreatefundedpsbt
        self.log.info("Create new addresses on node 0...")
        node0_address1 = self.nodes[0].getaddressinfo(self.nodes[0].getnewaddress())
        node0_address2 = self.nodes[0].getaddressinfo(self.nodes[0].getnewaddress())

        # Check addresses
        assert_equal(node0_address1['ismine'], True)
        assert_equal(node0_address2['ismine'], True)

        # Address Test - before import
        for addr_info in [node0_address1, node0_address2]:
            check_address_info = self.nodes[1].getaddressinfo(addr_info['address'])
            assert_equal(check_address_info['iswatchonly'], False)
            assert_equal(check_address_info['ismine'], False)

        # RPC importmulti on node 1
        self.log.info("Import the addresses on node 1, watch-only")
        for addr in [node0_address1, node0_address2]:
            address_info = self.nodes[0].getaddressinfo(addr['address'])
            result = self.nodes[1].importmulti([{
                "scriptPubKey": {
                    "address": address_info['address']
                },
                "timestamp": "now",
                "watchonly": True,
            }])
            assert_equal(result[0]['success'], True)
            address_assert = self.nodes[1].getaddressinfo(addr['address'])
            assert_equal(address_assert['iswatchonly'], True)
            assert_equal(address_assert['ismine'], False)
            assert_equal(address_assert['timestamp'], timestamp)
            assert_equal(address_assert['ischange'], False)

        # Fund the first address with 0.5 BCH
        self.nodes[1].sendtoaddress(node0_address1['address'], 0.5)

        # Mine it, check blockchain state on both nodes
        self.generate(self.nodes[1], 1)
        self.sync_all(self.nodes[0:1])
        assert_equal(self.nodes[0].getblockcount(), 102)
        assert_equal(self.nodes[1].getblockcount(), 102)
        assert_equal(self.nodes[0].getbalance(), 0.5)

        # RPC walletcreatefundedpsbt on node 0
        # see if it crashes the node :)
        psbt = self.nodes[1].walletcreatefundedpsbt(
                      # inputs
                      [],
                      # outputs
                      [{node0_address1['address']: 0.1}],
                      # locktime
                      0,
                      # options
                      {"changeAddress": node0_address2['address'],
                       "includeWatching": True},
                      # bip32derivs
                      True
                    )
        self.log.info(psbt)
        # Check that it decodes on both nodes
        for node_num in (0, 1):
            psbt_decoded = self.nodes[node_num].decodepsbt(psbt['psbt'])
            self.log.info("decoded PSBT on node {}: {}".format(node_num,
                                                               psbt_decoded))


if __name__ == '__main__':
    PSBTTest().main()
    BCHNIssue440Test().main()
