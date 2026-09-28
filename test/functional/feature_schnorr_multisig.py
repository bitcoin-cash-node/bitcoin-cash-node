#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Cash Node developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Schnorr/ECDSA interaction for multisig signing and assembly.

Consensus allows a CHECKMULTISIG input to be all-Schnorr (bitfield) or
all-ECDSA (null dummy), never a mix. The scheme a node uses for its own
signatures is set by -signschnorr, but assembling signatures produced
elsewhere must depend only on those signatures, never on local config.

Covers:
  - a node configured for Schnorr assembling foreign all-ECDSA signatures,
    via combinerawtransaction and via finalizepsbt (keyless roles),
  - the mirror case: a node configured for ECDSA assembling all-Schnorr ones,
  - mixing the two schemes on one input is refused with an explicit error
    rather than yielding a transaction the network rejects,
  - -signschnorr reaching the wallet's own signing.
"""
from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal, assert_greater_than_or_equal, assert_raises_rpc_error, find_output
)

# Size in bytes of a Schnorr signature plus its sighash-type byte. ECDSA
# signatures are DER and are never this length by consensus.
SCHNORR_SIG_LEN = 65
MIX_ERR = "mixes both Schnorr and ECDSA signatures"


class SchnorrMultisigTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        self.setup_clean_chain = True
        # node0 signs Schnorr (the default), node1 signs ECDSA, node2 signs
        # Schnorr and is only ever used for its keyless assembly roles.
        self.extra_args = [[], ["-signschnorr=0"], []]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def make_multisig(self, nkeys, required):
        """Return (address, redeem_script, [privkeys]) for a fresh m-of-n."""
        privkeys, pubkeys = [], []
        for _ in range(nkeys):
            addr = self.nodes[0].getnewaddress()
            privkeys.append(self.nodes[0].dumpprivkey(addr))
            pubkeys.append(self.nodes[0].getaddressinfo(addr)["pubkey"])
        ms = self.nodes[0].createmultisig(required, pubkeys)
        return ms["address"], ms["redeemScript"], privkeys

    def fund(self, address, amount=Decimal("1.0")):
        """Send to address, confirm, and return an input descriptor for it."""
        txid = self.nodes[0].sendtoaddress(address, amount)
        self.generate(self.nodes[0], 1)
        self.sync_all()
        raw = self.nodes[0].getrawtransaction(txid, True)
        vout = find_output(self.nodes[0], txid, amount)
        return {
            "txid": txid,
            "vout": vout,
            "scriptPubKey": raw["vout"][vout]["scriptPubKey"]["hex"],
            "amount": amount,
        }

    def spend_tx(self, txin, redeem_script):
        """Build an unsigned spend of txin, plus the prevtx list for signing."""
        outputs = {self.nodes[0].getnewaddress(): txin["amount"] - Decimal("0.001")}
        rawtx = self.nodes[0].createrawtransaction(
            [{"txid": txin["txid"], "vout": txin["vout"]}], outputs)
        prevtxs = [dict(txin, redeemScript=redeem_script)]
        return rawtx, prevtxs

    @staticmethod
    def script_pushes(script_hex):
        """Data pushed by a push-only script, in order.

        decoderawtransaction's "asm" strips the sighash byte off a signature and
        appends a [ALL|FORKID] annotation, so it cannot be used to measure
        signature lengths. Parse the script itself instead.
        """
        script = bytes.fromhex(script_hex)
        pushes, i = [], 0
        while i < len(script):
            op = script[i]
            i += 1
            if op == 0x00:          # OP_0 pushes an empty element
                pushes.append(b"")
                continue
            if op <= 0x4b:          # direct push
                size = op
            elif op == 0x4c:        # OP_PUSHDATA1
                size = script[i]
                i += 1
            elif op == 0x4d:        # OP_PUSHDATA2
                size = int.from_bytes(script[i:i + 2], "little")
                i += 2
            elif op == 0x4e:        # OP_PUSHDATA4
                size = int.from_bytes(script[i:i + 4], "little")
                i += 4
            else:
                # OP_1NEGATE / OP_1..OP_16: single-byte values, used for the
                # Schnorr multisig bitfield when it encodes minimally.
                pushes.append(bytes([0x81 if op == 0x4f else op - 0x50]))
                continue
            pushes.append(script[i:i + size])
            i += size
        return pushes

    def input_sig_lengths(self, node, tx_hex, n=0):
        """Signature lengths in input n's scriptSig, excluding dummy and redeemScript."""
        decoded = node.decoderawtransaction(tx_hex)
        pushes = self.script_pushes(decoded["vin"][n]["scriptSig"]["hex"])
        # <dummy/bitfield> <sig>... <redeemScript>
        return [len(p) for p in pushes[1:-1]]

    def run_test(self):
        node0, node1, node2 = self.nodes
        self.generate(node0, 101)
        self.sync_all()

        self.test_wallet_honors_signschnorr()
        self.test_assemble_foreign_ecdsa_on_schnorr_node()
        self.test_assemble_foreign_schnorr_on_ecdsa_node()
        self.test_mixed_schemes_are_refused()
        self.test_mixed_schemes_are_refused_psbt()

    def test_wallet_honors_signschnorr(self):
        """-signschnorr must reach CWallet's own signing, both ways."""
        self.log.info("Testing that -signschnorr reaches the wallet's signing")
        addr = self.nodes[0].getnewaddress()
        txin = self.fund(addr, Decimal("1.0"))
        rawtx, prevtxs = self.spend_tx(txin, None)
        prevtxs = [{k: v for k, v in prevtxs[0].items() if k != "redeemScript"}]
        privkey = self.nodes[0].dumpprivkey(addr)

        schnorr = self.nodes[0].signrawtransactionwithkey(rawtx, [privkey], prevtxs)
        assert_equal(schnorr["complete"], True)
        ecdsa = self.nodes[1].signrawtransactionwithkey(rawtx, [privkey], prevtxs)
        assert_equal(ecdsa["complete"], True)

        # P2PKH scriptSig is <sig> <pubkey>; the signature is the first push.
        schnorr_sig = self.script_pushes(self.nodes[0].decoderawtransaction(
            schnorr["hex"])["vin"][0]["scriptSig"]["hex"])[0]
        ecdsa_sig = self.script_pushes(self.nodes[1].decoderawtransaction(
            ecdsa["hex"])["vin"][0]["scriptSig"]["hex"])[0]
        assert_equal(len(schnorr_sig), SCHNORR_SIG_LEN)
        # DER encoding is variable but never 65 bytes for a real signature.
        assert len(ecdsa_sig) != SCHNORR_SIG_LEN, "expected a DER signature from -signschnorr=0"
        assert_greater_than_or_equal(len(ecdsa_sig), 70)

        # Both must be accepted by the network.
        self.nodes[0].sendrawtransaction(schnorr["hex"])
        self.generate(self.nodes[0], 1)
        self.sync_all()

    def test_assemble_foreign_ecdsa_on_schnorr_node(self):
        """A Schnorr-configured node must assemble all-ECDSA signatures."""
        self.log.info("Testing combinerawtransaction of ECDSA partials on a Schnorr node")
        address, redeem_script, privkeys = self.make_multisig(3, 2)
        txin = self.fund(address)
        rawtx, prevtxs = self.spend_tx(txin, redeem_script)

        # Both partial signatures are produced by the ECDSA-configured node.
        first = self.nodes[1].signrawtransactionwithkey(rawtx, [privkeys[0]], prevtxs)
        second = self.nodes[1].signrawtransactionwithkey(rawtx, [privkeys[1]], prevtxs)
        assert_equal(first["complete"], False)
        assert_equal(second["complete"], False)

        # node2 holds none of these keys and is configured for Schnorr; it must
        # still produce a valid all-ECDSA scriptSig.
        combined = self.nodes[2].combinerawtransaction([first["hex"], second["hex"]])
        for length in self.input_sig_lengths(self.nodes[2], combined):
            assert length != SCHNORR_SIG_LEN, "assembly must not re-sign; ECDSA sigs must survive"

        txid = self.nodes[2].sendrawtransaction(combined)
        self.sync_all()
        self.generate(self.nodes[0], 1)
        self.sync_all()
        assert_equal(self.nodes[0].getrawtransaction(txid, True)["confirmations"], 1)

        # Same via the PSBT finalizer role, which is also keyless.
        self.log.info("Testing finalizepsbt of an ECDSA PSBT on a Schnorr node")
        address, redeem_script, privkeys = self.make_multisig(3, 2)
        txin = self.fund(address)
        outputs = {self.nodes[0].getnewaddress(): txin["amount"] - Decimal("0.001")}
        psbt = self.nodes[0].createpsbt(
            [{"txid": txin["txid"], "vout": txin["vout"]}], outputs)

        self.nodes[1].createwallet("ecdsa_signer")
        signer = self.nodes[1].get_wallet_rpc("ecdsa_signer")
        signer.importaddress(redeem_script, "", True, True)
        for key in privkeys[:2]:
            signer.importprivkey(key)
        signed = signer.walletprocesspsbt(psbt)["psbt"]

        final = self.nodes[2].finalizepsbt(signed)
        assert_equal(final["complete"], True)
        txid = self.nodes[2].sendrawtransaction(final["hex"])
        self.sync_all()
        self.generate(self.nodes[0], 1)
        self.sync_all()
        assert_equal(self.nodes[0].getrawtransaction(txid, True)["confirmations"], 1)

    def test_assemble_foreign_schnorr_on_ecdsa_node(self):
        """The mirror: an ECDSA-configured node must assemble Schnorr signatures."""
        self.log.info("Testing combinerawtransaction of Schnorr partials on an ECDSA node")
        address, redeem_script, privkeys = self.make_multisig(3, 2)
        txin = self.fund(address)
        rawtx, prevtxs = self.spend_tx(txin, redeem_script)

        first = self.nodes[0].signrawtransactionwithkey(rawtx, [privkeys[0]], prevtxs)
        second = self.nodes[0].signrawtransactionwithkey(rawtx, [privkeys[1]], prevtxs)
        assert_equal(first["complete"], False)
        assert_equal(second["complete"], False)

        combined = self.nodes[1].combinerawtransaction([first["hex"], second["hex"]])
        lengths = self.input_sig_lengths(self.nodes[1], combined)
        assert_equal(lengths, [SCHNORR_SIG_LEN, SCHNORR_SIG_LEN])

        txid = self.nodes[1].sendrawtransaction(combined)
        self.sync_all()
        self.generate(self.nodes[0], 1)
        self.sync_all()
        assert_equal(self.nodes[0].getrawtransaction(txid, True)["confirmations"], 1)

    def test_mixed_schemes_are_refused(self):
        """One Schnorr and one ECDSA signature on the same input must error."""
        self.log.info("Testing that combinerawtransaction refuses a mixed multisig")
        address, redeem_script, privkeys = self.make_multisig(3, 2)
        txin = self.fund(address)
        rawtx, prevtxs = self.spend_tx(txin, redeem_script)

        schnorr_part = self.nodes[0].signrawtransactionwithkey(rawtx, [privkeys[0]], prevtxs)
        ecdsa_part = self.nodes[1].signrawtransactionwithkey(rawtx, [privkeys[1]], prevtxs)
        assert_equal(schnorr_part["complete"], False)
        assert_equal(ecdsa_part["complete"], False)

        # Refused the same way regardless of which node assembles, and
        # regardless of the order the partials are supplied in.
        for node in (self.nodes[0], self.nodes[1], self.nodes[2]):
            for pair in ([schnorr_part["hex"], ecdsa_part["hex"]],
                         [ecdsa_part["hex"], schnorr_part["hex"]]):
                assert_raises_rpc_error(-25, MIX_ERR, node.combinerawtransaction, pair)

        # Refuse to sign mixed-mode and check that tx hex is unchanged and the correct error appears
        self.log.info("Testing that signrawtransactionwithkey refuses a mixed multisig and leaves the tx unchanged")
        for node_num, txhex in ((1, schnorr_part["hex"]), (0, ecdsa_part["hex"])):
            node = self.nodes[node_num]
            result = node.signrawtransactionwithkey(txhex, [privkeys[node_num]], prevtxs)
            assert_equal(len(result["errors"]), 1)
            error_text = result["errors"][0]["error"]
            assert "multi-signature script that mixes both Schnorr and ECDSA signatures" in error_text
            assert_equal(result["complete"], False)
            # Tx should be unchanged in this case since attempting to add the wrong-mode signature to a mixed multisig
            # would always be wrong and never be useful.
            assert_equal(result["hex"], txhex)

    def test_mixed_schemes_are_refused_psbt(self):
        """The same mix must be refused on the PSBT path, not silently emitted."""
        self.log.info("Testing that finalizepsbt refuses a mixed multisig")
        address, redeem_script, privkeys = self.make_multisig(3, 2)
        txin = self.fund(address)
        outputs = {self.nodes[0].getnewaddress(): txin["amount"] - Decimal("0.001")}
        psbt = self.nodes[0].createpsbt(
            [{"txid": txin["txid"], "vout": txin["vout"]}], outputs)

        self.nodes[0].createwallet("schnorr_signer")
        schnorr_signer = self.nodes[0].get_wallet_rpc("schnorr_signer")
        schnorr_signer.importaddress(redeem_script, "", True, True)
        schnorr_signer.importprivkey(privkeys[0])

        self.nodes[1].createwallet("ecdsa_signer2")
        ecdsa_signer = self.nodes[1].get_wallet_rpc("ecdsa_signer2")
        ecdsa_signer.importaddress(redeem_script, "", True, True)
        ecdsa_signer.importprivkey(privkeys[1])

        part_schnorr = schnorr_signer.walletprocesspsbt(psbt)["psbt"]
        part_ecdsa = ecdsa_signer.walletprocesspsbt(psbt)["psbt"]
        combined = self.nodes[2].combinepsbt([part_schnorr, part_ecdsa])

        assert_raises_rpc_error(-25, MIX_ERR, self.nodes[2].finalizepsbt, combined)
        assert_raises_rpc_error(-25, MIX_ERR, self.nodes[0].finalizepsbt, combined)
        assert_raises_rpc_error(-25, MIX_ERR, self.nodes[1].finalizepsbt, combined)


if __name__ == '__main__':
    SchnorrMultisigTest().main()
