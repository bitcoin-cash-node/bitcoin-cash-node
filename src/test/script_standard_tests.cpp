// Copyright (c) 2017 The Bitcoin Core developers
// Copyright (c) 2019-2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <core_io.h>
#include <key.h>
#include <keystore.h>
#include <policy/policy.h>
#include <script/ismine.h>
#include <script/script.h>
#include <script/script_error.h>
#include <script/standard.h>
#include <test/setup_common.h>
#include <tinyformat.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <utility>

// Append given push onto a script, using specific opcode (not necessarily
// the minimal one, but must be able to contain the given data.)
void AppendPush(CScript &script, opcodetype opcode, const ByteView &b) {
    assert(opcode <= OP_PUSHDATA4);
    script.push_back(opcode);
    if (opcode < OP_PUSHDATA1) {
        assert(b.size() == opcode);
    } else if (opcode == OP_PUSHDATA1) {
        assert(b.size() <= 0xff);
        script.push_back(uint8_t(b.size()));
    } else if (opcode == OP_PUSHDATA2) {
        assert(b.size() <= 0xffff);
        uint8_t _data[2];
        WriteLE16(_data, b.size());
        script.insert(script.end(), _data, _data + sizeof(_data));
    } else if (opcode == OP_PUSHDATA4) {
        uint8_t _data[4];
        WriteLE32(_data, b.size());
        script.insert(script.end(), _data, _data + sizeof(_data));
    }
    script.insert(script.end(), b.begin(), b.end());
}

// Needed because ByteView and/or std::span lacks operator==
static bool Equal(const ByteView &a, const ByteView &b) {
    return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin());
}

BOOST_FIXTURE_TEST_SUITE(script_standard_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(script_standard_Solver_success) {
    using P = std::pair<bool, bool>;
    for (const auto [enable_p2sh_32, enable_p2s] : {P{false, false}, P{false, true}, P{true, false}, P{true, true}}) {
        uint32_t flags = enable_p2sh_32 ? STANDARD_SCRIPT_VERIFY_FLAGS | SCRIPT_ENABLE_P2SH_32
                                        : STANDARD_SCRIPT_VERIFY_FLAGS & ~SCRIPT_ENABLE_P2SH_32;
        if (enable_p2s) {
            flags |= SCRIPT_ENABLE_MAY2026;
        } else {
            flags &= ~SCRIPT_ENABLE_MAY2026;
        }

        CKey keys[3];
        CPubKey pubkeys[3];
        for (int i = 0; i < 3; i++) {
            keys[i].MakeNewKey(true);
            pubkeys[i] = keys[i].GetPubKey();
        }

        CScript s;
        std::vector<std::vector<uint8_t>> solutions;

        // TX_PUBKEY
        s.clear();
        s << pubkeys[0] << OP_CHECKSIG;
        BOOST_CHECK_EQUAL(Solver(s, solutions, flags), TX_PUBKEY);
        BOOST_CHECK_EQUAL(solutions.size(), 1U);
        BOOST_CHECK(Equal(solutions[0], pubkeys[0]));

        // TX_PUBKEYHASH
        s.clear();
        s << OP_DUP << OP_HASH160 << pubkeys[0].GetID()
          << OP_EQUALVERIFY << OP_CHECKSIG;
        BOOST_CHECK_EQUAL(Solver(s, solutions, flags), TX_PUBKEYHASH);
        BOOST_CHECK_EQUAL(solutions.size(), 1U);
        BOOST_CHECK(Equal(solutions[0], pubkeys[0].GetID()));

        // TX_SCRIPTHASH
        const CScript redeemScript(s); // initialize with leftover P2PKH script
        s.clear();
        s << OP_HASH160 << ScriptID(redeemScript, false /* p2sh_20 */) << OP_EQUAL;
        BOOST_CHECK_EQUAL(Solver(s, solutions, flags), TX_SCRIPTHASH);
        BOOST_CHECK_EQUAL(solutions.size(), 1U);
        BOOST_CHECK(Equal(solutions[0], ScriptID(redeemScript, false /* p2sh_20 */)));

        // TX_SCRIPTHASH (P2SH_32)
        s.clear();
        s << OP_HASH256 << ScriptID(redeemScript, true /* p2sh_32 */) << OP_EQUAL;
        if (enable_p2sh_32) {
            // If we are looping and p2sh_32 is enabled, we expect this
            BOOST_CHECK_EQUAL(Solver(s, solutions, flags), TX_SCRIPTHASH);
            BOOST_CHECK_EQUAL(solutions.size(), 1U);
            BOOST_CHECK(Equal(solutions[0], ScriptID(redeemScript, true /* p2sh_32 */)));
        } else {
            // Otherwise we expect this
            BOOST_CHECK_EQUAL(Solver(s, solutions, flags), enable_p2s ? TX_SCRIPT : TX_NONSTANDARD);
            BOOST_CHECK_EQUAL(solutions.size(), 0U);
        }

        // TX_MULTISIG
        s.clear();
        s << OP_1 << pubkeys[0] << pubkeys[1] << OP_2
          << OP_CHECKMULTISIG;
        BOOST_CHECK_EQUAL(Solver(s, solutions, flags), TX_MULTISIG);
        BOOST_CHECK_EQUAL(solutions.size(), 4U);
        BOOST_CHECK(solutions[0] == std::vector<uint8_t>({1}));
        BOOST_CHECK(Equal(solutions[1], pubkeys[0]));
        BOOST_CHECK(Equal(solutions[2], pubkeys[1]));
        BOOST_CHECK(solutions[3] == std::vector<uint8_t>({2}));

        s.clear();
        s << OP_2 << pubkeys[0] << pubkeys[1]
          << pubkeys[2] << OP_3 << OP_CHECKMULTISIG;
        BOOST_CHECK_EQUAL(Solver(s, solutions, flags), TX_MULTISIG);
        BOOST_CHECK_EQUAL(solutions.size(), 5U);
        BOOST_CHECK(solutions[0] == std::vector<uint8_t>({2}));
        BOOST_CHECK(Equal(solutions[1], pubkeys[0]));
        BOOST_CHECK(Equal(solutions[2], pubkeys[1]));
        BOOST_CHECK(Equal(solutions[3], pubkeys[2]));
        BOOST_CHECK(solutions[4] == std::vector<uint8_t>({3}));

        // TX_NULL_DATA
        s.clear();
        s << OP_RETURN << std::vector<uint8_t>({0}) << std::vector<uint8_t>({75})
          << std::vector<uint8_t>({255});
        BOOST_CHECK_EQUAL(Solver(s, solutions, flags), TX_NULL_DATA);
        BOOST_CHECK_EQUAL(solutions.size(), 0U);

        // TX_WITNESS_V0_KEYHASH
        s.clear();
        s << OP_0 << pubkeys[0].GetID();
        BOOST_CHECK_EQUAL(Solver(s, solutions, flags), enable_p2s ? TX_SCRIPT : TX_NONSTANDARD);
        BOOST_CHECK_EQUAL(solutions.size(), 0U);

        // TX_WITNESS_V0_SCRIPTHASH
        uint256 scriptHash;
        CSHA256()
            .Write(&redeemScript[0], redeemScript.size())
            .Finalize(scriptHash.begin());

        s.clear();
        s << OP_0 << scriptHash;
        BOOST_CHECK_EQUAL(Solver(s, solutions, flags), enable_p2s ? TX_SCRIPT : TX_NONSTANDARD);
        BOOST_CHECK_EQUAL(solutions.size(), 0U);

        // TX_SCRIPT (at 201 limit)
        s.clear();
        s << OP_9 << OP_2 << OP_ADD << OP_11 << OP_EQUALVERIFY << std::vector<uint8_t>(MAX_P2S_SCRIPT_SIZE - 7, uint8_t(1));
        BOOST_CHECK_EQUAL(s.size(), MAX_P2S_SCRIPT_SIZE);
        BOOST_CHECK_EQUAL(Solver(s, solutions, flags), enable_p2s ? TX_SCRIPT : TX_NONSTANDARD);
        BOOST_CHECK_EQUAL(solutions.size(), 0);

        // TX_NONSTANDARD (always, even if p2s is enabled, due to being over 201 limit)
        s.clear();
        s << OP_9 << OP_2 << OP_ADD << OP_11 << OP_EQUALVERIFY << std::vector<uint8_t>(MAX_P2S_SCRIPT_SIZE - 7 + 1, uint8_t(1));
        BOOST_CHECK_EQUAL(s.size(), MAX_P2S_SCRIPT_SIZE + 1);
        BOOST_CHECK_EQUAL(Solver(s, solutions, flags), TX_NONSTANDARD);
        BOOST_CHECK_EQUAL(solutions.size(), 0);


        // TX_NONSTANDARD (only if !p2s, otherwise TX_SCRIPT)
        s.clear();
        s << OP_9 << OP_ADD << OP_11 << OP_EQUAL;
        BOOST_CHECK_EQUAL(Solver(s, solutions, flags), enable_p2s ? TX_SCRIPT : TX_NONSTANDARD);
        BOOST_CHECK_EQUAL(solutions.size(), 0);

        // Try some non-minimal PUSHDATA pushes in various standard scripts
        for (auto pushdataop : {OP_PUSHDATA1, OP_PUSHDATA2, OP_PUSHDATA4}) {
            // mutated TX_PUBKEY
            s.clear();
            AppendPush(s, pushdataop, pubkeys[0]);
            s << OP_CHECKSIG;
            BOOST_CHECK_EQUAL(Solver(s, solutions, flags), enable_p2s ? TX_SCRIPT : TX_NONSTANDARD);
            BOOST_CHECK_EQUAL(solutions.size(), 0);

            // mutated TX_PUBKEYHASH
            s.clear();
            s << OP_DUP << OP_HASH160;
            AppendPush(s, pushdataop, pubkeys[0].GetID());
            s << OP_EQUALVERIFY << OP_CHECKSIG;
            BOOST_CHECK_EQUAL(Solver(s, solutions, flags), enable_p2s ? TX_SCRIPT : TX_NONSTANDARD);
            BOOST_CHECK_EQUAL(solutions.size(), 0);

            // mutated TX_SCRIPTHASH
            s.clear();
            s << OP_HASH160;
            AppendPush(s, pushdataop, ScriptID(redeemScript, false /* p2sh_20 */));
            s << OP_EQUAL;
            BOOST_CHECK_EQUAL(Solver(s, solutions, flags), enable_p2s ? TX_SCRIPT : TX_NONSTANDARD);
            BOOST_CHECK_EQUAL(solutions.size(), 0);

            // mutated TX_SCRIPTHASH (P2SH_32)
            s.clear();
            s << OP_HASH256;
            AppendPush(s, pushdataop, ScriptID(redeemScript, true /* p2sh_32 */));
            s << OP_EQUAL;
            BOOST_CHECK_EQUAL(Solver(s, solutions, flags), enable_p2s ? TX_SCRIPT : TX_NONSTANDARD);
            BOOST_CHECK_EQUAL(solutions.size(), 0);

            // mutated TX_MULTISIG -- pubkey
            s.clear();
            s << OP_1;
            AppendPush(s, pushdataop, pubkeys[0]);
            s << pubkeys[1] << OP_2 << OP_CHECKMULTISIG;
            BOOST_CHECK_EQUAL(Solver(s, solutions, flags), enable_p2s ? TX_SCRIPT : TX_NONSTANDARD);
            BOOST_CHECK_EQUAL(solutions.size(), 0);

            // mutated TX_MULTISIG -- num_signatures
            s.clear();
            AppendPush(s, pushdataop, std::vector<uint8_t>{1});
            s << pubkeys[0] << pubkeys[1] << OP_2
              << OP_CHECKMULTISIG;
            BOOST_CHECK_EQUAL(Solver(s, solutions, flags), enable_p2s ? TX_SCRIPT : TX_NONSTANDARD);
            BOOST_CHECK_EQUAL(solutions.size(), 0);

            // mutated TX_MULTISIG -- num_pubkeys
            s.clear();
            s << OP_1 << pubkeys[0] << pubkeys[1];
            AppendPush(s, pushdataop, std::vector<uint8_t>{2});
            s << OP_CHECKMULTISIG;
            BOOST_CHECK_EQUAL(Solver(s, solutions, flags), enable_p2s ? TX_SCRIPT : TX_NONSTANDARD);
            BOOST_CHECK_EQUAL(solutions.size(), 0);
        }

        // also try pushing the num_signatures and num_pubkeys using PUSH_N opcode
        // instead of OP_N opcode:
        s.clear();
        s << std::vector<uint8_t>{1} << pubkeys[0]
          << pubkeys[1] << OP_2 << OP_CHECKMULTISIG;
        BOOST_CHECK_EQUAL(Solver(s, solutions, flags), enable_p2s ? TX_SCRIPT : TX_NONSTANDARD);
        BOOST_CHECK_EQUAL(solutions.size(), 0);
        s.clear();
        s << OP_1 << pubkeys[0] << pubkeys[1]
          << std::vector<uint8_t>{2} << OP_CHECKMULTISIG;
        BOOST_CHECK_EQUAL(Solver(s, solutions, flags), enable_p2s ? TX_SCRIPT : TX_NONSTANDARD);
        BOOST_CHECK_EQUAL(solutions.size(), 0);

        // Non-minimal pushes in OP_RETURN scripts are standard (some OP_RETURN
        // protocols like SLP rely on this). Also it turns out OP_RESERVED gets past
        // IsPushOnly and thus is standard here.
        std::vector<uint8_t> op_return_nonminimal{
            OP_RETURN,    OP_RESERVED, OP_PUSHDATA1, 0x00, 0x01, 0x01,
            OP_PUSHDATA4, 0x01,        0x00,         0x00, 0x00, 0xaa};
        s.assign(op_return_nonminimal.begin(), op_return_nonminimal.end());
        BOOST_CHECK_EQUAL(Solver(s, solutions, flags), TX_NULL_DATA);
        BOOST_CHECK_EQUAL(solutions.size(), 0);
    }
}

BOOST_AUTO_TEST_CASE(script_standard_Solver_failure) {
    const uint32_t flags = STANDARD_SCRIPT_VERIFY_FLAGS | SCRIPT_ENABLE_P2SH_32;

    CKey key;
    CPubKey pubkey;
    key.MakeNewKey(true);
    pubkey = key.GetPubKey();

    CScript s;
    std::vector<std::vector<uint8_t>> solutions;

    // TX_PUBKEY with incorrectly sized pubkey
    s.clear();
    s << std::vector<uint8_t>(30, 0x01) << OP_CHECKSIG;
    BOOST_CHECK_EQUAL(Solver(s, solutions, flags), TX_NONSTANDARD);
    BOOST_CHECK_EQUAL(Solver(s, solutions, flags | SCRIPT_ENABLE_MAY2026), TX_SCRIPT);

    // TX_PUBKEYHASH with incorrectly sized key hash
    s.clear();
    s << OP_DUP << OP_HASH160 << pubkey << OP_EQUALVERIFY
      << OP_CHECKSIG;
    BOOST_CHECK_EQUAL(Solver(s, solutions, flags), TX_NONSTANDARD);
    BOOST_CHECK_EQUAL(Solver(s, solutions, flags | SCRIPT_ENABLE_MAY2026), TX_SCRIPT);

    // TX_SCRIPTHASH with incorrectly sized script hash
    s.clear();
    s << OP_HASH160 << std::vector<uint8_t>(21, 0x01) << OP_EQUAL;
    BOOST_CHECK_EQUAL(Solver(s, solutions, flags), TX_NONSTANDARD);
    BOOST_CHECK_EQUAL(Solver(s, solutions, flags | SCRIPT_ENABLE_MAY2026), TX_SCRIPT);

    // TX_SCRIPTHASH P2SH_32 with incorrectly sized script hash
    s.clear();
    s << OP_HASH256 << std::vector<uint8_t>(33, 0x01) << OP_EQUAL;
    BOOST_CHECK_EQUAL(Solver(s, solutions, flags), TX_NONSTANDARD);
    BOOST_CHECK_EQUAL(Solver(s, solutions, flags | SCRIPT_ENABLE_MAY2026), TX_SCRIPT);

    // TX_SCRIPTHASH P2SH_32 with SCRIPT_ENABLE_P2SH_32 disabled
    s.clear();
    s << OP_HASH256 << std::vector<uint8_t>(32, 0x01) << OP_EQUAL;
    BOOST_CHECK_EQUAL(Solver(s, solutions, flags | SCRIPT_ENABLE_P2SH_32), TX_SCRIPTHASH);
    BOOST_CHECK_EQUAL(Solver(s, solutions, flags | SCRIPT_ENABLE_P2SH_32 | SCRIPT_ENABLE_MAY2026), TX_SCRIPTHASH);
    BOOST_CHECK_EQUAL(Solver(s, solutions, flags & ~SCRIPT_ENABLE_P2SH_32), TX_NONSTANDARD);
    BOOST_CHECK_EQUAL(Solver(s, solutions, (flags & ~SCRIPT_ENABLE_P2SH_32) | SCRIPT_ENABLE_MAY2026), TX_SCRIPT);

    // TX_MULTISIG 0/2
    s.clear();
    s << OP_0 << pubkey << OP_1 << OP_CHECKMULTISIG;
    BOOST_CHECK_EQUAL(Solver(s, solutions, flags), TX_NONSTANDARD);
    BOOST_CHECK_EQUAL(Solver(s, solutions, flags | SCRIPT_ENABLE_MAY2026), TX_SCRIPT);

    // TX_MULTISIG 2/1
    s.clear();
    s << OP_2 << pubkey << OP_1 << OP_CHECKMULTISIG;
    BOOST_CHECK_EQUAL(Solver(s, solutions, flags), TX_NONSTANDARD);
    BOOST_CHECK_EQUAL(Solver(s, solutions, flags | SCRIPT_ENABLE_MAY2026), TX_SCRIPT);

    // TX_MULTISIG n = 2 with 1 pubkey
    s.clear();
    s << OP_1 << pubkey << OP_2 << OP_CHECKMULTISIG;
    BOOST_CHECK_EQUAL(Solver(s, solutions, flags), TX_NONSTANDARD);
    BOOST_CHECK_EQUAL(Solver(s, solutions, flags | SCRIPT_ENABLE_MAY2026), TX_SCRIPT);

    // TX_MULTISIG n = 1 with 0 pubkeys
    s.clear();
    s << OP_1 << OP_1 << OP_CHECKMULTISIG;
    BOOST_CHECK_EQUAL(Solver(s, solutions, flags), TX_NONSTANDARD);
    BOOST_CHECK_EQUAL(Solver(s, solutions, flags | SCRIPT_ENABLE_MAY2026), TX_SCRIPT);

    // TX_NULL_DATA with other opcodes
    s.clear();
    s << OP_RETURN << std::vector<uint8_t>({75}) << OP_ADD;
    BOOST_CHECK_EQUAL(Solver(s, solutions, flags), TX_NONSTANDARD);
    BOOST_CHECK_EQUAL(Solver(s, solutions, flags | SCRIPT_ENABLE_MAY2026), TX_SCRIPT);

    // TX_WITNESS with unknown version
    s.clear();
    s << OP_1 << pubkey;
    BOOST_CHECK_EQUAL(Solver(s, solutions, flags), TX_NONSTANDARD);
    BOOST_CHECK_EQUAL(Solver(s, solutions, flags | SCRIPT_ENABLE_MAY2026), TX_SCRIPT);

    // TX_WITNESS with incorrect program size
    s.clear();
    s << OP_0 << std::vector<uint8_t>(19, 0x01);
    BOOST_CHECK_EQUAL(Solver(s, solutions, flags), TX_NONSTANDARD);
    BOOST_CHECK_EQUAL(Solver(s, solutions, flags | SCRIPT_ENABLE_MAY2026), TX_SCRIPT);

    // TX_SCRIPT at the 201-byte limit
    s.clear();
    s << OP_1 << std::vector<uint8_t>(MAX_P2S_SCRIPT_SIZE - 4, 0x01) << OP_DROP;
    BOOST_CHECK_EQUAL(s.size(), MAX_P2S_SCRIPT_SIZE);
    BOOST_CHECK_EQUAL(Solver(s, solutions, flags), TX_NONSTANDARD);
    BOOST_CHECK_EQUAL(Solver(s, solutions, flags | SCRIPT_ENABLE_MAY2026), TX_SCRIPT);

    // TX_NONSTANDARD (script past the 201-byte limit)
    s.clear();
    s << OP_1 << std::vector<uint8_t>(MAX_P2S_SCRIPT_SIZE - 3, 0x01) << OP_DROP;
    BOOST_CHECK_EQUAL(s.size(), MAX_P2S_SCRIPT_SIZE + 1);
    BOOST_CHECK_EQUAL(Solver(s, solutions, flags), TX_NONSTANDARD);
    BOOST_CHECK_EQUAL(Solver(s, solutions, flags | SCRIPT_ENABLE_MAY2026), TX_NONSTANDARD);
}

BOOST_AUTO_TEST_CASE(script_standard_ExtractDestination) {
    using P = std::pair<bool, bool>;
    for (const auto [enable_p2s, enable_p2sh32] : {P{false, false}, P{false, true}, P{true, false}, P{true, true}}) {
        uint32_t flags = STANDARD_SCRIPT_VERIFY_FLAGS;
        if (enable_p2sh32) {
            flags |= SCRIPT_ENABLE_P2SH_32;
        } else {
            flags &= ~SCRIPT_ENABLE_P2SH_32;
        }
        if (enable_p2s) {
            flags |= SCRIPT_ENABLE_MAY2026;
        } else {
            flags &= ~SCRIPT_ENABLE_MAY2026;
        }

        CKey key;
        CPubKey pubkey;
        key.MakeNewKey(true);
        pubkey = key.GetPubKey();

        CScript s;
        CTxDestination address;

        // TX_PUBKEY
        s.clear();
        s << pubkey << OP_CHECKSIG;
        BOOST_CHECK(ExtractDestination(s, address, flags));
        BOOST_CHECK(std::get_if<CKeyID>(&address) &&
                    *std::get_if<CKeyID>(&address) == pubkey.GetID());
        address = {};

        // TX_PUBKEYHASH
        s.clear();
        s << OP_DUP << OP_HASH160 << pubkey.GetID() << OP_EQUALVERIFY
          << OP_CHECKSIG;
        BOOST_CHECK(ExtractDestination(s, address, flags));
        BOOST_CHECK(std::get_if<CKeyID>(&address) &&
                    *std::get_if<CKeyID>(&address) == pubkey.GetID());
        address = {};

        // TX_SCRIPTHASH
        const CScript redeemScript(s); // initialize with leftover P2PKH script
        s.clear();
        s << OP_HASH160 << ScriptID(redeemScript, false /* p2sh_32 */) << OP_EQUAL;
        BOOST_CHECK(ExtractDestination(s, address, flags));
        BOOST_CHECK(std::get_if<ScriptID>(&address) &&
                    *std::get_if<ScriptID>(&address) == ScriptID(redeemScript, false));
        address = {};

        // TX_SCRIPTHASH (P2SH_32)
        s.clear();
        s << OP_HASH256 << ScriptID(redeemScript, true /* p2sh_32 */) << OP_EQUAL;
        if (enable_p2sh32) {
            BOOST_CHECK(ExtractDestination(s, address, flags));
            BOOST_CHECK(std::get_if<ScriptID>(&address) &&
                        *std::get_if<ScriptID>(&address) == ScriptID(redeemScript, true /* p2sh_32 */));
        } else {
            BOOST_CHECK_MESSAGE(!ExtractDestination(s, address, flags),
                                strprintf("When disabling SCRIPT_ENABLE_P2SH_32, expected ExtractDestination to fail: %s",
                                          ScriptToAsmStr(s)));
        }
        address = {};

        // TX_MULTISIG
        s.clear();
        s << OP_1 << pubkey << OP_1 << OP_CHECKMULTISIG;
        BOOST_CHECK(!ExtractDestination(s, address, flags));
        BOOST_CHECK(!IsValidDestination(address));

        // TX_NULL_DATA
        s.clear();
        s << OP_RETURN << std::vector<uint8_t>({75});
        BOOST_CHECK(!ExtractDestination(s, address, flags));
        BOOST_CHECK(!IsValidDestination(address));

        // TX_WITNESS_V0_KEYHASH
        s.clear();
        s << OP_0 << pubkey;
        BOOST_CHECK(!ExtractDestination(s, address, flags));
        BOOST_CHECK(!IsValidDestination(address));

        // TX_WITNESS_V0_SCRIPTHASH
        s.clear();
        s << OP_0 << ScriptID(redeemScript, false /* p2sh_20 */);
        BOOST_CHECK(!ExtractDestination(s, address, flags));
        BOOST_CHECK(!IsValidDestination(address));

        // TX_WITNESS_V0_SCRIPTHASH (P2SH32; nonsensical)
        s.clear();
        s << OP_0 << ScriptID(redeemScript, true /* p2sh_32 */);
        BOOST_CHECK(!ExtractDestination(s, address, flags));
        BOOST_CHECK(!IsValidDestination(address));

        // TX_SCRIPT
        s.clear();
        s << OP_1 << ByteView{redeemScript};
        BOOST_CHECK_LE(s.size(), MAX_P2S_SCRIPT_SIZE);
        BOOST_CHECK(!ExtractDestination(s, address, flags));
        BOOST_CHECK(!IsValidDestination(address));

        // TX_NONSTANDARD
        s.clear();
        s << OP_1 << std::vector<uint8_t>(MAX_P2S_SCRIPT_SIZE, 0xfe);
        BOOST_CHECK_GT(s.size(), MAX_P2S_SCRIPT_SIZE);
        BOOST_CHECK(!ExtractDestination(s, address, flags));
        BOOST_CHECK(!IsValidDestination(address));
    }
}

BOOST_AUTO_TEST_CASE(script_standard_ExtractDestinations) {
    using P = std::pair<bool, bool>;
    for (const auto [enable_p2s, enable_p2sh32] : {P{false, false}, P{false, true}, P{true, false}, P{true, true}}) {
        uint32_t flags = STANDARD_SCRIPT_VERIFY_FLAGS;
        if (enable_p2sh32) {
            flags |= SCRIPT_ENABLE_P2SH_32;
        } else {
            flags &= ~SCRIPT_ENABLE_P2SH_32;
        }
        if (enable_p2s) {
            flags |= SCRIPT_ENABLE_MAY2026;
        } else {
            flags &= ~SCRIPT_ENABLE_MAY2026;
        }

        CKey keys[3];
        CPubKey pubkeys[3];
        for (int i = 0; i < 3; i++) {
            keys[i].MakeNewKey(true);
            pubkeys[i] = keys[i].GetPubKey();
        }

        CScript s;
        txnouttype whichType;
        std::vector<CTxDestination> addresses;
        int nRequired;

        // TX_PUBKEY
        s.clear();
        s << pubkeys[0] << OP_CHECKSIG;
        BOOST_CHECK(ExtractDestinations(s, whichType, addresses, nRequired, flags));
        BOOST_CHECK_EQUAL(whichType, TX_PUBKEY);
        BOOST_CHECK_EQUAL(addresses.size(), 1U);
        BOOST_CHECK_EQUAL(nRequired, 1);
        BOOST_CHECK(std::get_if<CKeyID>(&addresses[0]) &&
                    *std::get_if<CKeyID>(&addresses[0]) == pubkeys[0].GetID());

        // TX_PUBKEYHASH
        s.clear();
        s << OP_DUP << OP_HASH160 << pubkeys[0].GetID()
          << OP_EQUALVERIFY << OP_CHECKSIG;
        BOOST_CHECK(ExtractDestinations(s, whichType, addresses, nRequired, flags));
        BOOST_CHECK_EQUAL(whichType, TX_PUBKEYHASH);
        BOOST_CHECK_EQUAL(addresses.size(), 1U);
        BOOST_CHECK_EQUAL(nRequired, 1);
        BOOST_CHECK(std::get_if<CKeyID>(&addresses[0]) &&
                    *std::get_if<CKeyID>(&addresses[0]) == pubkeys[0].GetID());

        // TX_SCRIPTHASH
        // initialize with leftover P2PKH script
        const CScript redeemScript(s);
        s.clear();
        s << OP_HASH160 << ScriptID(redeemScript, false /* p2sh_32 */) << OP_EQUAL;
        BOOST_CHECK(ExtractDestinations(s, whichType, addresses, nRequired, flags));
        BOOST_CHECK_EQUAL(whichType, TX_SCRIPTHASH);
        BOOST_CHECK_EQUAL(addresses.size(), 1U);
        BOOST_CHECK_EQUAL(nRequired, 1);
        BOOST_CHECK(std::get_if<ScriptID>(&addresses[0]) &&
                    *std::get_if<ScriptID>(&addresses[0]) ==
                        ScriptID(redeemScript, false /* p2sh_32 */));

        // TX_SCRIPTHASH (P2SH_32)
        // initialize with leftover P2PKH script
        s.clear();
        s << OP_HASH256 << ScriptID(redeemScript, true /* p2sh_32 */) << OP_EQUAL;
        if (enable_p2sh32) {
            BOOST_CHECK(ExtractDestinations(s, whichType, addresses, nRequired, flags));
            BOOST_CHECK_EQUAL(whichType, TX_SCRIPTHASH);
            BOOST_CHECK_EQUAL(addresses.size(), 1U);
            BOOST_CHECK_EQUAL(nRequired, 1);
            BOOST_CHECK(std::get_if<ScriptID>(&addresses[0]) &&
                        *std::get_if<ScriptID>(&addresses[0]) == ScriptID(redeemScript, true /* p2sh_32 */));
        } else {
            BOOST_CHECK(!ExtractDestinations(s, whichType, addresses, nRequired, flags));
            BOOST_CHECK_EQUAL(whichType, enable_p2s ? TX_SCRIPT : TX_NONSTANDARD);
            BOOST_CHECK_EQUAL(addresses.size(), 0U);
        }

        // TX_MULTISIG
        s.clear();
        s << OP_2 << pubkeys[0] << pubkeys[1] << OP_2
          << OP_CHECKMULTISIG;
        BOOST_CHECK(ExtractDestinations(s, whichType, addresses, nRequired, flags));
        BOOST_CHECK_EQUAL(whichType, TX_MULTISIG);
        BOOST_CHECK_EQUAL(addresses.size(), 2U);
        BOOST_CHECK_EQUAL(nRequired, 2);
        BOOST_CHECK(std::get_if<CKeyID>(&addresses[0]) &&
                    *std::get_if<CKeyID>(&addresses[0]) == pubkeys[0].GetID());
        BOOST_CHECK(std::get_if<CKeyID>(&addresses[1]) &&
                    *std::get_if<CKeyID>(&addresses[1]) == pubkeys[1].GetID());

        // TX_NULL_DATA
        s.clear();
        s << OP_RETURN << std::vector<uint8_t>({75});
        BOOST_CHECK(!ExtractDestinations(s, whichType, addresses, nRequired, flags));
        BOOST_CHECK_EQUAL(whichType, TX_NULL_DATA);

        // TX_WITNESS_V0_KEYHASH
        s.clear();
        s << OP_0 << pubkeys[0].GetID();
        BOOST_CHECK(!ExtractDestinations(s, whichType, addresses, nRequired, flags));
        BOOST_CHECK_EQUAL(whichType, enable_p2s ? TX_SCRIPT : TX_NONSTANDARD);

        // TX_WITNESS_V0_SCRIPTHASH
        s.clear();
        s << OP_0 << ScriptID(redeemScript, false /* p2sh_20 */);
        BOOST_CHECK(!ExtractDestinations(s, whichType, addresses, nRequired, flags));
        BOOST_CHECK_EQUAL(whichType, enable_p2s ? TX_SCRIPT : TX_NONSTANDARD);

        // TX_WITNESS_V0_SCRIPTHASH using p2sh_32 (nonsenical)
        s.clear();
        s << OP_0 << ScriptID(redeemScript, true /* p2sh_32 */);
        BOOST_CHECK(!ExtractDestinations(s, whichType, addresses, nRequired, flags));
        BOOST_CHECK_EQUAL(whichType, enable_p2s ? TX_SCRIPT : TX_NONSTANDARD);
    }
}

BOOST_AUTO_TEST_CASE(script_standard_GetScriptFor_) {
    CKey keys[3];
    CPubKey pubkeys[3];
    for (int i = 0; i < 3; i++) {
        keys[i].MakeNewKey(true);
        pubkeys[i] = keys[i].GetPubKey();
    }

    CScript expected, result;

    // CKeyID
    expected.clear();
    expected << OP_DUP << OP_HASH160 << pubkeys[0].GetID()
             << OP_EQUALVERIFY << OP_CHECKSIG;
    result = GetScriptForDestination(pubkeys[0].GetID());
    BOOST_CHECK(result == expected);

    // ScriptID - p2sh_20 (legacy)
    CScript redeemScript(result);
    expected.clear();
    expected << OP_HASH160 << ScriptID(redeemScript, false) << OP_EQUAL;
    result = GetScriptForDestination(ScriptID(redeemScript, false));
    BOOST_CHECK(result == expected);

    // ScriptID - p2sh_32 (newer)
    expected.clear();
    expected << OP_HASH256 << ScriptID(redeemScript, true /* p2sh_32 */) << OP_EQUAL;
    result = GetScriptForDestination(ScriptID(redeemScript, true /* p2sh_32 */));
    BOOST_CHECK(result == expected);

    // CNoDestination
    expected.clear();
    result = GetScriptForDestination(CNoDestination());
    BOOST_CHECK(result == expected);

    // GetScriptForRawPubKey
    expected.clear();
    expected << pubkeys[0] << OP_CHECKSIG;
    result = GetScriptForRawPubKey(pubkeys[0]);
    BOOST_CHECK(result == expected);

    // GetScriptForMultisig
    expected.clear();
    expected << OP_2 << pubkeys[0] << pubkeys[1]
             << pubkeys[2] << OP_3 << OP_CHECKMULTISIG;
    result =
        GetScriptForMultisig(2, std::vector<CPubKey>(pubkeys, pubkeys + 3));
    BOOST_CHECK(result == expected);
}

BOOST_AUTO_TEST_CASE(script_standard_IsMine) {
    CKey keys[2];
    CPubKey pubkeys[2];
    for (int i = 0; i < 2; i++) {
        keys[i].MakeNewKey(true);
        pubkeys[i] = keys[i].GetPubKey();
    }

    CKey uncompressedKey;
    uncompressedKey.MakeNewKey(false);
    CPubKey uncompressedPubkey = uncompressedKey.GetPubKey();

    CScript scriptPubKey;
    isminetype result;

    // P2PK compressed
    {
        CBasicKeyStore keystore;
        scriptPubKey = GetScriptForRawPubKey(pubkeys[0]);

        // Keystore does not have key
        result = IsMine(keystore, scriptPubKey);
        BOOST_CHECK_EQUAL(result, ISMINE_NO);

        // Keystore has key
        BOOST_CHECK(keystore.AddKey(keys[0]));
        result = IsMine(keystore, scriptPubKey);
        BOOST_CHECK_EQUAL(result, ISMINE_SPENDABLE);
    }

    // P2PK uncompressed
    {
        CBasicKeyStore keystore;
        scriptPubKey = GetScriptForRawPubKey(uncompressedPubkey);

        // Keystore does not have key
        result = IsMine(keystore, scriptPubKey);
        BOOST_CHECK_EQUAL(result, ISMINE_NO);

        // Keystore has key
        BOOST_CHECK(keystore.AddKey(uncompressedKey));
        result = IsMine(keystore, scriptPubKey);
        BOOST_CHECK_EQUAL(result, ISMINE_SPENDABLE);
    }

    // P2PKH compressed
    {
        CBasicKeyStore keystore;
        scriptPubKey = GetScriptForDestination(pubkeys[0].GetID());

        // Keystore does not have key
        result = IsMine(keystore, scriptPubKey);
        BOOST_CHECK_EQUAL(result, ISMINE_NO);

        // Keystore has key
        BOOST_CHECK(keystore.AddKey(keys[0]));
        result = IsMine(keystore, scriptPubKey);
        BOOST_CHECK_EQUAL(result, ISMINE_SPENDABLE);
    }

    // P2PKH uncompressed
    {
        CBasicKeyStore keystore;
        scriptPubKey = GetScriptForDestination(uncompressedPubkey.GetID());

        // Keystore does not have key
        result = IsMine(keystore, scriptPubKey);
        BOOST_CHECK_EQUAL(result, ISMINE_NO);

        // Keystore has key
        BOOST_CHECK(keystore.AddKey(uncompressedKey));
        result = IsMine(keystore, scriptPubKey);
        BOOST_CHECK_EQUAL(result, ISMINE_SPENDABLE);
    }

    // P2SH-20
    {
        CBasicKeyStore keystore;

        CScript redeemScript = GetScriptForDestination(pubkeys[0].GetID());
        scriptPubKey = GetScriptForDestination(ScriptID(redeemScript, false /*=p2sh_20*/));

        // Keystore does not have redeemScript or key
        result = IsMine(keystore, scriptPubKey);
        BOOST_CHECK_EQUAL(result, ISMINE_NO);

        // Keystore has redeemScript but no key
        BOOST_CHECK(keystore.AddCScript(redeemScript, false /*=p2sh_20*/, false /* legacy vm limits */));
        result = IsMine(keystore, scriptPubKey);
        BOOST_CHECK_EQUAL(result, ISMINE_NO);

        // Keystore has redeemScript and key
        BOOST_CHECK(keystore.AddKey(keys[0]));
        result = IsMine(keystore, scriptPubKey);
        BOOST_CHECK_EQUAL(result, ISMINE_SPENDABLE);

        // Ensure that if we only added the P2SH-20, we don't also match P2SH-32
        CScript scriptPubKey32 = GetScriptForDestination(ScriptID(redeemScript, true /*=p2sh_32*/));
        result = IsMine(keystore, scriptPubKey32);
        BOOST_CHECK_EQUAL(result, ISMINE_NO);
    }

    // P2SH-32
    {
        CBasicKeyStore keystore;

        CScript redeemScript = GetScriptForDestination(pubkeys[0].GetID());
        scriptPubKey = GetScriptForDestination(ScriptID(redeemScript, true /*=p2sh_32*/));

        // Keystore does not have redeemScript or key
        result = IsMine(keystore, scriptPubKey);
        BOOST_CHECK_EQUAL(result, ISMINE_NO);

        // Keystore has redeemScript but no key
        BOOST_CHECK(keystore.AddCScript(redeemScript, true /*=p2sh_32*/, false /* legacy vm limits */));
        result = IsMine(keystore, scriptPubKey);
        BOOST_CHECK_EQUAL(result, ISMINE_NO);

        // Keystore has redeemScript and key
        BOOST_CHECK(keystore.AddKey(keys[0]));
        result = IsMine(keystore, scriptPubKey);
        BOOST_CHECK_EQUAL(result, ISMINE_SPENDABLE);

        // Ensure that if we only added the P2SH-32, we don't also match P2SH-20
        CScript scriptPubKey20 = GetScriptForDestination(ScriptID(redeemScript, false /*=p2sh_20*/));
        result = IsMine(keystore, scriptPubKey20);
        BOOST_CHECK_EQUAL(result, ISMINE_NO);
    }

    // (P2PKH inside) P2SH inside P2SH (invalid)
    {
        for (const bool is_p2sh_32 : {false, true}) {
            CBasicKeyStore keystore;

            CScript redeemscript_inner = GetScriptForDestination(pubkeys[0].GetID());
            CScript redeemscript = GetScriptForDestination(ScriptID(redeemscript_inner, is_p2sh_32));
            scriptPubKey = GetScriptForDestination(ScriptID(redeemscript, is_p2sh_32));

            BOOST_CHECK(keystore.AddCScript(redeemscript, is_p2sh_32, false /* legacy vm limits */));
            BOOST_CHECK(keystore.AddCScript(redeemscript_inner, is_p2sh_32, false /* legacy vm limits */));
            BOOST_CHECK(keystore.AddCScript(scriptPubKey, is_p2sh_32, false /* legacy vm limits */));
            BOOST_CHECK(keystore.AddKey(keys[0]));
            result = IsMine(keystore, scriptPubKey);
            BOOST_CHECK_EQUAL(result, ISMINE_NO);
        }
    }

    // scriptPubKey multisig
    {
        CBasicKeyStore keystore;

        scriptPubKey =
            GetScriptForMultisig(2, {uncompressedPubkey, pubkeys[1]});

        // Keystore does not have any keys
        result = IsMine(keystore, scriptPubKey);
        BOOST_CHECK_EQUAL(result, ISMINE_NO);

        // Keystore has 1/2 keys
        BOOST_CHECK(keystore.AddKey(uncompressedKey));

        result = IsMine(keystore, scriptPubKey);
        BOOST_CHECK_EQUAL(result, ISMINE_NO);

        // Keystore has 2/2 keys
        BOOST_CHECK(keystore.AddKey(keys[1]));

        result = IsMine(keystore, scriptPubKey);
        BOOST_CHECK_EQUAL(result, ISMINE_NO);

        // Keystore has 2/2 keys and the script
        BOOST_CHECK(keystore.AddCScript(scriptPubKey, false /*=p2sh_20*/, false /* legacy vm limits */));

        result = IsMine(keystore, scriptPubKey);
        BOOST_CHECK_EQUAL(result, ISMINE_NO);
    }

    // P2SH multisig
    {
        for (const bool is_p2sh_32 : {false, true}) {
            CBasicKeyStore keystore;
            BOOST_CHECK(keystore.AddKey(uncompressedKey));
            BOOST_CHECK(keystore.AddKey(keys[1]));

            CScript redeemScript = GetScriptForMultisig(2, {uncompressedPubkey, pubkeys[1]});
            scriptPubKey = GetScriptForDestination(ScriptID(redeemScript, is_p2sh_32));

            // Keystore has no redeemScript
            result = IsMine(keystore, scriptPubKey);
            BOOST_CHECK_EQUAL(result, ISMINE_NO);

            // Keystore has redeemScript
            BOOST_CHECK(keystore.AddCScript(redeemScript, is_p2sh_32, false /* legacy vm limits */));
            result = IsMine(keystore, scriptPubKey);
            BOOST_CHECK_EQUAL(result, ISMINE_SPENDABLE);
        }
    }

    // OP_RETURN
    {
        CBasicKeyStore keystore;
        BOOST_CHECK(keystore.AddKey(keys[0]));

        scriptPubKey.clear();
        scriptPubKey << OP_RETURN << pubkeys[0];

        result = IsMine(keystore, scriptPubKey);
        BOOST_CHECK_EQUAL(result, ISMINE_NO);
    }

    // Nonstandard
    {
        CBasicKeyStore keystore;
        BOOST_CHECK(keystore.AddKey(keys[0]));

        scriptPubKey.clear();
        scriptPubKey << OP_9 << OP_ADD << OP_11 << OP_EQUAL;

        result = IsMine(keystore, scriptPubKey);
        BOOST_CHECK_EQUAL(result, ISMINE_NO);
    }

    // Nonstandard, over p2s limit
    {
        CBasicKeyStore keystore;
        BOOST_CHECK(keystore.AddKey(keys[0]));

        scriptPubKey.clear();
        scriptPubKey << std::vector<uint8_t>(MAX_P2S_SCRIPT_SIZE, 0xef);
        BOOST_CHECK_GT(scriptPubKey.size(), MAX_P2S_SCRIPT_SIZE);

        result = IsMine(keystore, scriptPubKey);
        BOOST_CHECK_EQUAL(result, ISMINE_NO);
    }
}

BOOST_AUTO_TEST_SUITE_END()
