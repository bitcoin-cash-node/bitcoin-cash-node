// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017-2023 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>

#include <chainparamsconstants.h>
#include <chainparamsseeds.h>
#include <consensus/consensus.h>
#include <consensus/merkle.h>
#include <netbase.h>
#include <tinyformat.h>
#include <util/strencodings.h>
#include <util/system.h>

#include <cassert>
#include <cstring>
#include <memory>
#include <stdexcept>

static CBlock CreateGenesisBlock(const char *pszTimestamp,
                                 const CScript &genesisOutputScript,
                                 uint32_t nTime, uint32_t nNonce,
                                 uint32_t nBits, int32_t nVersion,
                                 const Amount genesisReward) {
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig =
        CScript() << ScriptInt::fromIntUnchecked(486604799)
                  << CScriptNum::fromIntUnchecked(4)
                  << std::vector<uint8_t>((const uint8_t *)pszTimestamp,
                                          (const uint8_t *)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime = nTime;
    genesis.nBits = nBits;
    genesis.nNonce = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation transaction
 * cannot be spent since it did not originally exist in the database.
 *
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000,
 * hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893,
 * vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase
 * 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */
CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits,
                          int32_t nVersion, const Amount genesisReward) {
    const char *pszTimestamp =
        "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks";
    const CScript genesisOutputScript =
        CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909"
                              "a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112"
                              "de5c384df7ba0b8d578a4c702b6bf11d5f")
                  << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce,
                              nBits, nVersion, genesisReward);
}

/**
 * Main network
 */
class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = CBaseChainParams::MAIN;
        consensus.nSubsidyHalvingInterval = 210000;
        // 00000000000000ce80a7e057163a4db1d5ad7b20fb6f598c9597b9665c8fb0d4 -
        // April 1, 2012
        consensus.BIP16Height = 173805;
        consensus.BIP34Height = 227931;
        consensus.BIP34Hash = BlockHash::fromHex(
            "000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8");
        // 000000000000000004c2b624ed5d7756c508d90fd0da2c7c679febfa6c4735f0
        consensus.BIP65Height = 388381;
        // 00000000000000000379eaa19dce8c9b722d46ae6a57c2f1a988119488b50931
        consensus.BIP66Height = 363725;
        // 000000000000000004a1b34462cb8aeebd5799177f7a29cf28f2d1961716b5b5
        consensus.CSVHeight = 419328;
        consensus.powLimit = uint256S(
            "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        // two weeks
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60;
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;

        // The half life for the ASERT DAA. For every (nASERTHalfLife) seconds behind schedule the blockchain gets,
        // difficulty is cut in half. Doubled if blocks are ahead of schedule.
        // Two days
        consensus.nASERTHalfLife = 2 * 24 * 60 * 60;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork =
            ChainParamsConstants::MAINNET_MINIMUM_CHAIN_WORK;

        // By default assume that the signatures in ancestors of this block are
        // valid.
        consensus.defaultAssumeValid =
            ChainParamsConstants::MAINNET_DEFAULT_ASSUME_VALID;

        // August 1, 2017 hard fork
        consensus.uahfHeight = 478558;

        // November 13, 2017 hard fork
        consensus.daaHeight = 504031;

        // November 15, 2018 hard fork
        consensus.magneticAnomalyHeight = 556766;

        // November 15, 2019 protocol upgrade
        consensus.gravitonHeight = 609135;

        // May 15, 2020 12:00:00 UTC protocol upgrade
        consensus.phononHeight = 635258;

        // Nov 15, 2020 12:00:00 UTC protocol upgrade
        consensus.axionActivationTime = 1605441600;

        // May 15, 2021 12:00:00 UTC protocol upgrade was 1621080000, but since this upgrade was for relay rules only,
        // we do not track this time (since it does not apply at all to the blockchain itself).

        // May 15, 2022 12:00:00 UTC protocol upgrade (upgrade8) height was 740237

        // May 15, 2023 12:00:00 UTC protocol upgrade (this is one less than the upgrade block itself)
        consensus.upgrade9Height = 792772;

        // May 15, 2024 12:00:00 UTC protocol upgrade (this is one less than the upgrade block itself)
        consensus.upgrade10Height = 845890;

        // May 15, 2025 12:00:00 UTC protocol upgrade (this is one less than the first block mined under new rules)
        consensus.upgrade11Height = 898373;

        // May 15, 2026 12:00:00 UTC protocol upgrade
        consensus.upgrade12ActivationTime = 1778846400;

        // May 15, 2027 12:00:00 UTC tentative protocol upgrade
        consensus.upgrade2027ActivationTime = 1810382400;

        // Default limit for block size (in bytes)
        consensus.nDefaultConsensusBlockSize = DEFAULT_CONSENSUS_BLOCK_SIZE;

        // Chain-specific default for mining block size, in percent of excessive block size (conf: -percentblockmaxsize)
        consensus.nDefaultGeneratedBlockSizePercent = 50.0; // 50% of 32MB = 16MB

        assert(consensus.nDefaultGeneratedBlockSizePercent >= 0.0
               && consensus.nDefaultGeneratedBlockSizePercent <= 100.0);
        assert(consensus.GetDefaultGeneratedBlockSizeBytes() <= consensus.nDefaultConsensusBlockSize);

        // Anchor params: Note that the block after this height *must* also be checkpointed below.
        consensus.asertAnchorParams = Consensus::Params::ASERTAnchor{
            661647,       // anchor block height
            0x1804dafe,   // anchor block nBits
            1605447844,   // anchor block previous block timestamp
        };

        // ABLA config -- upgrade 10 adjustable block limit algorithm
        consensus.ablaConfig = abla::Config::MakeDefault(consensus.nDefaultConsensusBlockSize, /* fixedSize = */ false);
        // Ensure base ABLA state yields same limit as pre-activation.
        assert(abla::State(consensus.ablaConfig, 0).GetBlockSizeLimit() == consensus.nDefaultConsensusBlockSize);
        // Ensure ABLA is *not* "fixed size" for mainnet
        assert( ! consensus.ablaConfig.IsFixedSize());

        /**
         * The message start string is designed to be unlikely to occur in
         * normal data. The characters are rarely used upper ASCII, not valid as
         * UTF-8, and produce a large 32-bit integer with any alignment.
         */
        diskMagic[0] = 0xf9;
        diskMagic[1] = 0xbe;
        diskMagic[2] = 0xb4;
        diskMagic[3] = 0xd9;
        netMagic[0] = 0xe3;
        netMagic[1] = 0xe1;
        netMagic[2] = 0xf3;
        netMagic[3] = 0xe8;
        nDefaultPort = 8333;
        nPruneAfterHeight = 100000;
        m_assumed_blockchain_size = 250;    // 207G
        m_assumed_chain_state_size = 6;     // 4.2G

        genesis = CreateGenesisBlock(1231006505, 2083236893, 0x1d00ffff, 1,
                                     50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock ==
               uint256S("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1"
                        "b60a8ce26f"));
        assert(genesis.hashMerkleRoot ==
               uint256S("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b"
                        "7afdeda33b"));

        vSeeds.emplace_back("seed.flowee.cash");
        // Note that of those which support the service bits prefix, most only
        // support a subset of possible options. This is fine at runtime as
        // we'll fall back to using them as a oneshot if they don't support the
        // service bits we want, but we should get them updated to support all
        // service bits wanted by any release ASAP to avoid it where possible.
        // bitcoinforks seeders
        vSeeds.emplace_back("seed-bch.bitcoinforks.org");
        // BU backed seeder
        vSeeds.emplace_back("btccash-seeder.bitcoinunlimited.info");
        // BCHD
        vSeeds.emplace_back("seed.bchd.cash");
        // Loping.net
        vSeeds.emplace_back("seed.bch.loping.net");
        // C3 Soft (NilacTheGrim)
        vSeeds.emplace_back("bchseed.c3-soft.com");
        // Jason Dreyzehner
        vSeeds.emplace_back("bch.bitjson.com");

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<uint8_t>(1, 0);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<uint8_t>(1, 5);
        base58Prefixes[SECRET_KEY] = std::vector<uint8_t>(1, 128);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};
        cashaddrPrefix = "bitcoincash";

        vFixedSeeds.assign(std::begin(pnSeed6_main), std::end(pnSeed6_main));

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        m_is_test_chain = false;

        checkpointData = {
            /* .mapCheckpoints = */ {
                {11111, BlockHash::fromHex("0000000069e244f73d78e8fd29ba2fd2ed6"
                                           "18bd6fa2ee92559f542fdb26e7c1d")},
                {33333, BlockHash::fromHex("000000002dd5588a74784eaa7ab0507a18a"
                                           "d16a236e7b1ce69f00d7ddfb5d0a6")},
                {74000, BlockHash::fromHex("0000000000573993a3c9e41ce34471c079d"
                                           "cf5f52a0e824a81e7f953b8661a20")},
                {105000, BlockHash::fromHex("00000000000291ce28027faea320c8d2b0"
                                            "54b2e0fe44a773f3eefb151d6bdc97")},
                {134444, BlockHash::fromHex("00000000000005b12ffd4cd315cd34ffd4"
                                            "a594f430ac814c91184a0d42d2b0fe")},
                {168000, BlockHash::fromHex("000000000000099e61ea72015e79632f21"
                                            "6fe6cb33d7899acb35b75c8303b763")},
                {193000, BlockHash::fromHex("000000000000059f452a5f7340de6682a9"
                                            "77387c17010ff6e6c3bd83ca8b1317")},
                {210000, BlockHash::fromHex("000000000000048b95347e83192f69cf03"
                                            "66076336c639f9b7228e9ba171342e")},
                {216116, BlockHash::fromHex("00000000000001b4f4b433e81ee46494af"
                                            "945cf96014816a4e2370f11b23df4e")},
                {225430, BlockHash::fromHex("00000000000001c108384350f74090433e"
                                            "7fcf79a606b8e797f065b130575932")},
                {250000, BlockHash::fromHex("000000000000003887df1f29024b06fc22"
                                            "00b55f8af8f35453d7be294df2d214")},
                {279000, BlockHash::fromHex("0000000000000001ae8c72a0b0c301f67e"
                                            "3afca10e819efa9041e458e9bd7e40")},
                {295000, BlockHash::fromHex("00000000000000004d9b4ef50f0f9d686f"
                                            "d69db2e03af35a100370c64632a983")},
                // UAHF fork block.
                {478559, BlockHash::fromHex("000000000000000000651ef99cb9fcbe0d"
                                            "adde1d424bd9f15ff20136191a5eec")},
                // Nov, 13 DAA activation block.
                {504032, BlockHash::fromHex("00000000000000000343e9875012f20625"
                                            "54c8752929892c82a0c0743ac7dcfd")},
                // Monolith activation.
                {530359, BlockHash::fromHex("0000000000000000011ada8bd08f46074f"
                                            "44a8f155396f43e38acf9501c49103")},
                // Magnetic anomaly activation.
                {556767, BlockHash::fromHex("0000000000000000004626ff6e3b936941"
                                            "d341c5932ece4357eeccac44e6d56c")},
                // Great wall activation.
                {582680, BlockHash::fromHex("000000000000000001b4b8e36aec7d4f96"
                                            "71a47872cb9a74dc16ca398c7dcc18")},
                // Graviton activation.
                {609136, BlockHash::fromHex("000000000000000000b48bb207faac5ac6"
                                            "55c313e41ac909322eaa694f5bc5b1")},
                // Phonon activation.
                {635259, BlockHash::fromHex("00000000000000000033dfef1fc2d6a5d5"
                                            "520b078c55193a9bf498c5b27530f7")},
                // Axion activation.
                {661648, BlockHash::fromHex("0000000000000000029e471c41818d24b8"
                                            "b74c911071c4ef0b4a0509f9b5a8ce")},
                {682900, BlockHash::fromHex("0000000000000000018b0a60a00ca53b69"
                                            "b213a8515e5eedbf8a207f0355fe42")},

                // Upgrade 7 ("tachyon") era (actual activation block was 688094)
                {699484, BlockHash::fromHex("0000000000000000030192242425926218184a609a63efee615b7586d7f3972b")},
                {714881, BlockHash::fromHex("000000000000000004cd628ee64c058183e780bc31143ff00680ea8af51fa0ff")},

                // Upgrade 8; May 15, 2022 (MTP time >= 1652616000), first upgrade block: 740238
                {740238, BlockHash::fromHex("000000000000000002afc6fbd302f01f8cf4533f4b45207abc61d9f4297bf969")},
                {741245, BlockHash::fromHex("000000000000000001c46d1d0f35df726bfb3e84cdc396d9edd9e2f8414191cd")},
                {768220, BlockHash::fromHex("0000000000000000012f9d67fc9304253bdf204b65782816cbbc64913398e25b")},
                {773784, BlockHash::fromHex("0000000000000000045cc0dbdd5cbbb86f7f63596e699ac5a11b2d41c65c6993")},

                // Upgrade 9; May 15, 2023 (MTP time >= 1684152000), first upgrade block: 792773
                {792773, BlockHash::fromHex("000000000000000002fc0cdadaef1857bbd2936d37ea94f80ba3db4a5e8353e8")},

                // Upgrade 10; May 15, 2024 (MTP time >= 1715774400), first block after upgrade: 845891
                {845891, BlockHash::fromHex("0000000000000000017012058e7b67032926f1f20f96d1a2cd66abff9aaf8244")},
                {853417, BlockHash::fromHex("000000000000000001c97a4c91c7a85d5f56a7ecd119f21abffdc6987a1be792")},
                {873239, BlockHash::fromHex("000000000000000000e28c75f4b398b3ac410755d18ef9314b770c3d08cb130e")},
                {878660, BlockHash::fromHex("000000000000000000c166d5661c13195722ae6fbee90f0ab2407ae60b71c2e6")},

                // Upgrade 11; May 15, 2025 (MTP time >= 1747310400), first block mined with upgrade rules: 898374
                {898374, BlockHash::fromHex("00000000000000000157a0a3dcdc80f1acd809648d238c1e893b26247091b3b4")},
                {901000, BlockHash::fromHex("000000000000000001eda4b93cfe9bc790906f2358fc5643ff335da5e7bbae5d")},
                {932228, BlockHash::fromHex("0000000000000000005a48a20e13f038be389952014373478b6a6a90d40e4680")},
            }};

        // Data as of block
        // 000000000000000000cf9718a045f88b75aca57e656e9c29482f626b1de7c7bc
        // (height 930654).
        chainTxData = ChainTxData{
            // UNIX timestamp of last known number of transactions.
            1766496206,
            // Total number of transactions between genesis and that timestamp
            // (the tx=... number in the ChainStateFlushed debug.log lines)
            413089131,
            // Estimated number of transactions per second after that timestamp.
            0.382,
        };
    }
};

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = CBaseChainParams::TESTNET;
        consensus.nSubsidyHalvingInterval = 210000;
        // 00000000040b4e986385315e14bee30ad876d8b47f748025b26683116d21aa65
        consensus.BIP16Height = 514;
        consensus.BIP34Height = 21111;
        consensus.BIP34Hash = BlockHash::fromHex(
            "0000000023b3a96d3484e5abb3755c413e7d41500f8e2a5c3f0dd01299cd8ef8");
        // 00000000007f6655f22f98e72ed80d8b06dc761d5da09df0fa1dc4be4f861eb6
        consensus.BIP65Height = 581885;
        // 000000002104c8c45e99a8853285a3b592602a3ccde2b832481da85e9e4ba182
        consensus.BIP66Height = 330776;
        // 00000000025e930139bac5c6c31a403776da130831ab85be56578f3fa75369bb
        consensus.CSVHeight = 770112;
        consensus.powLimit = uint256S(
            "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        // two weeks
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60;
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;

        // The half life for the ASERT DAA. For every (nASERTHalfLife) seconds behind schedule the blockchain gets,
        // difficulty is cut in half. Doubled if blocks are ahead of schedule.
        // One hour
        consensus.nASERTHalfLife = 60 * 60;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork =
            ChainParamsConstants::TESTNET_MINIMUM_CHAIN_WORK;

        // By default assume that the signatures in ancestors of this block are
        // valid.
        consensus.defaultAssumeValid =
            ChainParamsConstants::TESTNET_DEFAULT_ASSUME_VALID;

        // August 1, 2017 hard fork
        consensus.uahfHeight = 1155875;

        // November 13, 2017 hard fork
        consensus.daaHeight = 1188697;

        // November 15, 2018 hard fork
        consensus.magneticAnomalyHeight = 1267996;

        // November 15, 2019 protocol upgrade
        consensus.gravitonHeight = 1341711;

        // May 15, 2020 12:00:00 UTC protocol upgrade
        consensus.phononHeight = 1378460;

        // Nov 15, 2020 12:00:00 UTC protocol upgrade
        consensus.axionActivationTime = 1605441600;

        // May 15, 2022 12:00:00 UTC protocol upgrade (upgrade8) height was 1500205

        // May 15, 2023 12:00:00 UTC protocol upgrade (this is one less than the upgrade block itself)
        consensus.upgrade9Height = 1552787;

        // May 15, 2024 12:00:00 UTC protocol upgrade (this is one less than the upgrade block itself)
        consensus.upgrade10Height = 1605520;

        // May 15, 2025 12:00:00 UTC protocol upgrade (this is one less than the first block mined under new rules)
        consensus.upgrade11Height = 1658049;

        // May 15, 2026 12:00:00 UTC protocol upgrade
        consensus.upgrade12ActivationTime = 1778846400;

        // May 15, 2027 12:00:00 UTC tentative protocol upgrade
        consensus.upgrade2027ActivationTime = 1810382400;

        // Default limit for block size (in bytes)
        consensus.nDefaultConsensusBlockSize = DEFAULT_CONSENSUS_BLOCK_SIZE;

        // Chain-specific default for mining block size, in percent of excessive block size (conf: -percentblockmaxsize)
        consensus.nDefaultGeneratedBlockSizePercent = 50.0; // 50% of 32MB = 16MB

        assert(consensus.nDefaultGeneratedBlockSizePercent >= 0.0
               && consensus.nDefaultGeneratedBlockSizePercent <= 100.0);
        assert(consensus.GetDefaultGeneratedBlockSizeBytes() <= consensus.nDefaultConsensusBlockSize);

        // Anchor params: Note that the block after this height *must* also be checkpointed below.
        consensus.asertAnchorParams = Consensus::Params::ASERTAnchor{
            1421481,      // anchor block height
            0x1d00ffff,   // anchor block nBits
            1605445400,   // anchor block previous block timestamp
        };

        // ABLA config -- upgrade 10 adjustable block limit algorithm
        consensus.ablaConfig = abla::Config::MakeDefault(consensus.nDefaultConsensusBlockSize, /* fixedSize = */ true);
        // Ensure base abla state yields same limit as pre-activation.
        assert(abla::State(consensus.ablaConfig, 0).GetBlockSizeLimit() == consensus.nDefaultConsensusBlockSize);
        // Ensure ABLA *is* "fixed size" for testnet3
        assert(consensus.ablaConfig.IsFixedSize());

        diskMagic[0] = 0x0b;
        diskMagic[1] = 0x11;
        diskMagic[2] = 0x09;
        diskMagic[3] = 0x07;
        netMagic[0] = 0xf4;
        netMagic[1] = 0xe5;
        netMagic[2] = 0xf3;
        netMagic[3] = 0xf4;
        nDefaultPort = 18333;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 60;     // 43G
        m_assumed_chain_state_size = 2;     // 1.3G

        genesis =
            CreateGenesisBlock(1296688602, 414098458, 0x1d00ffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock ==
               uint256S("000000000933ea01ad0ee984209779baaec3ced90fa3f408719526"
                        "f8d77f4943"));
        assert(genesis.hashMerkleRoot ==
               uint256S("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b"
                        "7afdeda33b"));

        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
        // BCHD
        vSeeds.emplace_back("testnet-seed.bchd.cash");
        // Loping.net
        vSeeds.emplace_back("seed.tbch.loping.net");
        // Bitcoin Unlimited
        vSeeds.emplace_back("testnet-seed.bitcoinunlimited.info");

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<uint8_t>(1, 111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<uint8_t>(1, 196);
        base58Prefixes[SECRET_KEY] = std::vector<uint8_t>(1, 239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};
        cashaddrPrefix = "bchtest";
        vFixedSeeds.assign(std::begin(pnSeed6_testnet3), std::end(pnSeed6_testnet3));

        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        m_is_test_chain = true;

        checkpointData = {
            /* .mapCheckpoints = */ {
                {546, BlockHash::fromHex("000000002a936ca763904c3c35fce2f3556c5"
                                         "59c0214345d31b1bcebf76acb70")},
                // UAHF fork block.
                {1155876,
                 BlockHash::fromHex("00000000000e38fef93ed9582a7df43815d5c2ba9f"
                                    "d37ef70c9a0ea4a285b8f5")},
                // Nov, 13. DAA activation block.
                {1188698,
                 BlockHash::fromHex("0000000000051b450faa75bb8e1ea30bc18c4b9736"
                                    "e765d2794259a53bc83f99")},
                // Great wall activation.
                {1303885,
                 BlockHash::fromHex("00000000000000479138892ef0e4fa478ccc938fb9"
                                    "4df862ef5bde7e8dee23d3")},
                // Graviton activation.
                {1341712,
                 BlockHash::fromHex("00000000fffc44ea2e202bd905a9fbbb9491ef9e9d"
                                    "5a9eed4039079229afa35b")},
                // Phonon activation.
                {1378461, BlockHash::fromHex(
                              "0000000099f5509b5f36b1926bcf82b21d936ebeade"
                              "e811030dfbbb7fae915d7")},
                // Axion activation.
                {1421482, BlockHash::fromHex(
                              "0000000023e0680a8a062b3cc289a4a341124ce7fcb6340ede207e194d73b60a")},
                {1442860, BlockHash::fromHex(
                              "000000000004f42ffcf218d285cbd8d8d93e1c5a4262bdd1fdfd1991cfdb5027")},

                // Upgrade 7 ("tachyon") era (actual activation block was in the past significantly before this)
                {1459354, BlockHash::fromHex(
                              "00000000499a0384fe7f46f4e5470271804df474b19229aee839ea898d5d07e2")},
                {1472870, BlockHash::fromHex(
                              "00000000000000b013f75c2cf5e357b5f95af715c2829b0686ee53663101a6e0")},

                // Upgrade 8; May 15, 2022 (MTP time >= 1652616000), first upgrade block: 1500206
                {1500206, BlockHash::fromHex("000000000000360769353e933530c40d3f00565a4e7731ff56027e23fa74a8ef")},
                {1526155, BlockHash::fromHex("0000000057fa336560212f0ff351ca6b2008c6c48032bc305e5b4663e837953f")},
                {1532821, BlockHash::fromHex("00000000000000e2e476a806171758c75e6fd4c28d1435a56701df87874ddd2f")},

                // Upgrade 9; May 15, 2023 (MTP time >= 1684152000), first upgrade block: 1552788
                {1552788, BlockHash::fromHex("000000007bc92323648b95ea8401a2247e977b653b13adb9e40748ce06b30a5e")},

                // prior to upgrade 10 (to be replaced with a real upgrade 10 checkpoint after May 15, 2024
                {1582896, BlockHash::fromHex("000000000000088ef4d908ed35dc511b97fe4df78d5e37ab1e1aea4084d19506")},

                // Upgrade 10; May 15, 2024 (MTP time >= 1715774400), first block after upgrade: 1605521
                {1605521, BlockHash::fromHex("000000000000007d4c561056e9bcb3ab7591d024b18fff4bc27cca4d51d4780e")},
                {1610899, BlockHash::fromHex("00000000e2f5dde96179ea278285118ad69e5d94b9269fef63c604b3d551a5d0")},
                {1630783, BlockHash::fromHex("000000002e0058b88b1857bbf2ca3edaaade318e54bbb9226ca53b3ae5528f90")},
                {1636000, BlockHash::fromHex("0000000000001af6a0fb0ec4f079858b6add6d070381f94157be80fdb4809c65")},

                // Upgrade 11; May 15, 2025 (MTP time >= 1747310400), first block mined with upgrade rules: 1658050
                {1658050, BlockHash::fromHex("0000000015d90bbd6deeb63cf86dc1f794d76c697d2ea86a42158c8003da8c5e")},
                {1689348, BlockHash::fromHex("000000001935f758281aa60414a1218dcd09b4dc6b7ad0be2a3cddbcd38ff265")},
            }};

        // Data as of block
        // 000000001ff57d1ed3ee1d5e0a3c48ac4d8607ccd66602f9a4cdedf5e2cc131a
        // (height 1689425)
        chainTxData = ChainTxData{1766497032 /* time */, 64343360 /* numTx */, 0.00327 /* tx/sec */};
    }
};

/**
 * Testnet (v4)
 */
class CTestNet4Params : public CChainParams {
public:
    CTestNet4Params() {
        strNetworkID = CBaseChainParams::TESTNET4;
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.BIP16Height = 1;
        // Note: Because BIP34Height is less than 17, clients will face an unusual corner case with BIP34 encoding.
        // The "correct" encoding for BIP34 blocks at height <= 16 uses OP_1 (0x81) through OP_16 (0x90) as a single
        // byte (i.e. "[shortest possible] encoded CScript format"), not a single byte with length followed by the
        // little-endian encoded version of the height as mentioned in BIP34. The BIP34 spec document itself ought to
        // be updated to reflect this.
        // https://github.com/bitcoin/bitcoin/pull/14633
        consensus.BIP34Height = 2;
        consensus.BIP34Hash = BlockHash::fromHex("00000000b0c65b1e03baace7d5c093db0d6aac224df01484985ffd5e86a1a20c");
        consensus.BIP65Height = 3;
        consensus.BIP66Height = 4;
        consensus.CSVHeight = 5;
        consensus.powLimit = uint256S("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        // two weeks
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60;
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;

        // The half life for the ASERT DAA. For every (nASERTHalfLife) seconds behind schedule the blockchain gets,
        // difficulty is cut in half. Doubled if blocks are ahead of schedule.
        // One hour
        consensus.nASERTHalfLife = 60 * 60;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = ChainParamsConstants::TESTNET4_MINIMUM_CHAIN_WORK;

        // By default assume that the signatures in ancestors of this block are
        // valid.
        consensus.defaultAssumeValid = ChainParamsConstants::TESTNET4_DEFAULT_ASSUME_VALID;

        // August 1, 2017 hard fork
        consensus.uahfHeight = 6;

        // November 13, 2017 hard fork
        consensus.daaHeight = 3000;

        // November 15, 2018 hard fork
        consensus.magneticAnomalyHeight = 4000;

        // November 15, 2019 protocol upgrade
        consensus.gravitonHeight = 5000;

        // May 15, 2020 12:00:00 UTC protocol upgrade
        // Note: We must set this to 0 here because "historical" sigop code has
        //       been removed from the BCHN codebase. All sigop checks really
        //       use the new post-May2020 sigcheck code unconditionally in this
        //       codebase, regardless of what this height is set to. So it's
        //       "as-if" the activation height really is 0 for all intents and
        //       purposes. If other node implementations wish to use this code
        //       as a reference, they need to be made aware of this quirk of
        //       BCHN, so we explicitly set the activation height to zero here.
        //       For example, BU or other nodes do keep both sigop and sigcheck
        //       implementations in their execution paths so they will need to
        //       use 0 here to be able to synch to this chain.
        //       See: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/issues/167
        consensus.phononHeight = 0;

        // Nov 15, 2020 12:00:00 UTC protocol upgrade
        consensus.axionActivationTime = 1605441600;

        // May 15, 2022 12:00:00 UTC protocol upgrade (upgrade8) height was 95464

        // May 15, 2023 12:00:00 UTC protocol upgrade (this is one less than the upgrade block itself)
        consensus.upgrade9Height = 148043;

        // May 15, 2024 12:00:00 UTC protocol upgrade (this is one less than the upgrade block itself)
        consensus.upgrade10Height = 200740;

        // May 15, 2025 12:00:00 UTC protocol upgrade (this is one less than the first block mined under new rules)
        consensus.upgrade11Height = 253318;

        // May 15, 2026 12:00:00 UTC protocol upgrade
        consensus.upgrade12ActivationTime = 1778846400;

        // May 15, 2027 12:00:00 UTC tentative protocol upgrade
        consensus.upgrade2027ActivationTime = 1810382400;

        // Default limit for block size (in bytes) (testnet4 is smaller at 2MB)
        consensus.nDefaultConsensusBlockSize = 2 * ONE_MEGABYTE;

        // Chain-specific default for mining block size, in percent of excessive block size (conf: -percentblockmaxsize)
        consensus.nDefaultGeneratedBlockSizePercent = 100.0; // 100% of 2MB = 2MB

        assert(consensus.nDefaultGeneratedBlockSizePercent >= 0.0
               && consensus.nDefaultGeneratedBlockSizePercent <= 100.0);
        assert(consensus.GetDefaultGeneratedBlockSizeBytes() <= consensus.nDefaultConsensusBlockSize);

        // Anchor params: Note that the block after this height *must* also be checkpointed below.
        consensus.asertAnchorParams = Consensus::Params::ASERTAnchor{
            16844,        // anchor block height
            0x1d00ffff,   // anchor block nBits
            1605451779,   // anchor block previous block timestamp
        };

        // ABLA config -- upgrade 10 adjustable block limit algorithm
        consensus.ablaConfig = abla::Config::MakeDefault(consensus.nDefaultConsensusBlockSize, /* fixedSize = */ true);
        // Ensure base abla state yields same limit as pre-activation.
        assert(abla::State(consensus.ablaConfig, 0).GetBlockSizeLimit() == consensus.nDefaultConsensusBlockSize);
        // Ensure ABLA *is* "fixed size" for testnet4
        assert(consensus.ablaConfig.IsFixedSize());

        diskMagic[0] = 0xcd;
        diskMagic[1] = 0x22;
        diskMagic[2] = 0xa7;
        diskMagic[3] = 0x92;
        netMagic[0] = 0xe2;
        netMagic[1] = 0xb7;
        netMagic[2] = 0xda;
        netMagic[3] = 0xaf;
        nDefaultPort = 28333;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 1;      // 82M
        m_assumed_chain_state_size = 1;     // 12M

        genesis = CreateGenesisBlock(1597811185, 114152193, 0x1d00ffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock ==
            BlockHash::fromHex("000000001dd410c49a788668ce26751718cc797474d3152a5fc073dd44fd9f7b"));

        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
        vSeeds.emplace_back("testnet4-seed-bch.toom.im");
        // Loping.net
        vSeeds.emplace_back("seed.tbch4.loping.net");
        // Flowee
        vSeeds.emplace_back("testnet4-seed.flowee.cash");
        // Jason Dreyzehner
        vSeeds.emplace_back("testnet4.bitjson.com");

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<uint8_t>(1, 111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<uint8_t>(1, 196);
        base58Prefixes[SECRET_KEY] = std::vector<uint8_t>(1, 239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};
        cashaddrPrefix = "bchtest";
        vFixedSeeds.assign(std::begin(pnSeed6_testnet4), std::end(pnSeed6_testnet4));

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        m_is_test_chain = true;

        checkpointData = {
            /* .mapCheckpoints = */ {
                {0, genesis.GetHash()},
                {5000, BlockHash::fromHex("000000009f092d074574a216faec682040a853c4f079c33dfd2c3ef1fd8108c4")},
                // Axion activation.
                {16845, BlockHash::fromHex("00000000fb325b8f34fe80c96a5f708a08699a68bbab82dba4474d86bd743077")},
                {38000, BlockHash::fromHex("000000000015197537e59f339e3b1bbf81a66f691bd3d7aa08560fc7bf5113fb")},

                // Upgrade 7 ("tachyon") era (actual activation block was in the past significantly before this)
                {54700, BlockHash::fromHex("00000000009af4379d87f17d0f172ee4769b48839a5a3a3e81d69da4322518b8")},
                {68117, BlockHash::fromHex("0000000000a2c2fc11a3b72adbd10a3f02a1f8745da55a85321523043639829a")},

                // Upgrade 8; May 15, 2022 (MTP time >= 1652616000), first upgrade block: 95465
                {95465, BlockHash::fromHex("00000000a77206a2265cabc47cc2c34706ba1c5e5a5743ac6681b83d43c91a01")},
                {115252, BlockHash::fromHex("00000000ae25e85d9e22cd6c8d72c2f5d4b0222289d801b7f633aeae3f8c6367")},
                {121428, BlockHash::fromHex("00000000002cf277337c504f7ce708cce851d5d20cad2936fedf3be95a9ca5eb")},
                {128070, BlockHash::fromHex("00000000044f34642fa3d91e34678737cc10a821a4696f50c187091c3df480c2")},

                // Upgrade 9; May 15, 2023 (MTP time >= 1684152000), first upgrade block: 148044
                {148044, BlockHash::fromHex("0000000008d96c4423ac92aa200af82819339435251736b08babde1ecaf8a5b6")},

                // Upgrade 10; May 15, 2024 (MTP time >= 1715774400), first block after upgrade: 200741
                {200741, BlockHash::fromHex("0000000007d8ccbb767c269551dd81c520463066bec8654a18f4106aa53dc816")},
                {206379, BlockHash::fromHex("000000001d44ca6c351af579f81703c0a175d1d4554db70ae7b7f7df2919eaf9")},
                {226116, BlockHash::fromHex("000000008416a726dd957835add86d7166ef331b74f2f2ca38928dcd56484f8e")},
                {232000, BlockHash::fromHex("0000000018ef632fc8a77dd4ff6a6e29ad2c7af405af63247c6f28a051b1b817")},

                // Upgrade 11; May 15, 2025 (MTP time >= 1747310400), first block mined with upgrade rules: 253319
                {253319, BlockHash::fromHex("00000000004605937a919cf6f636b68e8137b5cb0226ddbc9e00f386ef02999b")},
                {277407, BlockHash::fromHex("00000000fd6af07e5c4618de0cc36796f9470620eb4610584d9011b9f41d3400")},
            }};

        // Data as of block
        // 0000000040d07c4639ce52cb07deb89016bd4af30ccf5fcdde8fddb62c738e40
        // (height 278588)
        chainTxData = {1766497469 /* time */, 388175 /* numTx */, 0.0034 /* tx/sec */};
    }
};

/**
 * Scalenet
 */
class CScaleNetParams : public CChainParams {
public:
    CScaleNetParams() {
        strNetworkID = CBaseChainParams::SCALENET;
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.BIP16Height = 1;
        consensus.BIP34Height = 2;
        // Note: Because BIP34Height is less than 17, clients will face an unusual corner case with BIP34 encoding.
        // The "correct" encoding for BIP34 blocks at height <= 16 uses OP_1 (0x81) through OP_16 (0x90) as a single
        // byte (i.e. "[shortest possible] encoded CScript format"), not a single byte with length followed by the
        // little-endian encoded version of the height as mentioned in BIP34. The BIP34 spec document itself ought to
        // be updated to reflect this.
        // https://github.com/bitcoin/bitcoin/pull/14633
        consensus.BIP34Hash = BlockHash::fromHex("00000000c8c35eaac40e0089a83bf5c5d9ecf831601f98c21ed4a7cb511a07d8");
        consensus.BIP65Height = 3;
        consensus.BIP66Height = 4;
        consensus.CSVHeight = 5;
        consensus.powLimit = uint256S("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        // two weeks
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60;
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;

        // The half life for the ASERT DAA. For every (nASERTHalfLife) seconds behind schedule the blockchain gets,
        // difficulty is cut in half. Doubled if blocks are ahead of schedule.
        // Two days
        consensus.nASERTHalfLife = 2 * 24 * 60 * 60;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = ChainParamsConstants::SCALENET_MINIMUM_CHAIN_WORK;

        // By default assume that the signatures in ancestors of this block are
        // valid.
        consensus.defaultAssumeValid = ChainParamsConstants::SCALENET_DEFAULT_ASSUME_VALID;

        // August 1, 2017 hard fork
        consensus.uahfHeight = 6;

        // November 13, 2017 hard fork
        consensus.daaHeight = 3000;

        // November 15, 2018 hard fork
        consensus.magneticAnomalyHeight = 4000;

        // November 15, 2019 protocol upgrade
        consensus.gravitonHeight = 5000;

        // May 15, 2020 12:00:00 UTC protocol upgrade
        // Note: We must set this to 0 here because "historical" sigop code has
        //       been removed from the BCHN codebase. All sigop checks really
        //       use the new post-May2020 sigcheck code unconditionally in this
        //       codebase, regardless of what this height is set to. So it's
        //       "as-if" the activation height really is 0 for all intents and
        //       purposes. If other node implementations wish to use this code
        //       as a reference, they need to be made aware of this quirk of
        //       BCHN, so we explicitly set the activation height to zero here.
        //       For example, BU or other nodes do keep both sigop and sigcheck
        //       implementations in their execution paths so they will need to
        //       use 0 here to be able to synch to this chain.
        //       See: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/issues/167
        consensus.phononHeight = 0;

        // Nov 15, 2020 12:00:00 UTC protocol upgrade
        consensus.axionActivationTime = 1605441600;

        // May 15, 2022 12:00:00 UTC protocol upgrade (upgrade8), retroactively always enabled

        // May 15, 2023 12:00:00 UTC protocol upgrade
        consensus.upgrade9Height = 10'006;

        // May 15, 2024 12:00:00 UTC protocol upgrade
        consensus.upgrade10Height = 10'006;

        // May 15, 2025 12:00:00 UTC protocol upgrade
        consensus.upgrade11Height = 10'006;

        // May 15, 2026 12:00:00 UTC protocol upgrade
        consensus.upgrade12ActivationTime = 1778846400;

        // May 15, 2027 12:00:00 UTC tentative protocol upgrade
        consensus.upgrade2027ActivationTime = 1810382400;

        // Default limit for block size (in bytes)
        consensus.nDefaultConsensusBlockSize = 256 * ONE_MEGABYTE;

        // Chain-specific default for mining block size, in percent of excessive block size (conf: -percentblockmaxsize)
        consensus.nDefaultGeneratedBlockSizePercent = 6.25; // 6.25% of 256MB = 16MB

        assert(consensus.nDefaultGeneratedBlockSizePercent >= 0.0
               && consensus.nDefaultGeneratedBlockSizePercent <= 100.0);
        assert(consensus.GetDefaultGeneratedBlockSizeBytes() <= consensus.nDefaultConsensusBlockSize);

        // ScaleNet has no hard-coded anchor block because will be expected to
        // reorg back down to height 10,000 periodically.
        consensus.asertAnchorParams.reset();

        // ABLA config -- upgrade 10 adjustable block limit algorithm
        consensus.ablaConfig = abla::Config::MakeDefault(consensus.nDefaultConsensusBlockSize, /* fixedSize = */ false);
        // Ensure base abla state yields same limit as pre-activation.
        assert(abla::State(consensus.ablaConfig, 0).GetBlockSizeLimit() == consensus.nDefaultConsensusBlockSize);
        // Ensure ABLA is *not* "fixed size" for scalenet
        assert( ! consensus.ablaConfig.IsFixedSize());

        diskMagic[0] = 0xba;
        diskMagic[1] = 0xc2;
        diskMagic[2] = 0x2d;
        diskMagic[3] = 0xc4;
        netMagic[0] = 0xc3;
        netMagic[1] = 0xaf;
        netMagic[2] = 0xe1;
        netMagic[3] = 0xa2;
        nDefaultPort = 38333;
        nPruneAfterHeight = 10000;
        m_assumed_blockchain_size = 250;    // 153G
        m_assumed_chain_state_size = 50;    // 16G

        genesis = CreateGenesisBlock(1598282438, -1567304284, 0x1d00ffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();

        assert(consensus.hashGenesisBlock ==
            uint256S("00000000e6453dc2dfe1ffa19023f86002eb11dbb8e87d0291a4599f0430be52"));
        assert(genesis.hashMerkleRoot ==
            uint256S("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"));

        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
        vSeeds.emplace_back("scalenet-seed-bch.toom.im");
        // Loping.net
        vSeeds.emplace_back("seed.sbch.loping.net");

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<uint8_t>(1, 111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<uint8_t>(1, 196);
        base58Prefixes[SECRET_KEY] = std::vector<uint8_t>(1, 239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};
        cashaddrPrefix = "bchtest";
        vFixedSeeds.assign(std::begin(pnSeed6_scalenet), std::end(pnSeed6_scalenet));

        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        m_is_test_chain = true;

        checkpointData = {
            /* .mapCheckpoints = */ {
                {0, genesis.GetHash()},
                {45, BlockHash::fromHex("00000000d75a7c9098d02b321e9900b16ecbd552167e65683fe86e5ecf88b320")},
                // scalenet periodically reorgs to height 10,000
                {10000, BlockHash::fromHex("00000000b711dc753130e5083888d106f99b920b1b8a492eb5ac41d40e482905")},
            }};

        // Data as of block
        // 00000000a6791274f38bca28465236c4c02873037ec187d61c99b7eaa498033f
        // (height 36141)
        chainTxData = {1660124250 /* time */, 489847053 /* numTx */, 0.00001 /* tx/sec */};
    }
};

/**
 * Chipnet (activates the next upgrade earier than the other networks)
 */
class CChipNetParams : public CChainParams {
public:
    CChipNetParams() {
        strNetworkID = CBaseChainParams::CHIPNET;
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.BIP16Height = 1;
        // Note: Because BIP34Height is less than 17, clients will face an unusual corner case with BIP34 encoding.
        // The "correct" encoding for BIP34 blocks at height <= 16 uses OP_1 (0x81) through OP_16 (0x90) as a single
        // byte (i.e. "[shortest possible] encoded CScript format"), not a single byte with length followed by the
        // little-endian encoded version of the height as mentioned in BIP34. The BIP34 spec document itself ought to
        // be updated to reflect this.
        // https://github.com/bitcoin/bitcoin/pull/14633
        consensus.BIP34Height = 2;
        consensus.BIP34Hash = BlockHash::fromHex("00000000b0c65b1e03baace7d5c093db0d6aac224df01484985ffd5e86a1a20c");
        consensus.BIP65Height = 3;
        consensus.BIP66Height = 4;
        consensus.CSVHeight = 5;
        consensus.powLimit = uint256S("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        // two weeks
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60;
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;

        // The half life for the ASERT DAA. For every (nASERTHalfLife) seconds behind schedule the blockchain gets,
        // difficulty is cut in half. Doubled if blocks are ahead of schedule.
        // One hour
        consensus.nASERTHalfLife = 60 * 60;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = ChainParamsConstants::CHIPNET_MINIMUM_CHAIN_WORK;

        // By default assume that the signatures in ancestors of this block are
        // valid.
        consensus.defaultAssumeValid = ChainParamsConstants::CHIPNET_DEFAULT_ASSUME_VALID;

        // August 1, 2017 hard fork
        consensus.uahfHeight = 6;

        // November 13, 2017 hard fork
        consensus.daaHeight = 3000;

        // November 15, 2018 hard fork
        consensus.magneticAnomalyHeight = 4000;

        // November 15, 2019 protocol upgrade
        consensus.gravitonHeight = 5000;

        // May 15, 2020 12:00:00 UTC protocol upgrade
        // Note: We must set this to 0 here because "historical" sigop code has
        //       been removed from the BCHN codebase. All sigop checks really
        //       use the new post-May2020 sigcheck code unconditionally in this
        //       codebase, regardless of what this height is set to. So it's
        //       "as-if" the activation height really is 0 for all intents and
        //       purposes. If other node implementations wish to use this code
        //       as a reference, they need to be made aware of this quirk of
        //       BCHN, so we explicitly set the activation height to zero here.
        //       For example, BU or other nodes do keep both sigop and sigcheck
        //       implementations in their execution paths so they will need to
        //       use 0 here to be able to synch to this chain.
        //       See: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/issues/167
        consensus.phononHeight = 0;

        // Nov 15, 2020 12:00:00 UTC protocol upgrade
        consensus.axionActivationTime = 1605441600;

        // May 15, 2022 12:00:00 UTC protocol upgrade (upgrade8) height was 95464

        // November 15, 2022 12:00:00 UTC; protocol upgrade activates 6 months early
        consensus.upgrade9Height = 121956; // (one less than upgrade block)

        // November 15, 2023 12:00:00 UTC; protocol upgrade activates 6 months early
        consensus.upgrade10Height = 174519; // (one less than upgrade block)

        // November 15, 2024 12:00:00 UTC; protocol upgrade activates 6 months early
        consensus.upgrade11Height = 227228; // (one less than upgrade block)

        // November 15, 2025 12:00:00 UTC; protocol upgrade activates 6 months early
        consensus.upgrade12ActivationTime = 1763208000;

        // November 15, 2026 12:00:00 UTC; tentative protocol upgrade activates 6 months early
        consensus.upgrade2027ActivationTime = 1794744000;

        // Default limit for block size (in bytes) (chipnet is like testnet4 in that it is smaller at 2MB)
        consensus.nDefaultConsensusBlockSize = 2 * ONE_MEGABYTE;

        // Chain-specific default for mining block size, in percent of excessive block size (conf: -percentblockmaxsize)
        consensus.nDefaultGeneratedBlockSizePercent = 100.0; // 100% of 2MB = 2MB

        assert(consensus.nDefaultGeneratedBlockSizePercent >= 0.0
               && consensus.nDefaultGeneratedBlockSizePercent <= 100.0);
        assert(consensus.GetDefaultGeneratedBlockSizeBytes() <= consensus.nDefaultConsensusBlockSize);

        // Anchor params: Note that the block after this height *must* also be checkpointed below.
        consensus.asertAnchorParams = Consensus::Params::ASERTAnchor{
            16844,        // anchor block height
            0x1d00ffff,   // anchor block nBits
            1605451779,   // anchor block previous block timestamp
        };

        // ABLA config -- upgrade 10 adjustable block limit algorithm
        consensus.ablaConfig = abla::Config::MakeDefault(consensus.nDefaultConsensusBlockSize, /* fixedSize = */ false);
        // Ensure base abla state yields same limit as pre-activation.
        assert(abla::State(consensus.ablaConfig, 0).GetBlockSizeLimit() == consensus.nDefaultConsensusBlockSize);
        // Ensure ABLA is *not* "fixed size" for chipnet
        assert( ! consensus.ablaConfig.IsFixedSize());

        diskMagic[0] = 0xcd;
        diskMagic[1] = 0x22;
        diskMagic[2] = 0xa7;
        diskMagic[3] = 0x92;
        netMagic[0] = 0xe2;
        netMagic[1] = 0xb7;
        netMagic[2] = 0xda;
        netMagic[3] = 0xaf;
        nDefaultPort = 48333;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 1;      // 242M
        m_assumed_chain_state_size = 1;     // 15M

        genesis = CreateGenesisBlock(1597811185, 114152193, 0x1d00ffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock ==
            BlockHash::fromHex("000000001dd410c49a788668ce26751718cc797474d3152a5fc073dd44fd9f7b"));

        vFixedSeeds.clear();
        vSeeds.clear();
        // Jason Dreyzehner
        vSeeds.emplace_back("chipnet.bitjson.com");

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<uint8_t>(1, 111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<uint8_t>(1, 196);
        base58Prefixes[SECRET_KEY] = std::vector<uint8_t>(1, 239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};
        cashaddrPrefix = "bchtest";
        vFixedSeeds.assign(std::begin(pnSeed6_chipnet), std::end(pnSeed6_chipnet));

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        m_is_test_chain = true;

        checkpointData = {
            /* .mapCheckpoints = */ {
                {0, genesis.GetHash()},
                {5000, BlockHash::fromHex("000000009f092d074574a216faec682040a853c4f079c33dfd2c3ef1fd8108c4")},
                // Axion activation.
                {16845, BlockHash::fromHex("00000000fb325b8f34fe80c96a5f708a08699a68bbab82dba4474d86bd743077")},
                {38000, BlockHash::fromHex("000000000015197537e59f339e3b1bbf81a66f691bd3d7aa08560fc7bf5113fb")},

                // Upgrade 7 ("tachyon") era (actual activation block was in the past significantly before this)
                {54700, BlockHash::fromHex("00000000009af4379d87f17d0f172ee4769b48839a5a3a3e81d69da4322518b8")},
                {68117, BlockHash::fromHex("0000000000a2c2fc11a3b72adbd10a3f02a1f8745da55a85321523043639829a")},

                // Upgrade 8; May 15, 2022 (MTP time >= 1652616000), first upgrade block: 95465
                {95465, BlockHash::fromHex("00000000a77206a2265cabc47cc2c34706ba1c5e5a5743ac6681b83d43c91a01")},

                // Fork block for chipnet
                {115252, BlockHash::fromHex("00000000040ba9641ba98a37b2e5ceead38e4e2930ac8f145c8094f94c708727")},
                {115510, BlockHash::fromHex("000000006ad16ee5ee579bc3712b6f15cdf0a7f25a694e1979616794b73c5122")},

                // Upgrade9 - first block mined under upgrade9 rules for chipnet (Nov. 15, 2022)
                {121957, BlockHash::fromHex("0000000056087dee73fb66178ca70da89dfd0be098b1a63cf6fe93934cd04c78")},
                {122396, BlockHash::fromHex("000000000363cd56e49a46684cec1d99854c4aae662a6faee0df4c9a49dc8a33")},
                {128042, BlockHash::fromHex("0000000010e506eeb528dd8238947c6fcdf8d752ece66517eea778650600edae")},
                {148000, BlockHash::fromHex("000000009788ecce39b046caab3cf0f72e8c5409df23454679dbdcae2bd4dded")},

                // A block after Upgrade 10 activated (Nov. 15, 2023), first block after upgrade: 174520
                {178140, BlockHash::fromHex("000000003c37cc0372a5b9ccacca921786bbfc699722fc41e9fdbb1de4146ef1")},
                {206364, BlockHash::fromHex("00000000146a073b9d4e172adbee5252014a8b4d75c56cce36858311565ae251")},

                // A block after Upgrade 11 activated (Nov. 15, 2024), first block after upgrade: 227229
                {228000, BlockHash::fromHex("00000000144b00db5736b33bd572b3a3a52aa9b4c26ba59fc212aeb68a9b7a20")},
                {232000, BlockHash::fromHex("0000000017d92f88ed2c81885c57f999184860a042250510be06b3edd12e0dc5")},
                {255000, BlockHash::fromHex("000000008654e310c090d6846459500c3a6531044fa9339865865575375db624")},

                // A block after Upgrade 12 activated (Nov. 15, 2025), first block after upgrade: 279792
                {284827, BlockHash::fromHex("000000007af65a6e8853f858b3f2a8e7edabe41e6264410276705b324267d7d8")},
            }};

        // Data as of block
        // 00000000020bed0ca19e9b72ce4b2ac3def4beda35f825bb573c51a7783db3e8
        // (height 285268)
        chainTxData = {1766497373 /* time */, 971240 /* numTx */, 0.0087 /* tx/sec */};
    }
};

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = CBaseChainParams::REGTEST;
        consensus.nSubsidyHalvingInterval = 150;
        // always enforce P2SH BIP16 on regtest
        consensus.BIP16Height = 0;
        // BIP34 has not activated on regtest (far in the future so block v1 are
        // not rejected in tests)
        consensus.BIP34Height = 100000000;
        consensus.BIP34Hash = BlockHash();
        // BIP65 activated on regtest (Used in rpc activation tests)
        consensus.BIP65Height = 1351;
        // BIP66 activated on regtest (Used in rpc activation tests)
        consensus.BIP66Height = 1251;
        // CSV activated on regtest (Used in rpc activation tests)
        consensus.CSVHeight = 576;
        consensus.powLimit = uint256S(
            "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        // two weeks
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60;
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;

        // The half life for the ASERT DAA. For every (nASERTHalfLife) seconds behind schedule the blockchain gets,
        // difficulty is cut in half. Doubled if blocks are ahead of schedule.
        // Two days. Note regtest has no DAA checks, so this unused parameter is here merely for completeness.
        consensus.nASERTHalfLife = 2 * 24 * 60 * 60;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are
        // valid.
        consensus.defaultAssumeValid = BlockHash();

        // UAHF is always enabled on regtest.
        consensus.uahfHeight = 0;

        // November 13, 2017 hard fork is always on on regtest.
        consensus.daaHeight = 0;

        // November 15, 2018 hard fork is always on on regtest.
        consensus.magneticAnomalyHeight = 0;

        // November 15, 2019 protocol upgrade
        consensus.gravitonHeight = 0;

        // May 15, 2020 12:00:00 UTC protocol upgrade
        consensus.phononHeight = 0;

        // Nov 15, 2020 12:00:00 UTC protocol upgrade
        consensus.axionActivationTime = 1605441600;

        // May 15, 2023 12:00:00 UTC protocol upgrade
        consensus.upgrade9Height = 0;

        // May 15, 2024 12:00:00 UTC protocol upgrade
        consensus.upgrade10Height = 0;

        // May 15, 2025 12:00:00 UTC protocol upgrade
        consensus.upgrade11Height = 0;

        // May 15, 2026 12:00:00 UTC protocol upgrade
        consensus.upgrade12ActivationTime = 1778846400;

        // May 15, 2027 12:00:00 UTC tentative protocol upgrade
        consensus.upgrade2027ActivationTime = 1810382400;

        // Default limit for block size (in bytes)
        consensus.nDefaultConsensusBlockSize = DEFAULT_CONSENSUS_BLOCK_SIZE;

        // Chain-specific default for mining block size, in percent of excessive block size (conf: -percentblockmaxsize)
        consensus.nDefaultGeneratedBlockSizePercent = 50.0; // 50% of 32MB = 16MB

        assert(consensus.nDefaultGeneratedBlockSizePercent >= 0.0
               && consensus.nDefaultGeneratedBlockSizePercent <= 100.0);
        assert(consensus.GetDefaultGeneratedBlockSizeBytes() <= consensus.nDefaultConsensusBlockSize);

        // ABLA config -- upgrade 10 adjustable block limit algorithm
        consensus.ablaConfig = abla::Config::MakeDefault(consensus.nDefaultConsensusBlockSize, /* fixedSize = */ false);
        // Ensure base abla state yields same limit as pre-activation.
        assert(abla::State(consensus.ablaConfig, 0).GetBlockSizeLimit() == consensus.nDefaultConsensusBlockSize);
        // Ensure ABLA is *not* "fixed size" for regtest
        assert( ! consensus.ablaConfig.IsFixedSize());

        diskMagic[0] = 0xfa;
        diskMagic[1] = 0xbf;
        diskMagic[2] = 0xb5;
        diskMagic[3] = 0xda;
        netMagic[0] = 0xda;
        netMagic[1] = 0xb5;
        netMagic[2] = 0xbf;
        netMagic[3] = 0xfa;
        nDefaultPort = 18444;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        genesis = CreateGenesisBlock(1296688602, 2, 0x207fffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock ==
               uint256S("0x0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b"
                        "1a11466e2206"));
        assert(genesis.hashMerkleRoot ==
               uint256S("0x4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab212"
                        "7b7afdeda33b"));

        //! Regtest mode doesn't have any fixed seeds.
        vFixedSeeds.clear();
        //! Regtest mode doesn't have any DNS seeds.
        vSeeds.clear();

        fDefaultConsistencyChecks = true;
        fRequireStandard = true;
        m_is_test_chain = true;

        checkpointData = {
            /* .mapCheckpoints = */ {
                {0, BlockHash::fromHex("0f9188f13cb7b2c71f2a335e3a4fc328bf5beb4"
                                       "36012afca590b1a11466e2206")},
            }};

        chainTxData = ChainTxData{0, 0, 0};

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<uint8_t>(1, 111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<uint8_t>(1, 196);
        base58Prefixes[SECRET_KEY] = std::vector<uint8_t>(1, 239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};
        cashaddrPrefix = "bchreg";
    }
};


static std::unique_ptr<CChainParams> globalChainParams;

const CChainParams &Params() {
    assert(globalChainParams);
    return *globalChainParams;
}

std::unique_ptr<CChainParams> CreateChainParams(const std::string &chain) {
    if (chain == CBaseChainParams::MAIN) {
        return std::make_unique<CMainParams>();
    }

    if (chain == CBaseChainParams::TESTNET) {
        return std::make_unique<CTestNetParams>();
    }

    if (chain == CBaseChainParams::TESTNET4) {
        return std::make_unique<CTestNet4Params>();
    }

    if (chain == CBaseChainParams::REGTEST) {
        return std::make_unique<CRegTestParams>();
    }

    if (chain == CBaseChainParams::SCALENET) {
        return std::make_unique<CScaleNetParams>();
    }

    if (chain == CBaseChainParams::CHIPNET) {
        return std::make_unique<CChipNetParams>();
    }

    throw std::runtime_error(
        strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string &network) {
    SelectBaseParams(network);
    globalChainParams = CreateChainParams(network);
}

SeedSpec6::SeedSpec6(const char *pszHostPort)
{
    const CService service = LookupNumeric(pszHostPort, 0);
    if (!service.IsValid() || service.GetPort() == 0)
        throw std::invalid_argument(strprintf("Unable to parse numeric-IP:port pair: %s", pszHostPort));
    if (!service.IsRoutable())
        throw std::invalid_argument(strprintf("Not routable: %s", pszHostPort));
    *this = SeedSpec6(service);
}
