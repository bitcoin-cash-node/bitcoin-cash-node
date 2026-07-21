// Copyright (c) 2016-2018 The Bitcoin Core developers
// Copyright (c) 2021-present The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>
#include <bench/data.h>
#include <chainparams.h>
#include <coins.h>
#include <key.h>
#include <policy/policy.h>
#if defined(HAVE_CONSENSUS_LIB)
#include <script/bitcoinconsensus.h>
#endif
#include <script/interpreter.h>
#include <script/script.h>
#include <script/script_error.h>
#include <script/script_execution_context.h>
#include <script/standard.h>
#include <streams.h>
#include <tinyformat.h>
#include <util/defer.h>
#include <util/time.h>
#include <version.h>

#include <stdexcept>

static void VerifyNestedIfScript(benchmark::State &state) {
    StackT stack;
    CScript script;
    for (int i = 0; i < 100; ++i) {
        script << OP_1 << OP_IF;
    }
    for (int i = 0; i < 1000; ++i) {
        script << OP_1;
    }
    for (int i = 0; i < 100; ++i) {
        script << OP_ENDIF;
    }
    BENCHMARK_LOOP {
        auto stack_copy = stack;
        ScriptExecutionMetrics metrics = {};
        ScriptError error;
        bool ret = EvalScript(stack_copy, script, 0, BaseSignatureChecker(), metrics,  &error);
        assert(ret);
    }
}

static void VerifyBlockScripts(bool reallyCheckSigs,
                               const uint32_t flags,
                               const std::vector<uint8_t> &blockdata, const std::vector<uint8_t> &coinsdata,
                               benchmark::State &state) {
    const auto prevParams = ::Params().NetworkIDString();
    SelectParams(CBaseChainParams::MAIN);
    // clean-up after we are done
    Defer d([&prevParams] {
        SelectParams(prevParams);
    });

    CCoinsView coinsDummy;
    CCoinsViewCache coinsCache(&coinsDummy);
    {
        std::map<COutPoint, Coin> coins;
        VectorReader(SER_NETWORK, PROTOCOL_VERSION, coinsdata, 0) >> coins;
        for (const auto & [outpt, coin] : coins) {
            coinsCache.AddCoin(outpt, coin, false);
        }
    }

    const CBlock block = [&] {
        CBlock tmpblock;
        VectorReader(SER_NETWORK, PROTOCOL_VERSION, blockdata, 0) >> tmpblock;
        return tmpblock;
    }();

    // save precomputed txdata ahead of time in case we iterate more than once, and so
    // that we concentrate the benchmark itself on VerifyScript()
    std::vector<PrecomputedTransactionData> txdataVec;
    if (reallyCheckSigs) {
        txdataVec.reserve(block.vtx.size());
    }

    const auto &coins = coinsCache; // get a const reference to be safe
    std::vector<const Coin *> coinsVec; // coins being spent laid out in block input order
    std::vector<std::vector<ScriptExecutionContext>> contexts; // script execution contexts for each tx
    contexts.reserve(block.vtx.size());
    for (const auto &tx : block.vtx) {
        if (tx->IsCoinBase()) continue;
        contexts.push_back(ScriptExecutionContext::createForAllInputs(*tx, coinsCache));
        for (auto &inp : tx->vin) {
            auto &coin = coins.AccessCoin(inp.prevout);
            assert(!coin.IsSpent());
            coinsVec.push_back(&coin);
        }
        if (reallyCheckSigs && !contexts.back().empty()) {
            txdataVec.emplace_back(contexts.back().at(0));
        }
    }

    struct FakeSignaureChecker final : ContextOptSignatureChecker {
        bool VerifySignature(const ByteView &, const CPubKey &, const uint256 &) const override { return true; }
        bool CheckSig(const ByteView &, const std::vector<uint8_t> &, const ByteView &, uint32_t,
                      size_t *) const override { return true; }
        bool CheckLockTime(const CScriptNum &) const override { return true; }
        bool CheckSequence(const CScriptNum &) const override { return true; }
        using ContextOptSignatureChecker::ContextOptSignatureChecker;
    };

    BENCHMARK_LOOP {
        size_t okct = 0;
        size_t txdataVecIdx = 0, coinsVecIdx = 0;
        for (const auto &tx : block.vtx) {
            if (tx->IsCoinBase()) continue;
            unsigned inputNum = 0;
            for (auto &inp : tx->vin) {
                assert(coinsVecIdx < coinsVec.size());
                auto &coin = *coinsVec[coinsVecIdx];
                bool ok{};
                const auto &context = contexts[txdataVecIdx][inputNum];
                ScriptError serror;
                if (reallyCheckSigs) {
                    assert(txdataVecIdx < txdataVec.size());
                    const auto &txdata = txdataVec[txdataVecIdx];
                    const TransactionSignatureChecker checker(context, txdata);
                    ok = VerifyScript(inp.scriptSig, coin.GetTxOut().scriptPubKey, flags, checker, &serror);
                } else {
                    ok = VerifyScript(inp.scriptSig, coin.GetTxOut().scriptPubKey, flags, FakeSignaureChecker(context),
                                      &serror);
                }
                if (!ok) {
                    throw std::runtime_error(
                        strprintf("Not ok: %s in tx: %s error: %s (okct: %d)",
                                  inp.prevout.ToString(), tx->GetId().ToString(), ScriptErrorString(serror), okct)
                    );
                }
                ++okct;
                ++inputNum;
                ++coinsVecIdx;
            }
            ++txdataVecIdx;
        }
    }
}

static const uint32_t flags_413567 = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY;
static const uint32_t flags_556034 = flags_413567 | SCRIPT_VERIFY_CHECKSEQUENCEVERIFY | SCRIPT_VERIFY_STRICTENC
                                     | SCRIPT_ENABLE_SIGHASH_FORKID | SCRIPT_VERIFY_LOW_S | SCRIPT_VERIFY_NULLFAIL;

// pure bench of just the script VM (sigchecks are trivially always skipped)
static void VerifyScripts_Block413567(benchmark::State &state) {
    VerifyBlockScripts(false, flags_413567, benchmark::data::Get_block413567(), benchmark::data::Get_coins_spent_413567(), state);
}

// pure bench of just the script VM (sigchecks are trivially always skipped)
static void VerifyScripts_Block556034(benchmark::State &state) {
    VerifyBlockScripts(false, flags_556034, benchmark::data::Get_block556034(), benchmark::data::Get_coins_spent_556034(), state);
}

// bench of the script VM *with* signature checking. The cost is usually dominated by libsecp256k1 here
static void VerifyScripts_SigsChecks_Block413567(benchmark::State &state) {
    VerifyBlockScripts(true, flags_413567, benchmark::data::Get_block413567(), benchmark::data::Get_coins_spent_413567(), state);
}

// bench of the script VM *with* signature checking. The cost is usually dominated by libsecp256k1 here
// Block 556034 is a very big block (this is very very slow).
static void VerifyScripts_SigsChecks_Block556034(benchmark::State &state) {
    VerifyBlockScripts(true, flags_556034, benchmark::data::Get_block556034(), benchmark::data::Get_coins_spent_556034(), state);
}

static void VerifyLoopScript(benchmark::State &state, int which, bool tightLoop) {
    constexpr uint32_t flags = STANDARD_SCRIPT_VERIFY_FLAGS | SCRIPT_ENABLE_P2SH_32 | SCRIPT_ENABLE_TOKENS
                               | SCRIPT_ENABLE_MAY2025 | SCRIPT_VM_LIMITS_STANDARD | SCRIPT_ENABLE_MAY2026;
    constexpr size_t finalScriptSize = 1000; // modify this to test various sized busy-loop scripts.
    static_assert(finalScriptSize >= 20);
    CScript script;
    switch (which) {
        case 0:
            // simple OP_NOP best case?
            script << OP_BEGIN;
            while (script.size() < finalScriptSize - 2) {
                script << OP_NOP;
                if (tightLoop) break; // use a tiny loop body with tightLoop -> rest of input will be padded with OP_NOP
            }
            script << OP_0 << OP_UNTIL;
            break;
        case 1:
            // Smallish number, keep incrementing using OP_1 OP_ADD
            script << OP_1 << OP_BEGIN;
            while (script.size() < finalScriptSize - 2) {
                script << OP_1 << OP_ADD;
                if (tightLoop) break; // use a tiny loop body with tightLoop -> rest of input will be padded with OP_NOP
            }
            script << OP_0 << OP_UNTIL;
            break;
        case 2:
            // Smallish number, keep incrementing using OP_1ADD
            script << OP_1 << OP_BEGIN;
            while (script.size() < finalScriptSize - 2) {
                script << OP_1ADD;
                if (tightLoop) break; // use a tiny loop body with tightLoop -> rest of input will be padded with OP_NOP
            }
            script << OP_0 << OP_UNTIL;
            break;
        case 3:
            // Start with smallish number, keep multiplying by 2
            script << OP_1 << OP_BEGIN;
            while (script.size() < finalScriptSize - 2) {
                script << OP_2 << OP_MUL;
                if (tightLoop) break; // use a tiny loop body with tightLoop -> rest of input will be padded with OP_NOP
            }
            script << OP_0 << OP_UNTIL;
            break;
        case 4: {
            // BigInts keep adding together
            auto bigNum = ScriptBigInt::fromIntUnchecked(31466179_bi);
            script << bigNum << OP_BEGIN;
            while (script.size() < finalScriptSize - 2) {
                script << bigNum << OP_ADD;
                if (tightLoop) break; // use a tiny loop body with tightLoop -> rest of input will be padded with OP_NOP
            }
            script << OP_0 << OP_UNTIL;
            break;
        }
        case 5: {
            // BigInts increment around the boundary between smallint -> bigint transition
            auto bigNum = ScriptBigInt::fromIntUnchecked(9223372036854775000_bi);
            script << bigNum << OP_BEGIN;
            while (script.size() < finalScriptSize - 2) {
                script << OP_1ADD;
                if (tightLoop) break; // use a tiny loop body with tightLoop -> rest of input will be padded with OP_NOP
            }
            script << OP_0 << OP_UNTIL;
            break;
        }
        case 6: {
            // OP_INVOKE an empty function in a loop
            script << std::vector<uint8_t>{} /* <- empty function body */ << OP_2 /* <- function index 2 */ << OP_DEFINE
                   << OP_BEGIN;
            while (script.size() < finalScriptSize - 2) {
                script << OP_2 << OP_INVOKE;
                if (tightLoop) break; // use a tiny loop body with tightLoop -> rest of input will be padded with OP_NOP
            }
            script << OP_0 << OP_UNTIL;
            break;
        }
        case 7: {
            // OP_INVOKE a trivial OP_1ADD function in a loop
            script << std::vector<uint8_t>(1, OP_1ADD) /* */ << OP_2 /* <- function index 2 */ << OP_DEFINE
                   << OP_1 << OP_BEGIN;
            while (script.size() < finalScriptSize - 2) {
                script << OP_2 << OP_INVOKE;
                if (tightLoop) break; // use a tiny loop body with tightLoop -> rest of input will be padded with OP_NOP
            }
            script << OP_0 << OP_UNTIL;
            break;
        }
        case 8: {
            // OP_INVOKE a huuuge OP_1ADD * finalScriptSize - 11 function in a tight loop
            script << std::vector<uint8_t>(finalScriptSize - 11, OP_1ADD) << OP_2 /* <- function index 2 */ << OP_DEFINE
                   << OP_1 /* <- value we keep incrementing */
                   << OP_BEGIN
                   << OP_2 << OP_INVOKE
                   << OP_0 << OP_UNTIL;
            break;
        }
        default:
            assert(!"Unknown case in switch");
            break;
    }
    // pad end with OP_NOP
    if (script.size() < finalScriptSize) {
        script.resize(finalScriptSize, static_cast<uint8_t>(OP_NOP));
    }
    size_t nBytesEvaluated = 0;
    ScriptExecutionMetrics metrics = {};
    ScriptError error{};
    StackT stack;
    Tic t0;
    BENCHMARK_LOOP {
        stack = {};
        error = {};
        metrics = {};
        metrics.SetScriptLimits(flags, script.size());
        bool res = EvalScript(stack, script, flags, BaseSignatureChecker(), metrics,  &error);
        nBytesEvaluated += script.size();
        // these tests always exhausts the VM op cost limit, throw if that is not the case
        if (res || error != ScriptError::OP_COST) {
            throw std::runtime_error(
                strprintf("Benchmark \"%s\" did not produce the expected error result: res=%d, error=%s",
                          state.GetName(), int(res), ScriptErrorString(error)));
        }
    }
    t0.fin();
    const auto stackBottom = !stack.empty() ? stack.front() : StackT::value_type{};
    struct Stat {
        int64_t opCost{};
        int64_t opCostLimit{};
        size_t scriptSize{};
        std::string stackBottom;
        double bogoCostPerByte;
    };
    Stat stat{
        .opCost = metrics.GetCompositeOpCost(flags),
        .opCostLimit = metrics.GetScriptLimits()->GetOpCostLimit(),
        .scriptSize = script.size(),
        .stackBottom = ScriptBigInt(stackBottom.vec(), false, ScriptBigInt::MAXIMUM_ELEMENT_SIZE_BIG_INT).getBigInt().ToString(),
        .bogoCostPerByte = t0.nsec() / double(nBytesEvaluated),
    };
    using StatVec = std::vector<Stat>;
    StatVec *psvec;
    if (!(psvec = std::any_cast<StatVec>(&state.anyData))) {
        psvec = &state.anyData.emplace<StatVec>();
    }
    psvec->push_back(std::move(stat));

    if (!state.completionFunction) {
        state.completionFunction = [](const benchmark::State &st, benchmark::Printer &p) {
            const StatVec &svec = std::any_cast<StatVec>(st.anyData); // may throw
            assert(!svec.empty());
            Stat avg = svec[0];
            for (size_t i = 1; i < svec.size(); ++i) {
                const auto &s = svec[i];
                // everything should be the same between evaluations except for the bogoCostPerByte field, which we average
                assert(avg.opCost == s.opCost);
                assert(avg.opCostLimit == s.opCostLimit);
                assert(avg.scriptSize == s.scriptSize);
                assert(avg.stackBottom == s.stackBottom);
                avg.bogoCostPerByte += s.bogoCostPerByte;
            }
            avg.bogoCostPerByte /= svec.size(); // take average
            benchmark::Printer::ExtraData data = {{
                {"Name", st.GetName()},
                {"BogoCostPerByte", strprintf("%1.3f", avg.bogoCostPerByte)},
                {"ScriptSize", strprintf("%d", avg.scriptSize)},
                {"OpCost", strprintf("%d", avg.opCost)},
                {"OpCostLimit", strprintf("%d", avg.opCostLimit)},
                {"StackBottom (as number)", avg.stackBottom},
            }};

            p.appendExtraDataForCategory("verify_script (loops)", std::move(data));
        };
    }
}

static void VerifyBigLoop_NOP(benchmark::State &state) { VerifyLoopScript(state, 0, false); }
static void VerifyBigLoop_Add_1(benchmark::State &state) { VerifyLoopScript(state, 1, false); }
static void VerifyBigLoop_1ADD(benchmark::State &state) { VerifyLoopScript(state, 2, false); }
static void VerifyBigLoop_Mul_2(benchmark::State &state) { VerifyLoopScript(state, 3, false); }
static void VerifyBigLoop_BigInt_Add(benchmark::State &state) { VerifyLoopScript(state, 4, false); }
static void VerifyBigLoop_BigInt_1ADD(benchmark::State &state) { VerifyLoopScript(state, 5, false); }
static void VerifyBigLoop_Invoke_Spam(benchmark::State &state) { VerifyLoopScript(state, 6, false); }
static void VerifyBigLoop_Invoke_1ADD(benchmark::State &state) { VerifyLoopScript(state, 7, false); }

static void VerifyTightLoop_NOP(benchmark::State &state) { VerifyLoopScript(state, 0, true); }
static void VerifyTightLoop_Add_1(benchmark::State &state) { VerifyLoopScript(state, 1, true); }
static void VerifyTightLoop_1ADD(benchmark::State &state) { VerifyLoopScript(state, 2, true); }
static void VerifyTightLoop_Mul_2(benchmark::State &state) { VerifyLoopScript(state, 3, true); }
static void VerifyTightLoop_BigInt_Add(benchmark::State &state) { VerifyLoopScript(state, 4, true); }
static void VerifyTightLoop_BigInt_1ADD(benchmark::State &state) { VerifyLoopScript(state, 5, true); }
static void VerifyTightLoop_Invoke_Spam(benchmark::State &state) { VerifyLoopScript(state, 6, true); }
static void VerifyTightLoop_Invoke_1ADD(benchmark::State &state) { VerifyLoopScript(state, 7, true); }
static void VerifyTightLoop_Invoke_BigFunc(benchmark::State &state) { VerifyLoopScript(state, 8, false); }

BENCHMARK(VerifyBigLoop_NOP, 100);
BENCHMARK(VerifyBigLoop_Add_1, 100);
BENCHMARK(VerifyBigLoop_1ADD, 100);
BENCHMARK(VerifyBigLoop_Mul_2, 100);
BENCHMARK(VerifyBigLoop_BigInt_Add, 100);
BENCHMARK(VerifyBigLoop_BigInt_1ADD, 100);
BENCHMARK(VerifyBigLoop_Invoke_Spam, 100);
BENCHMARK(VerifyBigLoop_Invoke_1ADD, 100)

BENCHMARK(VerifyTightLoop_NOP, 100);
BENCHMARK(VerifyTightLoop_Add_1, 100);
BENCHMARK(VerifyTightLoop_1ADD, 100);
BENCHMARK(VerifyTightLoop_Mul_2, 100);
BENCHMARK(VerifyTightLoop_BigInt_Add, 100);
BENCHMARK(VerifyTightLoop_BigInt_1ADD, 100);
BENCHMARK(VerifyTightLoop_Invoke_Spam, 100);
BENCHMARK(VerifyTightLoop_Invoke_1ADD, 100);
BENCHMARK(VerifyTightLoop_Invoke_BigFunc, 100);

BENCHMARK(VerifyNestedIfScript, 100);

// These benchmarks just test the script VM itself, without doing real sigchecks
BENCHMARK(VerifyScripts_Block413567, 60);
BENCHMARK(VerifyScripts_Block556034, 3);

// These benchmarks do a full end-to-end test of the VM, including sigchecks.
// Since sigchecks dominate the cost here, this is slow, and as a result
// may not reveal much about the efficiency of the script interpreter itself.
// Consequently, if concerned with optimizing the script interpreter, it may
// be better to prefer the above two benchmarcks over the below two for
// measuring the script interpreter's own efficiency.
BENCHMARK(VerifyScripts_SigsChecks_Block413567, 2);
BENCHMARK(VerifyScripts_SigsChecks_Block556034, 1);
