// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017-present The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/interpreter.h>

#include <crypto/ripemd160.h>
#include <crypto/sha1.h>
#include <crypto/sha256.h>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <script/bitfield.h>
#include <script/script.h>
#include <script/script_flags.h>
#include <script/sigencoding.h>
#include <tinyformat.h>
#include <uint256.h>
#include <util/bitmanip.h>
#include <util/hwaccel.h>

#include <limits>
#include <list>
#include <map>
#include <span>
#include <utility>

bool CastToBool(const StackT::value_type &vch) {
    // Note: 'false' can be all zero bytes or "negative zero", which is, byte-wise, 0 or more 0x0's followed by a 0x80
    // byte, e.g.: {0x0, 0x0, ..., 0x0, 0x80}

    const size_t sz = vch.size();
    if (sz == 0) {
        // Empty vector is false
        return false;
    } else if (const auto last = vch.back(); last != 0x00u && last != 0x80u) {
        // If the last byte is not zero and is not negative 0, then this byte blob must be truthy (fast path)
        return true;
    }
    // At this point we know that the vector is: (1) not empty and (2) the last byte is either 0x00 or it's 0x80

    if (sz == 1) {
        // Since the only byte is one of: 0x00 or 0x80 ("negative 0"), we know it's false
        return false;
    }

    // At this point we know that: sz > 1, and last byte is either 0x00 or 0x80, proceed with scanning all bytes except
    // the last one. If all remaining bytes are zero, it's false, otherwise it's true.
    return not hwaccel::IsAllZeros(std::span{vch}.first(sz - 1));
}

/**
 * Script is a stack machine (like Forth) that evaluates a predicate
 * returning a bool indicating valid or not.
 */
#define stacktop(i) (stack.at(stack.size() + (i)))
#define altstacktop(i) (altstack.at(altstack.size() + (i)))
static inline void popstack(std::vector<valtype> &stack) {
    if (stack.empty()) {
        throw std::runtime_error("popstack(): stack empty");
    }
    stack.pop_back();
}

FindAndDeleteResult FindAndDelete(const ByteView &script, const CScript &b) {
    FindAndDeleteResult res;
    if (b.empty()) {
        return res;
    }

    CScript &result = res.replacementScript;
    const uint8_t *pc = script.data(), *pc2 = script.data(), * const end = script.data() + script.size();
    opcodetype opcode;
    do {
        result.insert(result.end(), pc2, pc);
        while (static_cast<size_t>(end - pc) >= b.size() && std::equal(b.begin(), b.end(), pc)) {
            pc = pc + b.size();
            ++res.nFound;
        }
        pc2 = pc;
    } while (GetScriptOp(pc, end, opcode, nullptr));

    if (res.nFound > 0u) {
        result.insert(result.end(), pc2, end);
    } else {
        result.clear();
    }

    return res;
}

struct CleanupScriptCodeResult {
    std::optional<CScript> optScriptCode;
    ByteView scriptCode; ///< points to either this->optScriptCode or an external buffer

    CleanupScriptCodeResult(const ByteView &externalBuffer) : scriptCode{externalBuffer} {}

    CleanupScriptCodeResult(FindAndDeleteResult &&r, CleanupScriptCodeResult &&res) {
        if (r.nFound) {
            scriptCode = optScriptCode.emplace(std::move(r.replacementScript));
        } else {
            *this = std::move(res);
        }
    }

    CleanupScriptCodeResult(const CleanupScriptCodeResult &o) { *this = o; }
    CleanupScriptCodeResult(CleanupScriptCodeResult &&o) { *this = std::move(o); }

    CleanupScriptCodeResult &operator=(const CleanupScriptCodeResult &o) {
        if (this != &o) {
            optScriptCode = o.optScriptCode;
            setScriptCode(o.scriptCode);
        }
        return *this;
    }
    CleanupScriptCodeResult &operator=(CleanupScriptCodeResult &&o) {
        if (this != &o) {
            optScriptCode = std::move(o.optScriptCode);
            setScriptCode(o.scriptCode);
        }
        return *this;
    }
private:
    void setScriptCode(const ByteView &externalBuffer) {
        if (optScriptCode) scriptCode = *optScriptCode;
        else scriptCode = externalBuffer;
    }
};

[[nodiscard]]
static CleanupScriptCodeResult CleanupScriptCode(CleanupScriptCodeResult &&res,
                                                 const std::vector<uint8_t> &vchSig,
                                                 uint32_t flags) {
    // Drop the signature in scripts when SIGHASH_FORKID is not used.
    if (!(flags & SCRIPT_ENABLE_SIGHASH_FORKID) || !GetHashType(vchSig).hasFork()) {
        return {FindAndDelete(res.scriptCode, CScript(vchSig)), std::move(res)};
    }
    return std::move(res);
}

static bool IsOpcodeDisabled(opcodetype opcode, uint32_t flags) {
    switch (opcode) {
        case OP_INVERT:
        case OP_LSHIFTNUM:
        case OP_RSHIFTNUM:
        case OP_LSHIFTBIN:
        case OP_RSHIFTBIN:
            // Disabled before May 2026
            return (flags & SCRIPT_ENABLE_MAY2026) == 0;
        default:
            break;
    }
    return false;
}

namespace {
/**
 * A data type to abstract out the condition stack during script execution.
 *
 * Conceptually it acts like a vector of booleans, one for each level of nested
 * IF/THEN/ELSE, indicating whether we're in the active or inactive branch of
 * each.
 *
 * The elements on the stack cannot be observed individually; we only need to
 * expose whether the stack is empty and whether or not any false values are
 * present at all. To implement OP_ELSE, a toggle_top modifier is added, which
 * flips the last value without returning it.
 *
 * This uses an optimized implementation that does not materialize the
 * actual stack. Instead, it just stores the size of the would-be stack,
 * and the position of the first false value in it.
 */
class ConditionStack {
private:
    //! A constant for m_first_false_pos to indicate there are no falses.
    static constexpr uint32_t NO_FALSE = std::numeric_limits<uint32_t>::max();

    //! The size of the implied stack.
    uint32_t m_stack_size = 0;
    //! The position of the first false value on the implied stack, or NO_FALSE
    //! if all true.
    uint32_t m_first_false_pos = NO_FALSE;

public:
    [[nodiscard]] constexpr bool empty() const noexcept { return m_stack_size == 0; }
    [[nodiscard]] constexpr bool all_true() const noexcept { return m_first_false_pos == NO_FALSE; }
    constexpr void push_back(bool f) noexcept {
        if (m_first_false_pos == NO_FALSE && !f) {
            // The stack consists of all true values, and a false is added.
            // The first false value will appear at the current size.
            m_first_false_pos = m_stack_size;
        }
        ++m_stack_size;
    }
    constexpr void pop_back() noexcept {
        --m_stack_size;
        if (m_first_false_pos == m_stack_size) {
            // When popping off the first false value, everything becomes true.
            m_first_false_pos = NO_FALSE;
        }
    }
    constexpr void toggle_top() noexcept {
        if (m_first_false_pos == NO_FALSE) {
            // The current stack is all true values; the first false will be the
            // top.
            m_first_false_pos = m_stack_size - 1;
        } else if (m_first_false_pos == m_stack_size - 1) {
            // The top is the first false value; toggling it will make
            // everything true.
            m_first_false_pos = NO_FALSE;
        } else {
            // There is a false value, but not on top. No action is needed as
            // toggling anything but the first false value is unobservable.
        }
    }

    constexpr uint32_t size() const noexcept { return m_stack_size; }
};

/**
 *  Encapsulates an evaluation stack frame. Needed to support OP_INVOKE. Each stack frame has its own conditional
 *  stack, control stack, script, program counter, etc. All stack frames share the same data `stack`, `altstack`, and
 *  function table, however.
 */
struct EvalFrame {
    const size_t cumulativeCtr = 0; ///< Cumulative vfExec.size() + loopDepthCtr for all control frames BELOW this one
    const ByteView script;          ///< The script we are evaluating (as a view type)
    ConditionStack vfExec;          ///< The O(1) conditional stack for this control frame
    const uint8_t *pc;              ///< Initially equal to script.data(), but incremented as we execute the script
    const uint8_t *pbegincodehash;  ///< Initially equal to `pc`, but updated if we encounter OP_CODESEPARATOR opcodes

    /**
     *  Control-flow stack. nullptr entries indicate most-recent control block we are inside of is an OP_IF;
     *  non-nullptr indicates we are inside a loop (OP_BEGIN) and the value is a `pc` to jump to for looping (points
     *  into `script` above).
     */
    std::vector<const uint8_t *> controlStack;
    /**
     * Indicates the nesting level of how deep we are inside of loops (OP_BEGIN/OP_UNTIL constructs).
     * Gets incremented for every OP_BEGIN pushed, decremented for each OP_UNTIL popped.
     */
    size_t loopDepthCtr = 0;

    EvalFrame(size_t cumCtr, const ByteView &script_)
        : cumulativeCtr(cumCtr), script{script_}, pc{script.data()}, pbegincodehash{pc} {}

    /// Returns non-nullptr if the innermost control flow structure is a loop (OP_BEGIN), nullptr otherwise.
    [[nodiscard]] const uint8_t *controlStackTop() const {
        return controlStack.empty() ? nullptr : controlStack.back();
    }

    void loopBeginPushPC() {
        controlStack.push_back(pc);
        ++loopDepthCtr;
    }
    void loopEndPopPC() {
        if (controlStackTop()) {
            --loopDepthCtr;
            controlStack.pop_back();
        }
    }

    void processIf(bool val) {
        vfExec.push_back(val);
        controlStack.push_back(nullptr); // Indicate that the innermost control block is OP_IF/OP_NOTIF
    }
    [[nodiscard]] bool processEndIf(ScriptError *serror) {
        if (vfExec.empty()) {
            // No matching OP_IF/OP_NOTIF
            return set_error(serror, ScriptError::UNBALANCED_CONDITIONAL);
        }
        if (controlStackTop()) {
            // Inner-most control block is OP_BEGIN, so OP_ENDIF violates proper control structure
            return set_error(serror, ScriptError::UNBALANCED_CONTROL_FLOW);
        }
        if (!controlStack.empty()) {
            // Pop the nullptr that is at the top of the controlStack (nullptr means we are in an IF-like block).
            controlStack.pop_back();
        }
        vfExec.pop_back(); // tell the condition stack we popped out of this IF block
        return true;
    }
    [[nodiscard]] bool processElse(ScriptError *serror) {
        if (vfExec.empty()) {
            // No matching OP_IF/OP_NOTIF
            return set_error(serror, ScriptError::UNBALANCED_CONDITIONAL);
        }
        if (controlStackTop()) {
            // Inner-most control block is OP_BEGIN, so OP_ELSE violates proper control structure
            return set_error(serror, ScriptError::UNBALANCED_CONTROL_FLOW);
        }
        vfExec.toggle_top(); // Tell the condition stack to invert its exec flag (to take or ignore the upcoming branch)
        return true;
    }
};

/**
 *  The evaluation stack frames, used to support OP_INVOKE. The initial frame is the base scriptSig, scriptPubKey, or
 *  redeemScript that was passed-in to EvalScript(). Subsequent frames are any OP_DEFINE'd sub-scripts we may have
 *  encountered, which are pushed to the top of this stack as OP_INVOKE op-codes are executed.
 *
 *  After pushing a new sub-script to this stack, the current script is paused, with execution proceeding to the first
 *  instruction of the newly pushed script. When the stack's top-most script ends, execution resumes where it left off
 *  on the previous stack frame, and so on, until the EvalStack is empty after all scripts have completed successfully.
 *
 *  If any script or sub-script on the EvalStack fails (such as due to normal processing e.g. OP_VERIFY failure, or if
 *  a script error occurs), the entire evaluation fails.
 */
class EvalStack {
    std::list<EvalFrame> evalFrames; ///< NB: We use a list here to get stable references to contained objects

public:
    explicit EvalStack(const CScript *outermostScript) {
        assert(outermostScript != nullptr);
        pushFrame(*outermostScript);
    }

    void pushFrame(const ByteView &script) {
        if (script.size() > MAX_SCRIPT_SIZE) {
            // Size check consensus rule (enforced here on push for belt-and-suspenders)
            throw ScriptEvaluationError(ScriptError::SCRIPT_SIZE);
        }
        evalFrames.emplace_back(depth(true), script);
    }

    void popFrame() {
        if (evalFrames.empty()) throw std::out_of_range("popFrame: Evaluation stack is empty");
        evalFrames.pop_back();
    }

    // Returns the depth of this stack. Note that if the stack has only 1 frame with an empty vfExec, 0 is returned.
    size_t depth(bool omitNumFrames = false) const {
        if (evalFrames.empty()) return 0;
        auto &top = evalFrames.back();
        return top.cumulativeCtr   // Cumulative sum of nested IFs + loops for all frames below current
               + top.vfExec.size() // Count of currently open OP_IF/OP_NOTIF blocks for the current frame
               + top.loopDepthCtr  // Count of currently open OP_BEGIN loops for the current frame
               + (omitNumFrames ? 0 : evalFrames.size() - 1u); // OP_INVOKE nesting: number of parent frames
    }

    EvalFrame &top() {
        if (evalFrames.empty()) throw std::out_of_range("top: Evaluation stack is empty");
        return evalFrames.back();
    }

    bool empty() const {  return evalFrames.empty(); }
};

template<bool UsesBigInt>
bool EvalScriptImpl(std::vector<valtype> &stack, const CScript &initialScript, uint32_t flags,
                    const BaseSignatureChecker &checker, ScriptExecutionMetrics &metrics, ScriptError *serror) {
    // UsesBigInt template arg must match flags
    assert(UsesBigInt == bool(flags & SCRIPT_ENABLE_MAY2025));
    using ScriptNumType = std::conditional_t<UsesBigInt, FastBigNum, CScriptNum>;

    static auto const bnZero = ScriptNumType::fromIntUnchecked(0);
    static const valtype vchFalse(0);
    static const valtype vchTrue(1, 1);

    if (initialScript.size() > MAX_SCRIPT_SIZE) {
        return set_error(serror, ScriptError::SCRIPT_SIZE);
    }

    // Function table (OP_DEFINE/OP_INVOKE support)
    using FunctionTable = std::map<valtype, const valtype>;
    FunctionTable functionTable;

    std::vector<valtype> altstack;
    set_error(serror, ScriptError::UNKNOWN);
    int nOpCount = 0; /* Only used iff chipVmLimitsEnabled == false */
    bool const fRequireMinimal = (flags & SCRIPT_VERIFY_MINIMALDATA) != 0;
    bool const nativeTokens = (flags & SCRIPT_ENABLE_TOKENS) != 0;
    const ScriptExecutionContext * const context = checker.GetContext();

    size_t const maxIntegerSizeLegacy = CScriptNum::MAXIMUM_ELEMENT_SIZE_64_BIT;
    size_t const maxIntegerSize = UsesBigInt ? ScriptBigInt::MAXIMUM_ELEMENT_SIZE_BIG_INT : maxIntegerSizeLegacy;

    ScriptError const invalidNumberRangeError = UsesBigInt ? ScriptError::INVALID_NUMBER_RANGE_BIG_INT
                                                           : ScriptError::INVALID_NUMBER_RANGE_64_BIT;

    bool const chipVmLimitsEnabled = (flags & SCRIPT_ENABLE_MAY2025) != 0;
    size_t const maxScriptElementSize = chipVmLimitsEnabled ? may2025::MAX_SCRIPT_ELEMENT_SIZE
                                                            : MAX_SCRIPT_ELEMENT_SIZE_LEGACY;

    if (chipVmLimitsEnabled && !metrics.HasValidScriptLimits() && context) {
        // Calculate metrics "scriptLimits", if not already passed-in, and if we have a `context` object
        // from which to get the scriptSig size.
        metrics.SetScriptLimits(flags, context->scriptSig().size());
    }

    bool const may2026Enabled = (flags & SCRIPT_ENABLE_MAY2026) != 0;

    try {
        // Initial frame for the top-level script (zero-copy view)
        EvalStack evalStack(&initialScript);

        do {
            EvalFrame &curFrame = evalStack.top();
            const uint8_t *&pc = curFrame.pc;
            const uint8_t *&pbegincodehash = curFrame.pbegincodehash;
            const uint8_t *const pend = curFrame.script.data() + curFrame.script.size();
            bool newEvalFrameWasPushed = false;

            while (pc < pend && !newEvalFrameWasPushed) {
                bool fExec = curFrame.vfExec.all_true();

                //
                // Read instruction
                //
                opcodetype opcode;
                valtype vchPushValue;
                if (!GetScriptOp(pc, pend, opcode, &vchPushValue)) {
                    return set_error(serror, ScriptError::BAD_OPCODE);
                }
                if (vchPushValue.size() > maxScriptElementSize) {
                    return set_error(serror, ScriptError::PUSH_SIZE);
                }

                // Op-code cost accounting
                // May 2025 upgrade: Cost of 100 per instruction executed; this is measured unconditionally but the limit
                // for this metric is only enforced after the May 2025 upgrade.
                metrics.TallyOp(may2025::OPCODE_COST);
                // Pre May 2025 upgrade: increment the `nOpCount` variable
                if ( ! chipVmLimitsEnabled) {
                    // Note how OP_RESERVED does not count towards the opcode limit.
                    if (opcode > OP_16 && ++nOpCount > MAX_OPS_PER_SCRIPT_LEGACY) {
                        return set_error(serror, ScriptError::OP_COUNT);
                    }
                }

                // Some opcodes are disabled.
                if (IsOpcodeDisabled(opcode, flags)) {
                    return set_error(serror, ScriptError::DISABLED_OPCODE);
                }

                if (fExec && 0 <= opcode && opcode <= OP_PUSHDATA4) {
                    if (fRequireMinimal &&
                        !CheckMinimalPush(vchPushValue, opcode)) {
                        return set_error(serror, ScriptError::MINIMALDATA);
                    }
                    stack.push_back(std::move(vchPushValue));
                    metrics.TallyPushOp(stack.back().size());
                } else if (fExec || (OP_IF <= opcode && opcode <= OP_ENDIF)) {
                    switch (opcode) {
                        //
                        // Push value
                        //
                        case OP_1NEGATE:
                        case OP_1:
                        case OP_2:
                        case OP_3:
                        case OP_4:
                        case OP_5:
                        case OP_6:
                        case OP_7:
                        case OP_8:
                        case OP_9:
                        case OP_10:
                        case OP_11:
                        case OP_12:
                        case OP_13:
                        case OP_14:
                        case OP_15:
                        case OP_16: {
                            // ( -- value)
                            auto const bn = CScriptNum::fromIntUnchecked(int(opcode) - int(OP_1 - 1));
                            stack.push_back(bn.getvch());
                            metrics.TallyPushOp(stack.back().size());
                            // The result of these opcodes should always be the
                            // minimal way to push the data they push, so no need
                            // for a CheckMinimalPush here.
                        } break;

                        case OP_NOP:
                            break;

                        case OP_CHECKLOCKTIMEVERIFY: {
                            if (!(flags & SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY)) {
                                break;
                            }

                            if (stack.size() < 1) {
                                return set_error(
                                    serror, ScriptError::INVALID_STACK_OPERATION);
                            }

                            // Note that elsewhere numeric opcodes are limited to
                            // operands in the range -2**31+1 to 2**31-1, however it
                            // is legal for opcodes to produce results exceeding
                            // that range. This limitation is implemented by
                            // CScriptNum's default 4-byte limit.
                            //
                            // If we kept to that limit we'd have a year 2038
                            // problem, even though the nLockTime field in
                            // transactions themselves is uint32 which only becomes
                            // meaningless after the year 2106.
                            //
                            // Thus as a special case we tell CScriptNum to accept
                            // up to 5-byte bignums, which are good until 2**39-1,
                            // well beyond the 2**32-1 limit of the nLockTime field
                            // itself.
                            const CScriptNum nLockTime(stacktop(-1), fRequireMinimal, 5);

                            // In the rare event that the argument may be < 0 due to
                            // some arithmetic being done first, you can always use
                            // 0 MAX CHECKLOCKTIMEVERIFY.
                            if (nLockTime < 0) {
                                return set_error(serror, ScriptError::NEGATIVE_LOCKTIME);
                            }

                            // Actually compare the specified lock time with the
                            // transaction.
                            if (!checker.CheckLockTime(nLockTime)) {
                                return set_error(serror,
                                                 ScriptError::UNSATISFIED_LOCKTIME);
                            }

                            break;
                        }

                        case OP_CHECKSEQUENCEVERIFY: {
                            if (!(flags & SCRIPT_VERIFY_CHECKSEQUENCEVERIFY)) {
                                break;
                            }

                            if (stack.size() < 1) {
                                return set_error(serror, ScriptError::INVALID_STACK_OPERATION);
                            }

                            // nSequence, like nLockTime, is a 32-bit unsigned
                            // integer field. See the comment in CHECKLOCKTIMEVERIFY
                            // regarding 5-byte numeric operands.
                            const CScriptNum nSequence(stacktop(-1), fRequireMinimal, 5);

                            // In the rare event that the argument may be < 0 due to
                            // some arithmetic being done first, you can always use
                            // 0 MAX CHECKSEQUENCEVERIFY.
                            if (nSequence < 0) {
                                return set_error(serror, ScriptError::NEGATIVE_LOCKTIME);
                            }

                            // To provide for future soft-fork extensibility, if the
                            // operand has the disabled lock-time flag set,
                            // CHECKSEQUENCEVERIFY behaves as a NOP.
                            auto res = nSequence.safeBitwiseAnd(CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG);
                            if ( ! res) {
                                // Defensive programming: It is impossible for the following error to be
                                // returned unless the current possible values of the operands change.
                                return set_error(serror, ScriptError::INVALID_NUMBER_RANGE_64_BIT);
                            }
                            if (*res != 0) {
                                break;
                            }

                            // Compare the specified sequence number with the input.
                            if (!checker.CheckSequence(nSequence)) {
                                return set_error(serror, ScriptError::UNSATISFIED_LOCKTIME);
                            }
                            break;
                        }

                        case OP_NOP1:
                        case OP_NOP4:
                        case OP_NOP5:
                        case OP_NOP6:
                        case OP_NOP7:
                        case OP_NOP8:
                        case OP_NOP9:
                        case OP_NOP10: {
                            if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS) {
                                return set_error(
                                    serror,
                                    ScriptError::DISCOURAGE_UPGRADABLE_NOPS);
                            }
                        } break;

                        //
                        // Functions
                        //
                        case OP_DEFINE: {
                            // <function-code> <function-id>
                            if (!may2026Enabled) {
                                // Upgrade 12 not yet activated, treat as bad opcode.
                                return set_error(serror, ScriptError::BAD_OPCODE);
                            }
                            if (stack.size() < 2) {
                                return set_error(serror, ScriptError::INVALID_STACK_OPERATION);
                            }

                            auto &funcId = stacktop(-1);
                            if (funcId.size() > may2026::MAX_FUNCTION_IDENTIFIER_SIZE) {
                                return set_error(serror, ScriptError::INVALID_FUNCTION_IDENTIFIER);
                            }

                            auto &funcCode = stacktop(-2);
                            if (funcCode.size() > MAX_SCRIPT_SIZE) {
                                // belt-and-suspenders check -- should never happen in production code
                                return set_error(serror, ScriptError::SCRIPT_SIZE);
                            }

                            const auto & [it, inserted] =
                                functionTable.try_emplace(std::move(funcId), std::move(funcCode));

                            if ( ! inserted) {
                                // overwriting existing functions is disallowed
                                return set_error(serror, ScriptError::FUNCTION_OVERWRITE_DISALLOWED);
                            }

                            // consume args
                            popstack(stack);
                            popstack(stack);
                            // tally additional op cost: byte size of the function's code
                            metrics.TallyPushOp(it->second.size());
                        } break;

                        case OP_INVOKE: {
                            // <function-id>
                            if (!may2026Enabled) {
                                // Upgrade 12 not yet activated, treat as bad opcode.
                                return set_error(serror, ScriptError::BAD_OPCODE);
                            }
                            if (stack.empty()) {
                                return set_error(serror, ScriptError::INVALID_STACK_OPERATION);
                            }

                            const auto &funcId = stacktop(-1);
                            if (funcId.size() > may2026::MAX_FUNCTION_IDENTIFIER_SIZE) {
                                return set_error(serror, ScriptError::INVALID_FUNCTION_IDENTIFIER);
                            }

                            const auto it = functionTable.find(funcId);
                            if (it == functionTable.end()) {
                                return set_error(serror, ScriptError::INVOKED_UNDEFINED_FUNCTION);
                            }

                            popstack(stack);
                            evalStack.pushFrame(it->second); // MAX_SCRIPT_SIZE check done by pushFrame
                            // Tell enclosing code to pause evaluating the current script; and begin this frame's script
                            newEvalFrameWasPushed = true;
                        } break;

                        //
                        // Control
                        //
                        case OP_IF:
                        case OP_NOTIF: {
                            // <expression> if [statements] [else [statements]]
                            // endif
                            bool fValue = false;
                            if (fExec) {
                                if (stack.size() < 1) {
                                    return set_error(
                                        serror,
                                        ScriptError::UNBALANCED_CONDITIONAL);
                                }
                                const valtype &vch = stacktop(-1);
                                if (flags & SCRIPT_VERIFY_MINIMALIF) {
                                    if (vch.size() > 1) {
                                        return set_error(serror,
                                                         ScriptError::MINIMALIF);
                                    }
                                    if (vch.size() == 1 && vch[0] != 1) {
                                        return set_error(serror,
                                                         ScriptError::MINIMALIF);
                                    }
                                }
                                fValue = CastToBool(vch);
                                if (opcode == OP_NOTIF) {
                                    fValue = !fValue;
                                }
                                popstack(stack);
                            }
                            curFrame.processIf(fValue);
                        } break;

                        case OP_BEGIN: {
                            if ( ! may2026Enabled) {
                                return set_error(serror, ScriptError::BAD_OPCODE);
                            }
                            // Unconditionally push program counter, even if !fExec, to keep track of proper control-
                            // flow structures.
                            curFrame.loopBeginPushPC();
                        } break;

                        case OP_UNTIL: {
                            if ( ! may2026Enabled) {
                                return set_error(serror, ScriptError::BAD_OPCODE);
                            }
                            if ( ! curFrame.controlStackTop()) {
                                // Innermost control block is not OP_BEGIN
                                return set_error(serror, ScriptError::UNBALANCED_CONTROL_FLOW);
                            }
                            bool fValue = true;
                            if (fExec) {
                                if (stack.empty()) {
                                    return set_error(serror, ScriptError::INVALID_STACK_OPERATION);
                                }
                                fValue = CastToBool(stacktop(-1));
                                popstack(stack);
                            }
                            if ( ! fValue) {
                                // This branch is only taken if fExec is true and if the test condition was false.
                                // Update program counter to point to the instruction after the enclosing OP_BEGIN.
                                pc = curFrame.controlStackTop();
                            } else {
                                // Condition met or !fExec, pop the loop stack item previously pushed by OP_BEGIN.
                                // Execution proceeds normally after OP_UNTIL instruction.
                                curFrame.loopEndPopPC();
                            }
                        } break;

                        case OP_ELSE: {
                            if ( ! curFrame.processElse(serror) ) {
                                return false; // serror was set by processElse
                            }
                        } break;

                        case OP_ENDIF: {
                            if ( ! curFrame.processEndIf(serror) ) {
                                return false; // serror was set by processEndIf
                            }
                        } break;

                        case OP_VERIFY: {
                            // (true -- ) or
                            // (false -- false) and return
                            if (stack.size() < 1) {
                                return set_error(
                                    serror, ScriptError::INVALID_STACK_OPERATION);
                            }
                            bool fValue = CastToBool(stacktop(-1));
                            if (fValue) {
                                popstack(stack);
                            } else {
                                return set_error(serror, ScriptError::VERIFY);
                            }
                        } break;

                        case OP_RETURN: {
                            return set_error(serror, ScriptError::OP_RETURN);
                        } break;

                        //
                        // Stack ops
                        //
                        case OP_TOALTSTACK: {
                            if (stack.size() < 1) {
                                return set_error(
                                    serror, ScriptError::INVALID_STACK_OPERATION);
                            }
                            altstack.push_back(std::move(stacktop(-1)));
                            popstack(stack);
                            // Intentional: no tallying is done to metrics.TallyPushOp()
                        } break;

                        case OP_FROMALTSTACK: {
                            if (altstack.size() < 1) {
                                return set_error(
                                    serror,
                                    ScriptError::INVALID_ALTSTACK_OPERATION);
                            }
                            stack.push_back(std::move(altstacktop(-1)));
                            metrics.TallyPushOp(stack.back().size());
                            popstack(altstack);
                        } break;

                        case OP_2DROP: {
                            // (x1 x2 -- )
                            if (stack.size() < 2) {
                                return set_error(
                                    serror, ScriptError::INVALID_STACK_OPERATION);
                            }
                            popstack(stack);
                            popstack(stack);
                        } break;

                        case OP_2DUP: {
                            // (x1 x2 -- x1 x2 x1 x2)
                            if (stack.size() < 2) {
                                return set_error(
                                    serror, ScriptError::INVALID_STACK_OPERATION);
                            }
                            valtype vch1 = stacktop(-2);
                            valtype vch2 = stacktop(-1);
                            stack.push_back(std::move(vch1));
                            metrics.TallyPushOp(stack.back().size());
                            stack.push_back(std::move(vch2));
                            metrics.TallyPushOp(stack.back().size());
                        } break;

                        case OP_3DUP: {
                            // (x1 x2 x3 -- x1 x2 x3 x1 x2 x3)
                            if (stack.size() < 3) {
                                return set_error(
                                    serror, ScriptError::INVALID_STACK_OPERATION);
                            }
                            valtype vch1 = stacktop(-3);
                            valtype vch2 = stacktop(-2);
                            valtype vch3 = stacktop(-1);
                            stack.push_back(std::move(vch1));
                            metrics.TallyPushOp(stack.back().size());
                            stack.push_back(std::move(vch2));
                            metrics.TallyPushOp(stack.back().size());
                            stack.push_back(std::move(vch3));
                            metrics.TallyPushOp(stack.back().size());
                        } break;

                        case OP_2OVER: {
                            // (x1 x2 x3 x4 -- x1 x2 x3 x4 x1 x2)
                            if (stack.size() < 4) {
                                return set_error(
                                    serror, ScriptError::INVALID_STACK_OPERATION);
                            }
                            valtype vch1 = stacktop(-4);
                            valtype vch2 = stacktop(-3);
                            stack.push_back(std::move(vch1));
                            metrics.TallyPushOp(stack.back().size());
                            stack.push_back(std::move(vch2));
                            metrics.TallyPushOp(stack.back().size());
                        } break;

                        case OP_2ROT: {
                            // (x1 x2 x3 x4 x5 x6 -- x3 x4 x5 x6 x1 x2)
                            if (stack.size() < 6) {
                                return set_error(
                                    serror, ScriptError::INVALID_STACK_OPERATION);
                            }
                            valtype vch1 = stacktop(-6);
                            valtype vch2 = stacktop(-5);
                            stack.erase(stack.end() - 6, stack.end() - 4);
                            stack.push_back(std::move(vch1));
                            metrics.TallyPushOp(stack.back().size());
                            stack.push_back(std::move(vch2));
                            metrics.TallyPushOp(stack.back().size());
                        } break;

                        case OP_2SWAP: {
                            // (x1 x2 x3 x4 -- x3 x4 x1 x2)
                            if (stack.size() < 4) {
                                return set_error(
                                    serror, ScriptError::INVALID_STACK_OPERATION);
                            }
                            swap(stacktop(-4), stacktop(-2));
                            swap(stacktop(-3), stacktop(-1));
                            // Intentional: no tallying is done to metrics.TallyPushOp()
                        } break;

                        case OP_IFDUP: {
                            // (x - 0 | x x)
                            if (stack.size() < 1) {
                                return set_error(
                                    serror, ScriptError::INVALID_STACK_OPERATION);
                            }
                            const valtype &vch = stacktop(-1);
                            if (CastToBool(vch)) {
                                valtype copy = vch;
                                stack.push_back(std::move(copy)); // Note: `vch` reference may be invalidated here
                                metrics.TallyPushOp(stack.back().size());
                            }
                        } break;

                        case OP_DEPTH: {
                            // -- stacksize
                            auto const bn = CScriptNum::fromIntUnchecked(stack.size());
                            stack.push_back(bn.getvch());
                            metrics.TallyPushOp(stack.back().size());
                        } break;

                        case OP_DROP: {
                            // (x -- )
                            if (stack.size() < 1) {
                                return set_error(serror, ScriptError::INVALID_STACK_OPERATION);
                            }
                            popstack(stack);
                        } break;

                        case OP_DUP: {
                            // (x -- x x)
                            if (stack.size() < 1) {
                                return set_error(
                                    serror, ScriptError::INVALID_STACK_OPERATION);
                            }
                            valtype vch = stacktop(-1);
                            stack.push_back(std::move(vch));
                            metrics.TallyPushOp(stack.back().size());
                        } break;

                        case OP_NIP: {
                            // (x1 x2 -- x2)
                            if (stack.size() < 2) {
                                return set_error(
                                    serror, ScriptError::INVALID_STACK_OPERATION);
                            }
                            stack.erase(stack.end() - 2);
                        } break;

                        case OP_OVER: {
                            // (x1 x2 -- x1 x2 x1)
                            if (stack.size() < 2) {
                                return set_error(
                                    serror, ScriptError::INVALID_STACK_OPERATION);
                            }
                            valtype vch = stacktop(-2);
                            stack.push_back(std::move(vch));
                            metrics.TallyPushOp(stack.back().size());
                        } break;

                        case OP_PICK:
                        case OP_ROLL: {
                            // (xn ... x2 x1 x0 n - xn ... x2 x1 x0 xn)
                            // (xn ... x2 x1 x0 n - ... x2 x1 x0 xn)
                            if (stack.size() < 2) {
                                return set_error(serror, ScriptError::INVALID_STACK_OPERATION);
                            }
                            int64_t const n = CScriptNum(stacktop(-1), fRequireMinimal, maxIntegerSizeLegacy).getint64();
                            popstack(stack);
                            if (n < 0 || uint64_t(n) >= stack.size()) {
                                return set_error(serror, ScriptError::INVALID_STACK_OPERATION);
                            }

                            valtype vch;
                            if (auto it = stack.end() - n - 1; opcode == OP_ROLL) {
                                // We use std::move to avoid excess copying in the OP_ROLL case.
                                vch = std::move(*it);
                                stack.erase(it); // `it` is invalidated here
                                metrics.TallyOp(n); // erasing in the middle is linear with `n`
                            } else {
                                // The OP_PICK case must do a copy, but at least we save on not having to erase in the
                                // middle and thus we don't have to slide everything over by 1 (hence extraCost = 0).
                                vch = *it;
                            }
                            stack.push_back(std::move(vch)); // move-construct to save on copying
                            metrics.TallyPushOp(stack.back().size());
                        } break;

                        case OP_ROT: {
                            // (x1 x2 x3 -- x2 x3 x1)
                            //  x2 x1 x3  after first swap
                            //  x2 x3 x1  after second swap
                            if (stack.size() < 3) {
                                return set_error(serror, ScriptError::INVALID_STACK_OPERATION);
                            }
                            swap(stacktop(-3), stacktop(-2));
                            swap(stacktop(-2), stacktop(-1));
                            // Intentional: no tallying is done to metrics.TallyPushOp()
                        } break;

                        case OP_SWAP: {
                            // (x1 x2 -- x2 x1)
                            if (stack.size() < 2) {
                                return set_error(serror, ScriptError::INVALID_STACK_OPERATION);
                            }
                            swap(stacktop(-2), stacktop(-1));
                            // Intentional: no tallying is done to metrics.TallyPushOp()
                        } break;

                        case OP_TUCK: {
                            // (x1 x2 -- x2 x1 x2)
                            if (stack.size() < 2) {
                                return set_error(serror, ScriptError::INVALID_STACK_OPERATION);
                            }
                            valtype vch = stacktop(-1);
                            metrics.TallyPushOp(vch.size());
                            stack.insert(stack.end() - 2, std::move(vch));
                        } break;

                        case OP_SIZE: {
                            // (in -- in size)
                            if (stack.size() < 1) {
                                return set_error(serror, ScriptError::INVALID_STACK_OPERATION);
                            }
                            auto const bn = CScriptNum::fromIntUnchecked(stacktop(-1).size());
                            stack.push_back(bn.getvch());
                            metrics.TallyPushOp(stack.back().size());
                        } break;

                        //
                        // Bitwise logic
                        //
                        case OP_AND:
                        case OP_OR:
                        case OP_XOR: {
                            // (x1 x2 - out)
                            if (stack.size() < 2) {
                                return set_error(serror, ScriptError::INVALID_STACK_OPERATION);
                            }
                            valtype &vch1 = stacktop(-2);
                            valtype &vch2 = stacktop(-1);

                            // Inputs must be the same size
                            if (vch1.size() != vch2.size()) {
                                return set_error(serror, ScriptError::INVALID_OPERAND_SIZE);
                            }

                            // To avoid allocating, we modify vch1 in place.
                            switch (opcode) {
                                case OP_AND:
                                    for (size_t i = 0; i < vch1.size(); ++i) {
                                        vch1[i] &= vch2[i];
                                    }
                                    break;
                                case OP_OR:
                                    for (size_t i = 0; i < vch1.size(); ++i) {
                                        vch1[i] |= vch2[i];
                                    }
                                    break;
                                case OP_XOR:
                                    for (size_t i = 0; i < vch1.size(); ++i) {
                                        vch1[i] ^= vch2[i];
                                    }
                                    break;
                                default:
                                    break;
                            }

                            // May 2025 Upgrade: tally this as the length of the result (vch1)
                            metrics.TallyOp(vch1.size());

                            // And pop vch2.
                            popstack(stack);
                        } break;

                        case OP_INVERT: {
                            // bitwise inverts all bytes (non-numeric operand and result)
                            // (x1 -> ~x1)
                            if (stack.size() < 1) {
                                return set_error(serror, ScriptError::INVALID_STACK_OPERATION);
                            }
                            valtype &data = stacktop(-1);
                            // Ensure result would respect size limits; this branch is only reachable from tests.
                            if (data.size() > maxScriptElementSize) {
                                return set_error(serror, ScriptError::PUSH_SIZE);
                            }
                            for (uint8_t &ch : data) {
                                ch = ~ch;
                            }
                            metrics.TallyPushOp(data.size());
                        } break;

                        case OP_EQUAL:
                        case OP_EQUALVERIFY:
                            // case OP_NOTEQUAL: // use OP_NUMNOTEQUAL
                            {
                                // (x1 x2 - bool)
                                if (stack.size() < 2) {
                                    return set_error(serror, ScriptError::INVALID_STACK_OPERATION);
                                }

                                const bool fEqual = stacktop(-2) == stacktop(-1);
                                // OP_NOTEQUAL is disabled because it would be too
                                // easy to say something like n != 1 and have some
                                // wiseguy pass in 1 with extra zero bytes after it
                                // (numerically, 0x01 == 0x0001 == 0x000001)
                                // if (opcode == OP_NOTEQUAL)
                                //    fEqual = !fEqual;
                                popstack(stack);
                                popstack(stack);
                                stack.push_back(fEqual ? vchTrue : vchFalse);
                                metrics.TallyPushOp(stack.back().size());
                                if (opcode == OP_EQUALVERIFY) {
                                    if (fEqual) {
                                        popstack(stack);
                                    } else {
                                        return set_error(serror, ScriptError::EQUALVERIFY);
                                    }
                                }
                            }
                            break;

                        //
                        // Numeric
                        //
                        case OP_1ADD:
                        case OP_1SUB:
                        case OP_NEGATE:
                        case OP_ABS:
                        case OP_NOT:
                        case OP_0NOTEQUAL: {
                            // (in -- out)
                            if (stack.size() < 1) {
                                return set_error(serror, ScriptError::INVALID_STACK_OPERATION);
                            }
                            ScriptNumType bn(stacktop(-1), fRequireMinimal, maxIntegerSize);
                            uint32_t pushCostFactor = 2u; // all except OP_NOT and OP_0NOTEQUAL will be costed 2x

                            switch (opcode) {
                                case OP_1ADD: {
                                    const bool ok = bn.safeIncr();
                                    if ( ! ok) {
                                        return set_error(serror, invalidNumberRangeError);
                                    }
                                    break;
                                }
                                case OP_1SUB: {
                                    const bool ok = bn.safeDecr();
                                    if ( ! ok) {
                                        return set_error(serror, invalidNumberRangeError);
                                    }
                                    break;
                                }
                                case OP_NEGATE:
                                    bn.negate();
                                    break;
                                case OP_ABS:
                                    if (bn < bnZero) {
                                        bn.negate();
                                    }
                                    break;
                                case OP_NOT:
                                    bn = ScriptNumType::fromIntUnchecked(bn == bnZero);
                                    pushCostFactor = 1u; // as per spec, this op gets costed 1x
                                    break;
                                case OP_0NOTEQUAL:
                                    bn = ScriptNumType::fromIntUnchecked(bn != bnZero);
                                    pushCostFactor = 1u; // as per spec, this op gets costed 1x
                                    break;
                                default:
                                    assert(!"invalid opcode");
                                    break;
                            }
                            popstack(stack);
                            auto vch = bn.getvch();
                            // belt-and-suspenders check (BigInt case only)
                            if (UsesBigInt && vch.size() > maxScriptElementSize) {
                                return set_error(serror, invalidNumberRangeError);
                            }
                            stack.push_back(std::move(vch));
                            metrics.TallyPushOp(stack.back().size() * pushCostFactor);
                        } break;

                        case OP_ADD:
                        case OP_SUB:
                        case OP_MUL:
                        case OP_DIV:
                        case OP_MOD:
                        case OP_BOOLAND:
                        case OP_BOOLOR:
                        case OP_NUMEQUAL:
                        case OP_NUMEQUALVERIFY:
                        case OP_NUMNOTEQUAL:
                        case OP_LESSTHAN:
                        case OP_GREATERTHAN:
                        case OP_LESSTHANOREQUAL:
                        case OP_GREATERTHANOREQUAL:
                        case OP_MIN:
                        case OP_MAX: {
                            // (x1 x2 -- out)
                            if (stack.size() < 2) {
                                return set_error(serror, ScriptError::INVALID_STACK_OPERATION);
                            }
                            const valtype &vch1 = stacktop(-2);
                            const valtype &vch2 = stacktop(-1);
                            ScriptNumType bn1(vch1, fRequireMinimal, maxIntegerSize);
                            ScriptNumType const bn2(vch2, fRequireMinimal, maxIntegerSize);
                            auto bn = ScriptNumType::fromIntUnchecked(0);
                            uint32_t quadraticOpCost = 0u; // for OP_MUL, OP_DIV, and OP_MOD
                            uint32_t pushCostFactor = 1u; // arithmetic and min/max ops below set this to 2x
                            constexpr uint64_t worstCaseSize = std::max(MAX_SCRIPT_ELEMENT_SIZE_LEGACY, may2025::MAX_SCRIPT_ELEMENT_SIZE);
                            static_assert(std::in_range<uint32_t>(worstCaseSize * worstCaseSize),
                                          "Assumption is that the largest theoretical op cost fits in a 32-bit unsigned int.");

                            switch (opcode) {
                                case OP_ADD: {
                                    const bool ok = bn1.safeAddInPlace(bn2);
                                    if ( ! ok) {
                                        return set_error(serror, invalidNumberRangeError);
                                    }
                                    bn = std::move(bn1);
                                    pushCostFactor = 2u;
                                    break;
                                }

                                case OP_SUB: {
                                    const bool ok = bn1.safeSubInPlace(bn2);
                                    if ( ! ok) {
                                        return set_error(serror, invalidNumberRangeError);
                                    }
                                    bn = std::move(bn1);
                                    pushCostFactor = 2u;
                                    break;
                                }

                                case OP_MUL: {
                                    const bool ok = bn1.safeMulInPlace(bn2);
                                    if ( ! ok) {
                                        return set_error(serror, invalidNumberRangeError);
                                    }
                                    bn = std::move(bn1);
                                    quadraticOpCost = vch1.size() * vch2.size();
                                    pushCostFactor = 2u;
                                    break;
                                }

                                case OP_DIV:
                                    // denominator must not be 0
                                    if (bn2 == bnZero) {
                                        return set_error(serror, ScriptError::DIV_BY_ZERO);
                                    }
                                    bn = std::move(bn1 /= bn2);
                                    quadraticOpCost = vch1.size() * vch2.size();
                                    pushCostFactor = 2u;
                                    break;

                                case OP_MOD:
                                    // divisor must not be 0
                                    if (bn2 == bnZero) {
                                        return set_error(serror, ScriptError::MOD_BY_ZERO);
                                    }
                                    bn = std::move(bn1 %= bn2);
                                    quadraticOpCost = vch1.size() * vch2.size();
                                    pushCostFactor = 2u;
                                    break;

                                case OP_BOOLAND:
                                    bn = ScriptNumType::fromIntUnchecked(bn1 != bnZero && bn2 != bnZero);
                                    break;
                                case OP_BOOLOR:
                                    bn = ScriptNumType::fromIntUnchecked(bn1 != bnZero || bn2 != bnZero);
                                    break;
                                case OP_NUMEQUAL:
                                    bn = ScriptNumType::fromIntUnchecked(bn1 == bn2);
                                    break;
                                case OP_NUMEQUALVERIFY:
                                    bn = ScriptNumType::fromIntUnchecked(bn1 == bn2);
                                    break;
                                case OP_NUMNOTEQUAL:
                                    bn = ScriptNumType::fromIntUnchecked(bn1 != bn2);
                                    break;
                                case OP_LESSTHAN:
                                    bn = ScriptNumType::fromIntUnchecked(bn1 < bn2);
                                    break;
                                case OP_GREATERTHAN:
                                    bn = ScriptNumType::fromIntUnchecked(bn1 > bn2);
                                    break;
                                case OP_LESSTHANOREQUAL:
                                    bn = ScriptNumType::fromIntUnchecked(bn1 <= bn2);
                                    break;
                                case OP_GREATERTHANOREQUAL:
                                    bn = ScriptNumType::fromIntUnchecked(bn1 >= bn2);
                                    break;
                                case OP_MIN:
                                    bn = (bn1 < bn2 ? bn1 : bn2);
                                    pushCostFactor = 2u;
                                    break;
                                case OP_MAX:
                                    bn = (bn1 > bn2 ? bn1 : bn2);
                                    pushCostFactor = 2u;
                                    break;
                                default:
                                    assert(!"invalid opcode");
                                    break;
                            }

                            metrics.TallyOp(quadraticOpCost); // is 0 for most opcodes except: MUL, MOD, DIV

                            popstack(stack); // invalidates: vch1 and vch2
                            popstack(stack);
                            {
                                auto vch = bn.getvch();
                                // Belt-and-suspenders check that we aren't overflowing the push limit in the BigInt case
                                if (UsesBigInt && vch.size() > maxScriptElementSize) {
                                    return set_error(serror, invalidNumberRangeError);
                                }
                                stack.push_back(std::move(vch));
                            }
                            metrics.TallyPushOp(stack.back().size() * pushCostFactor);

                            if (opcode == OP_NUMEQUALVERIFY) {
                                if (CastToBool(stacktop(-1))) {
                                    popstack(stack);
                                } else {
                                    return set_error(serror, ScriptError::NUMEQUALVERIFY);
                                }
                            }
                        } break;

                        case OP_LSHIFTNUM:
                        case OP_RSHIFTNUM: {
                            // (num nbits -- out)
                            // LSHIFTNUM is an arithmetic 2's complement left-shift,  defined as: out = num * 2^nbits
                            // RSHIFTNUM is an arithmetic 2's complement right-shift, defined as: out = num / 2^nbits
                            // Rounding is always done towards negative infinity, like in C++20 operator>>, so e.g.:
                            //     `-1 >> 1 == -1`, but `1 >> 1 == 0`.
                            if (stack.size() < 2) {
                                return set_error(serror, ScriptError::INVALID_STACK_OPERATION);
                            }
                            // Note, we don't support this operation before arbitrary precision arithmetic activated.
                            // Also note that these op-codes are marked "disabled" by IsOpcodeDisabled() before May 2026,
                            // since the op-code values corresponded to historical OP_2MUL/OP_2DIV (disabled by Satoshi).
                            if constexpr (!UsesBigInt) {
                                // This branch is never taken outside of tests.
                                return set_error(serror, ScriptError::UNKNOWN);
                            } else {
                                static_assert(std::in_range<int32_t>(ScriptBigInt::MAX_BITS),
                                              "Assumption is a 32-bit int can hold more than the bit size of a script number");
                                // Note: This call clamps i32bits to the range: [INT_MIN, INT_MAX].
                                int32_t const i32bits = ScriptNumType(stacktop(-1), fRequireMinimal, maxIntegerSize).getint32();

                                // Disallow negative bit counts
                                if (i32bits < 0) {
                                    return set_error(serror, ScriptError::INVALID_BIT_SHIFT);
                                }

                                uint64_t const nbits = static_cast<uint64_t>(i32bits); // prefer uint64_t for below code

                                popstack(stack); // consume nbits; numeric argument is now the topmost stack item

                                if (nbits == 0) {
                                    // If nbits == 0 the number already on the stack can remain, saving cycles, however we
                                    // must still validate it; we never accept an invalid number as a numeric argument.
                                    ScriptBigInt::throwIfInvalidScriptNumEncoding(stacktop(-1), fRequireMinimal, maxIntegerSize);
                                } else {
                                    // nbits > 0, we must do actual work
                                    ScriptNumType num(stacktop(-1), fRequireMinimal, maxIntegerSize);
                                    popstack(stack); // consume numeric argument

                                    bool valid{};
                                    if (opcode == OP_LSHIFTNUM) {
                                        // Arithmetic left shift, r = a * 2^b
                                        valid = num.checkedLeftShift(nbits); // Note: this fast-fails on excessive nbits
                                    } else {
                                        // Arithmetic right shift, r = a / 2^b (rounded towards negative infinity)
                                        valid = num.checkedRightShift(nbits); // Note: this fast-returns on excessive nbits
                                    }

                                    if (!valid) {
                                        // result overflow, abort early before allocating any more vectors, etc
                                        return set_error(serror, invalidNumberRangeError);
                                    }

                                    valtype vch = num.getvch();
                                    // Ensure result respects size limits; this check is redundant with the above code
                                    // block, but is here for belt-and-suspenders.
                                    if (vch.size() > maxScriptElementSize) {
                                        return set_error(serror, ScriptError::PUSH_SIZE);
                                    }
                                    stack.push_back(std::move(vch));
                                }

                                metrics.TallyPushOp(stack.back().size());
                            }
                        } break;

                        case OP_WITHIN: {
                            // (x min max -- out)
                            if (stack.size() < 3) {
                                return set_error(serror, ScriptError::INVALID_STACK_OPERATION);
                            }
                            ScriptNumType const bn1(stacktop(-3), fRequireMinimal, maxIntegerSize);
                            ScriptNumType const bn2(stacktop(-2), fRequireMinimal, maxIntegerSize);
                            ScriptNumType const bn3(stacktop(-1), fRequireMinimal, maxIntegerSize);

                            bool fValue = (bn2 <= bn1 && bn1 < bn3);
                            popstack(stack);
                            popstack(stack);
                            popstack(stack);
                            stack.push_back(fValue ? vchTrue : vchFalse);
                            metrics.TallyPushOp(stack.back().size());
                        } break;

                        //
                        // Crypto
                        //
                        case OP_RIPEMD160:
                        case OP_SHA1:
                        case OP_SHA256:
                        case OP_HASH160:
                        case OP_HASH256: {
                            // (in -- hash)
                            if (stack.size() < 1) {
                                return set_error(serror, ScriptError::INVALID_STACK_OPERATION);
                            }
                            const valtype &vch = stacktop(-1);
                            valtype vchHash((opcode == OP_RIPEMD160 ||
                                             opcode == OP_SHA1 ||
                                             opcode == OP_HASH160)
                                                ? 20
                                                : 32);
                            bool isTwoRoundHashOp = false;
                            if (opcode == OP_RIPEMD160) {
                                CRIPEMD160()
                                    .Write(vch.data(), vch.size())
                                    .Finalize(vchHash.data());
                            } else if (opcode == OP_SHA1) {
                                CSHA1()
                                    .Write(vch.data(), vch.size())
                                    .Finalize(vchHash.data());
                            } else if (opcode == OP_SHA256) {
                                CSHA256()
                                    .Write(vch.data(), vch.size())
                                    .Finalize(vchHash.data());
                            } else if (opcode == OP_HASH160) {
                                CHash160().Write(vch).Finalize(vchHash);
                                isTwoRoundHashOp = true;
                            } else if (opcode == OP_HASH256) {
                                CHash256().Write(vch).Finalize(vchHash);
                                isTwoRoundHashOp = true;
                            }
                            metrics.TallyHashOp(vch.size(), isTwoRoundHashOp);
                            popstack(stack);
                            stack.push_back(std::move(vchHash));
                            metrics.TallyPushOp(stack.back().size());
                        } break;

                        case OP_CODESEPARATOR: {
                            // Hash starts after the code separator
                            pbegincodehash = pc;
                        } break;

                        case OP_CHECKSIG:
                        case OP_CHECKSIGVERIFY: {
                            // (sig pubkey -- bool)
                            if (stack.size() < 2) {
                                return set_error(serror, ScriptError::INVALID_STACK_OPERATION);
                            }
                            valtype const &vchSig = stacktop(-2);
                            valtype const &vchPubKey = stacktop(-1);

                            if (!CheckTransactionSignatureEncoding(vchSig, flags,
                                                                   serror) ||
                                !CheckPubKeyEncoding(vchPubKey, flags, serror)) {
                                // serror is set
                                return false;
                            }

                            bool fSuccess = false;
                            if (vchSig.size()) {
                                // Subset of script starting at the most recent
                                // codeseparator
                                const ByteView scriptCode(pbegincodehash, pend);

                                // Remove signature for pre-fork scripts
                                const auto cleanedUp = CleanupScriptCode(scriptCode, vchSig, flags);

                                size_t bytesHashed{};
                                fSuccess = checker.CheckSig(vchSig, vchPubKey, cleanedUp.scriptCode, flags, &bytesHashed);
                                metrics.TallySigChecks(1);
                                if (bytesHashed) {
                                    metrics.TallyHashOp(bytesHashed, true);
                                }

                                if (!fSuccess && (flags & SCRIPT_VERIFY_NULLFAIL)) {
                                    return set_error(serror, ScriptError::SIG_NULLFAIL);
                                }
                            }

                            popstack(stack);
                            popstack(stack);
                            stack.push_back(fSuccess ? vchTrue : vchFalse);
                            metrics.TallyPushOp(stack.back().size());
                            if (opcode == OP_CHECKSIGVERIFY) {
                                if (fSuccess) {
                                    popstack(stack);
                                } else {
                                    return set_error(serror, ScriptError::CHECKSIGVERIFY);
                                }
                            }
                        } break;

                        case OP_CHECKDATASIG:
                        case OP_CHECKDATASIGVERIFY: {
                            // (sig message pubkey -- bool)
                            if (stack.size() < 3) {
                                return set_error(serror, ScriptError::INVALID_STACK_OPERATION);
                            }

                            valtype const &vchSig = stacktop(-3);
                            valtype const &vchMessage = stacktop(-2);
                            valtype const &vchPubKey = stacktop(-1);

                            if (!CheckDataSignatureEncoding(vchSig, flags,
                                                            serror) ||
                                !CheckPubKeyEncoding(vchPubKey, flags, serror)) {
                                // serror is set
                                return false;
                            }

                            bool fSuccess = false;
                            if (vchSig.size()) {
                                uint256 sigHash{uint256::Uninitialized};
                                CSHA256()
                                    .Write(vchMessage.data(), vchMessage.size())
                                    .Finalize(sigHash.data());
                                fSuccess = checker.VerifySignature(vchSig, CPubKey(vchPubKey), sigHash);
                                metrics.TallySigChecks(1);
                                metrics.TallyHashOp(vchMessage.size(), false);

                                if (!fSuccess && (flags & SCRIPT_VERIFY_NULLFAIL)) {
                                    return set_error(serror, ScriptError::SIG_NULLFAIL);
                                }
                            }

                            popstack(stack);
                            popstack(stack);
                            popstack(stack);
                            stack.push_back(fSuccess ? vchTrue : vchFalse);
                            metrics.TallyPushOp(stack.back().size());
                            if (opcode == OP_CHECKDATASIGVERIFY) {
                                if (fSuccess) {
                                    popstack(stack);
                                } else {
                                    return set_error(serror, ScriptError::CHECKDATASIGVERIFY);
                                }
                            }
                        } break;

                        case OP_CHECKMULTISIG:
                        case OP_CHECKMULTISIGVERIFY: {
                            // ([dummy] [sig ...] num_of_signatures [pubkey ...]
                            // num_of_pubkeys -- bool)
                            const size_t idxKeyCount = 1;
                            if (stack.size() < idxKeyCount) {
                                return set_error(serror, ScriptError::INVALID_STACK_OPERATION);
                            }
                            int64_t const nKeysCount = CScriptNum(stacktop(-idxKeyCount), fRequireMinimal, maxIntegerSizeLegacy).getint64();
                            if (nKeysCount < 0 || nKeysCount > MAX_PUBKEYS_PER_MULTISIG) {
                                return set_error(serror, ScriptError::PUBKEY_COUNT);
                            }
                            if ( ! chipVmLimitsEnabled) {
                                // Pre May 2025: tally nOpCount
                                // Post May 2025: we account for this differently
                                nOpCount += nKeysCount;
                                if (nOpCount > MAX_OPS_PER_SCRIPT_LEGACY) {
                                    return set_error(serror, ScriptError::OP_COUNT);
                                }
                            }

                            // stack depth of the top pubkey
                            const size_t idxTopKey = idxKeyCount + 1;

                            // stack depth of nSigsCount
                            const size_t idxSigCount = idxTopKey + nKeysCount;
                            if (stack.size() < idxSigCount) {
                                return set_error(serror, ScriptError::INVALID_STACK_OPERATION);
                            }
                            int64_t const nSigsCount = CScriptNum(stacktop(-idxSigCount), fRequireMinimal, maxIntegerSizeLegacy).getint64();
                            if (nSigsCount < 0 || nSigsCount > nKeysCount) {
                                return set_error(serror, ScriptError::SIG_COUNT);
                            }

                            // stack depth of the top signature
                            const size_t idxTopSig = idxSigCount + 1;

                            // stack depth of the dummy element
                            const size_t idxDummy = idxTopSig + nSigsCount;
                            if (stack.size() < idxDummy) {
                                return set_error(serror, ScriptError::INVALID_STACK_OPERATION);
                            }

                            // Assuming success is usually a bad idea, but the
                            // schnorr path can only succeed.
                            bool fSuccess = true;

                            if ((flags & SCRIPT_ENABLE_SCHNORR_MULTISIG) &&
                                stacktop(-idxDummy).size() != 0) {
                                // SCHNORR MULTISIG
                                static_assert(
                                    MAX_PUBKEYS_PER_MULTISIG < 32,
                                    "Schnorr multisig checkbits implementation "
                                    "assumes < 32 pubkeys.");
                                uint32_t checkBits = 0;

                                // Dummy element is to be interpreted as a bitfield
                                // that represent which pubkeys should be checked.
                                valtype const &vchDummy = stacktop(-idxDummy);
                                if ( ! DecodeBitfield(vchDummy, nKeysCount, checkBits, serror)) {
                                    // serror is set
                                    return false;
                                }

                                // The bitfield doesn't set the right number of
                                // signatures.
                                if (countBits(checkBits) != uint32_t(nSigsCount)) {
                                    return set_error(serror, ScriptError::INVALID_BIT_COUNT);
                                }

                                // Subset of script starting at the most recent
                                // codeseparator
                                const ByteView scriptCode(pbegincodehash, pend);

                                const size_t idxBottomKey = idxTopKey + nKeysCount - 1;
                                const size_t idxBottomSig = idxTopSig + nSigsCount - 1;

                                int iKey = 0;
                                for (int iSig = 0; iSig < nSigsCount; iSig++, iKey++) {
                                    if ((checkBits >> iKey) == 0) {
                                        // This is a sanity check and should be
                                        // unrecheable.
                                        return set_error(serror, ScriptError::INVALID_BIT_RANGE);
                                    }

                                    // Find the next suitable key.
                                    while (((checkBits >> iKey) & 0x01) == 0) {
                                        iKey++;
                                    }

                                    if (iKey >= nKeysCount) {
                                        // This is a sanity check and should be
                                        // unrecheable.
                                        return set_error(serror, ScriptError::PUBKEY_COUNT);
                                    }

                                    // Check the signature.
                                    valtype const &vchSig = stacktop(-idxBottomSig + iSig);
                                    valtype const &vchPubKey = stacktop(-idxBottomKey + iKey);

                                    // Note that only pubkeys associated with a
                                    // signature are checked for validity.
                                    if ( ! CheckTransactionSchnorrSignatureEncoding(vchSig, flags, serror) ||
                                         ! CheckPubKeyEncoding(vchPubKey, flags, serror)) {
                                        // serror is set
                                        return false;
                                    }

                                    // Check signature
                                    size_t bytesHashed{};
                                    if (!checker.CheckSig(vchSig, vchPubKey, scriptCode, flags, &bytesHashed)) {
                                        // This can fail if the signature is empty,
                                        // which also is a NULLFAIL error as the
                                        // bitfield should have been null in this
                                        // situation.
                                        return set_error(serror, ScriptError::SIG_NULLFAIL);
                                    }

                                    // this is guaranteed to execute exactly
                                    // nSigsCount times (if not script error)
                                    metrics.TallySigChecks(1);
                                    // Account for hash ops
                                    if (bytesHashed > 0u) {
                                        metrics.TallyHashOp(bytesHashed, true);
                                    }
                                }

                                if ((checkBits >> iKey) != 0) {
                                    // This is a sanity check and should be
                                    // unrecheable.
                                    return set_error(serror, ScriptError::INVALID_BIT_COUNT);
                                }
                            } else {
                                // LEGACY MULTISIG (ECDSA / NULL)

                                // Subset of script starting at the most recent
                                // codeseparator
                                CleanupScriptCodeResult cleanedUp({pbegincodehash, pend});

                                // Remove signature for pre-fork scripts
                                for (int k = 0; k < nSigsCount; k++) {
                                    valtype const &vchSig = stacktop(-idxTopSig - k);
                                    cleanedUp = CleanupScriptCode(std::move(cleanedUp), vchSig, flags);
                                }

                                int nSigsRemaining = nSigsCount;
                                int nKeysRemaining = nKeysCount;
                                while (fSuccess && nSigsRemaining > 0) {
                                    valtype const &vchSig = stacktop(-idxTopSig - (nSigsCount - nSigsRemaining));
                                    valtype const &vchPubKey = stacktop(-idxTopKey - (nKeysCount - nKeysRemaining));

                                    // Note how this makes the exact order of pubkey/signature evaluation
                                    // distinguishable by CHECKMULTISIG NOT if the STRICTENC flag is set. See the
                                    // script_(in)valid tests for details.
                                    if (!CheckTransactionECDSASignatureEncoding(vchSig, flags, serror) ||
                                        !CheckPubKeyEncoding(vchPubKey, flags, serror)) {
                                        // serror is set
                                        return false;
                                    }

                                    // Check signature
                                    size_t bytesHashed{};
                                    bool fOk = checker.CheckSig(vchSig, vchPubKey, cleanedUp.scriptCode, flags, &bytesHashed);
                                    // Account for hash ops (may be 0 on nullsig, in which case we hashed nothing)
                                    if (bytesHashed > 0u) {
                                        metrics.TallyHashOp(bytesHashed, true);
                                    }

                                    if (fOk) {
                                        nSigsRemaining--;
                                    }
                                    nKeysRemaining--;

                                    // If there are more signatures left than keys left, then too many signatures have
                                    // failed. Exit early, without checking any further signatures.
                                    if (nSigsRemaining > nKeysRemaining) {
                                        fSuccess = false;
                                    }
                                }

                                bool areAllSignaturesNull = true;
                                for (int i = 0; i < nSigsCount; i++) {
                                    if (stacktop(-idxTopSig - i).size()) {
                                        areAllSignaturesNull = false;
                                        break;
                                    }
                                }

                                // If the operation failed, we may require that all signatures must be empty vector
                                if (!fSuccess && (flags & SCRIPT_VERIFY_NULLFAIL) && !areAllSignaturesNull) {
                                    return set_error(serror, ScriptError::SIG_NULLFAIL);
                                }

                                if (!areAllSignaturesNull) {
                                    // This is not identical to the number of actual ECDSA verifies, but, it is an upper
                                    // bound that can be easily determined without doing CPU-intensive checks.
                                    metrics.TallySigChecks(nKeysCount);
                                }
                            }

                            // Clean up stack of all arguments
                            for (size_t i = 0; i < idxDummy; i++) {
                                popstack(stack);
                            }

                            stack.push_back(fSuccess ? vchTrue : vchFalse);
                            metrics.TallyPushOp(stack.back().size());
                            if (opcode == OP_CHECKMULTISIGVERIFY) {
                                if (fSuccess) {
                                    popstack(stack);
                                } else {
                                    return set_error(serror, ScriptError::CHECKMULTISIGVERIFY);
                                }
                            }
                        } break;

                        //
                        // Byte string operations
                        //
                        case OP_CAT: {
                            // (x1 x2 -- out)
                            if (stack.size() < 2) {
                                return set_error(serror, ScriptError::INVALID_STACK_OPERATION);
                            }
                            valtype &vch1 = stacktop(-2);
                            const valtype &vch2 = stacktop(-1);
                            if (vch1.size() + vch2.size() > maxScriptElementSize) {
                                return set_error(serror, ScriptError::PUSH_SIZE);
                            }
                            vch1.insert(vch1.end(), vch2.begin(), vch2.end());
                            popstack(stack);
                            metrics.TallyPushOp(stack.back().size());
                        } break;

                        case OP_SPLIT: {
                            // (in position -- x1 x2)
                            if (stack.size() < 2) {
                                return set_error(serror, ScriptError::INVALID_STACK_OPERATION);
                            }

                            const valtype &data = stacktop(-2);

                            // Make sure the split point is appropriate.
                            int64_t const position = CScriptNum(stacktop(-1), fRequireMinimal, maxIntegerSizeLegacy).getint64();
                            if (position < 0 || uint64_t(position) > data.size()) {
                                return set_error(serror, ScriptError::INVALID_SPLIT_RANGE);
                            }

                            // Prepare the results in their own buffer as `data` will be invalidated.
                            valtype n1(data.begin(), data.begin() + position);
                            valtype n2(data.begin() + position, data.end());

                            // Replace existing stack values by the new values.
                            const size_t totalSize = n1.size() + n2.size();
                            stacktop(-2) = std::move(n1);
                            stacktop(-1) = std::move(n2);
                            metrics.TallyPushOp(totalSize);
                        } break;

                        case OP_REVERSEBYTES: {
                            // (in -- out)
                            if (stack.size() < 1) {
                                return set_error(serror, ScriptError::INVALID_STACK_OPERATION);
                            }

                            valtype &data = stacktop(-1);
                            std::reverse(data.begin(), data.end());
                            metrics.TallyPushOp(data.size());
                        } break;

                        //
                        // Conversion operations
                        //
                        case OP_NUM2BIN: {
                            // (in size -- out)
                            if (stack.size() < 2) {
                                return set_error(serror, ScriptError::INVALID_STACK_OPERATION);
                            }

                            uint64_t const size = CScriptNum(stacktop(-1), fRequireMinimal, maxIntegerSizeLegacy).getint64();
                            if (size > maxScriptElementSize) {
                                return set_error(serror, ScriptError::PUSH_SIZE);
                            }

                            popstack(stack);
                            valtype &rawnum = stacktop(-1);

                            // Try to see if we can fit that number in the number of byte requested.
                            ScriptNumType::MinimallyEncode(rawnum);
                            if (rawnum.size() > size) {
                                // We definitively cannot.
                                return set_error(serror, ScriptError::IMPOSSIBLE_ENCODING);
                            }

                            // We already have an element of the right size, we don't need to do anything.
                            if (rawnum.size() == size) {
                                metrics.TallyPushOp(rawnum.size());
                                break;
                            }

                            uint8_t signbit = 0x00;
                            if (rawnum.size() > 0) {
                                signbit = rawnum.back() & 0x80;
                                rawnum[rawnum.size() - 1] &= 0x7f;
                            }

                            rawnum.reserve(size);
                            while (rawnum.size() < size - 1) {
                                rawnum.push_back(0x00);
                            }

                            rawnum.push_back(signbit);
                            metrics.TallyPushOp(rawnum.size());
                        } break;

                        case OP_BIN2NUM: {
                            // (in -- out)
                            if (stack.size() < 1) {
                                return set_error(serror, ScriptError::INVALID_STACK_OPERATION);
                            }

                            valtype &n = stacktop(-1);
                            ScriptNumType::MinimallyEncode(n);
                            metrics.TallyPushOp(n.size());

                            // The resulting number must be a valid number.
                            // Note: IsMinimallyEncoded() here is really just checking if the number is in range.
                            if ( ! ScriptNumType::IsMinimallyEncoded(n, maxIntegerSize)) {
                                return set_error(serror, invalidNumberRangeError);
                            }
                        } break;

                        case OP_LSHIFTBIN:
                        case OP_RSHIFTBIN: {
                            // (in nbits -- out)
                            // Left (or right) shift of an arbitrary byte-blob as if it were a big (in.size() * 8)-bit word,
                            // padding with 0 bits at the rightmost (or leftmost) end.
                            if (stack.size() < 2) {
                                return set_error(serror, ScriptError::INVALID_STACK_OPERATION);
                            }
                            constexpr uint64_t maxDataPushBits = 8u * std::max(MAX_SCRIPT_ELEMENT_SIZE_LEGACY,
                                                                               may2025::MAX_SCRIPT_ELEMENT_SIZE);
                            static_assert(std::in_range<int32_t>(maxDataPushBits),
                                          "Assumption is a 32-bit int can hold the bit size of a data push");

                            // Note: The below call to `getint32()` is a saturating call that clamps to [INT_MIN, INT_MAX].
                            //
                            // The spec allows for the bit count argument to be *any* script number even if it exceeds 80k
                            // bits! However, our `bitShiftBlob()` API only supports bit shifting up to `size_t`-max bits.
                            // So, in order to handle this, and as an optimization, we just saturate `nbits` to INT_MAX here
                            // even if the number of bits requested is > 2^31 - 1. Since the input data can never exceed 80k
                            // bits (let alone INT_MAX bits), this is ok and produces consensus-correct behavior.
                            int32_t const nbits = ScriptNumType(stacktop(-1), fRequireMinimal, maxIntegerSize).getint32();

                            // Negative bit counts are not allowed
                            if (nbits < 0) {
                                return set_error(serror, ScriptError::INVALID_BIT_SHIFT);
                            }
                            valtype data = std::move(stacktop(-2));

                            popstack(stack);
                            popstack(stack);

                            // Note: If bit shifting exceeds the number of bits in `data`, that's ok, `bitShiftBlob`
                            // returns quickly, having zeroed-out `data` in that case.
                            bitShiftBlob(data, nbits, /* right shift = */ opcode == OP_RSHIFTBIN);

                            // Belt-and-suspenders redundant check: Ensure result fits on stack & push result.
                            if (data.size() > maxScriptElementSize) {
                                // This branch can never be taken outside of tests.
                                return set_error(serror, ScriptError::PUSH_SIZE);
                            }
                            stack.push_back(std::move(data));

                            metrics.TallyPushOp(stack.back().size());
                        } break;

                        // Note: For the introspection opcodes, we intentionally use CScriptNum for reading/writing the
                        //       inputs/outputs of these opcodes as a performance optimization, since their parameters
                        //       and their results can never exceed 64-bits.

                        // Native Introspection opcodes (Nullary)
                        case OP_INPUTINDEX:
                        case OP_ACTIVEBYTECODE:
                        case OP_TXVERSION:
                        case OP_TXINPUTCOUNT:
                        case OP_TXOUTPUTCOUNT:
                        case OP_TXLOCKTIME: {
                            if ( ! context) {
                                return set_error(serror, ScriptError::CONTEXT_NOT_PRESENT);
                            }

                            switch (opcode) {
                                //  Operations
                                case OP_INPUTINDEX: {
                                    auto const bn = CScriptNum::fromInt(context->inputIndex()).value();
                                    stack.push_back(bn.getvch());
                                } break;
                                case OP_ACTIVEBYTECODE: {
                                    // Subset of script starting at the most recent code separator (if any)
                                    // or the entire script if no code separators are present.
                                    if (static_cast<size_t>(pend - pbegincodehash) > maxScriptElementSize) {
                                        return set_error(serror, ScriptError::PUSH_SIZE);
                                    }
                                    stack.emplace_back(pbegincodehash, pend);
                                } break;
                                case OP_TXVERSION: {
                                    auto const bn = CScriptNum::fromInt(context->tx().nVersion()).value();
                                    stack.push_back(bn.getvch());
                                } break;
                                case OP_TXINPUTCOUNT: {
                                    auto const bn = CScriptNum::fromInt(context->tx().vin().size()).value();
                                    stack.push_back(bn.getvch());
                                } break;
                                case OP_TXOUTPUTCOUNT: {
                                    auto const bn = CScriptNum::fromInt(context->tx().vout().size()).value();
                                    stack.push_back(bn.getvch());
                                } break;
                                case OP_TXLOCKTIME: {
                                    auto const bn = CScriptNum::fromInt(context->tx().nLockTime()).value();
                                    stack.push_back(bn.getvch());
                                } break;
                                default: {
                                    assert(!"invalid opcode");
                                    break;
                                }
                            }
                            // Tally push cost
                            metrics.TallyPushOp(stack.back().size());
                        } break; // end of Native Introspection opcodes (Nullary)

                        // Native Introspection opcodes (Unary)
                        case OP_UTXOTOKENCATEGORY:
                        case OP_UTXOTOKENCOMMITMENT:
                        case OP_UTXOTOKENAMOUNT:
                        case OP_OUTPUTTOKENCATEGORY:
                        case OP_OUTPUTTOKENCOMMITMENT:
                        case OP_OUTPUTTOKENAMOUNT:
                            // These require native tokens (upgrade9)
                            if ( ! nativeTokens) {
                                return set_error(serror, ScriptError::BAD_OPCODE);
                            }
                            [[fallthrough]];
                        case OP_UTXOVALUE:
                        case OP_UTXOBYTECODE:
                        case OP_OUTPOINTTXHASH:
                        case OP_OUTPOINTINDEX:
                        case OP_INPUTBYTECODE:
                        case OP_INPUTSEQUENCENUMBER:
                        case OP_OUTPUTVALUE:
                        case OP_OUTPUTBYTECODE: {
                            if ( ! context) {
                                return set_error(serror, ScriptError::CONTEXT_NOT_PRESENT);
                            }

                            // (in -- out)
                            if (stack.size() < 1) {
                                return set_error(serror, ScriptError::INVALID_STACK_OPERATION);
                            }
                            auto const index = CScriptNum(stacktop(-1), fRequireMinimal, maxIntegerSizeLegacy).getint64();
                            popstack(stack); // consume element

                            auto is_valid_input_index = [&] {
                                if (index < 0 || uint64_t(index) >= context->tx().vin().size()) {
                                    return set_error(serror, ScriptError::INVALID_TX_INPUT_INDEX);
                                }
                                return true;
                            };
                            auto is_valid_output_index = [&] {
                                if (index < 0 || uint64_t(index) >= context->tx().vout().size()) {
                                    return set_error(serror, ScriptError::INVALID_TX_OUTPUT_INDEX);
                                }
                                return true;
                            };
                            auto get_bytecode = [&nativeTokens](const CTxOut &txout) -> std::vector<uint8_t> {
                                std::vector<uint8_t> ret;
                                if (!nativeTokens && txout.tokenDataPtr) {
                                    // Special pre-activation case for upgrade9; If they ask for the bytecode, and
                                    // there is PATFO token data we must return what a naive node would return here:
                                    // The full serialized spk blob pre-activation [TOKEN_PREFIX + tokenData + spk]
                                    token::WrappedScriptPubKey wspk;
                                    token::WrapScriptPubKey(wspk, txout.tokenDataPtr, txout.scriptPubKey, INIT_PROTO_VERSION);
                                    ret.assign(wspk.begin(), wspk.end());
                                } else {
                                    // Post-activation or if no PATFO token data; Return just the scriptPubKey.
                                    ret.assign(txout.scriptPubKey.begin(), txout.scriptPubKey.end());
                                }
                                return ret;
                            };

                            switch (opcode) {
                                case OP_UTXOVALUE: {
                                    if ( ! is_valid_input_index()) {
                                        return false; // serror set by is_invalid_input_index lambda
                                    }
                                    if (context->isLimited() && uint64_t(index) != context->inputIndex()) {
                                        // This branch can only happen in tests or other non-consensus code
                                        // that calls the VM without all the *other* inputs' coins.
                                        return set_error(serror, ScriptError::LIMITED_CONTEXT_NO_SIBLING_INFO);
                                    }
                                    auto const bn = CScriptNum::fromInt(context->coinAmount(index) / SATOSHI).value();
                                    stack.push_back(bn.getvch());
                                } break;

                                case OP_UTXOBYTECODE: {
                                    if ( ! is_valid_input_index()) {
                                        return false; // serror set by is_invalid_input_index lambda
                                    }
                                    if (context->isLimited() && uint64_t(index) != context->inputIndex()) {
                                        // This branch can only happen in tests or other non-consensus code
                                        // that calls the VM without all the *other* inputs' coins.
                                        return set_error(serror, ScriptError::LIMITED_CONTEXT_NO_SIBLING_INFO);
                                    }
                                    auto utxoScript = get_bytecode(context->coin(index).GetTxOut());
                                    if (utxoScript.size() > maxScriptElementSize) {
                                        return set_error(serror, ScriptError::PUSH_SIZE);
                                    }
                                    stack.push_back(std::move(utxoScript));
                                } break;

                                case OP_OUTPOINTTXHASH: {
                                    if ( ! is_valid_input_index()) {
                                        return false; // serror set by is_invalid_input_index lambda
                                    }
                                    auto const& input = context->tx().vin()[index];
                                    auto const& txid = input.prevout.GetTxId();
                                    static_assert(TxId::size() <= std::min(MAX_SCRIPT_ELEMENT_SIZE_LEGACY, may2025::MAX_SCRIPT_ELEMENT_SIZE));
                                    stack.emplace_back(txid.begin(), txid.end());
                                } break;

                                case OP_OUTPOINTINDEX: {
                                    if ( ! is_valid_input_index()) {
                                        return false; // serror set by is_invalid_input_index lambda
                                    }
                                    auto const& input = context->tx().vin()[index];
                                    auto const bn = CScriptNum::fromInt(input.prevout.GetN()).value();
                                    stack.push_back(bn.getvch());
                                } break;

                                case OP_INPUTBYTECODE: {
                                    if ( ! is_valid_input_index()) {
                                        return false; // serror set by is_invalid_input_index lambda
                                    }
                                    auto const& inputScript = context->scriptSig(index);
                                    if (inputScript.size() > maxScriptElementSize) {
                                        return set_error(serror, ScriptError::PUSH_SIZE);
                                    }
                                    stack.emplace_back(inputScript.begin(), inputScript.end());
                                } break;

                                case OP_INPUTSEQUENCENUMBER: {
                                    if ( ! is_valid_input_index()) {
                                        return false; // serror set by is_invalid_input_index lambda
                                    }
                                    auto const& input = context->tx().vin()[index];
                                    auto const bn = CScriptNum::fromInt(input.nSequence).value();
                                    stack.push_back(bn.getvch());
                                } break;

                                case OP_OUTPUTVALUE: {
                                    if ( ! is_valid_output_index()) {
                                        return false; // serror set by is_invalid_output_index lambda
                                    }
                                    auto const& output = context->tx().vout()[index];
                                    auto const bn = CScriptNum::fromInt(output.nValue / SATOSHI).value();
                                    stack.push_back(bn.getvch());
                                } break;

                                case OP_OUTPUTBYTECODE: {
                                    if ( ! is_valid_output_index()) {
                                        return false; // serror set by is_invalid_output_index lambda
                                    }
                                    auto outputScript = get_bytecode(context->tx().vout()[index]);
                                    if (outputScript.size() > maxScriptElementSize) {
                                        return set_error(serror, ScriptError::PUSH_SIZE);
                                    }
                                    stack.push_back(std::move(outputScript));
                                } break;

                                // Token introspection
                                case OP_UTXOTOKENCATEGORY: {
                                    if ( ! is_valid_input_index()) {
                                        return false; // serror set by is_invalid_input_index lambda
                                    }
                                    if (context->isLimited() && uint64_t(index) != context->inputIndex()) {
                                        // This branch can only happen in tests or other non-consensus code
                                        // that calls the VM without all the *other* inputs' coins.
                                        return set_error(serror, ScriptError::LIMITED_CONTEXT_NO_SIBLING_INFO);
                                    }
                                    if (const auto &pdata = context->coinTokenData(index); !pdata) {
                                        // no token data, push CScriptNum 0 (empty vec)
                                        stack.push_back(CScriptNum::fromIntUnchecked(0).getvch());
                                    } else {
                                        // has token data, push token id (32 bytes) + *maybe* 0x1 or 0x2 (1 byte)
                                        const auto &tokId = pdata->GetId();
                                        valtype vch;
                                        // only push the capability if it's one of: 0x1 (mutable) or 0x2 (minting)
                                        const bool pushCapByte = pdata->IsMintingNFT() || pdata->IsMutableNFT();
                                        vch.reserve(tokId.size() + pushCapByte);
                                        vch.insert(vch.end(), tokId.begin(), tokId.end());
                                        if (pushCapByte) vch.push_back(static_cast<uint8_t>(pdata->GetCapability()));
                                        if (vch.size() > maxScriptElementSize) {
                                            // This branch cannot be taken in the current code, but is left in defensively.
                                            return set_error(serror, ScriptError::PUSH_SIZE);
                                        }
                                        stack.push_back(std::move(vch));
                                    }
                                } break;

                                case OP_UTXOTOKENCOMMITMENT: {
                                    if ( ! is_valid_input_index()) {
                                        return false; // serror set by is_invalid_input_index lambda
                                    }
                                    if (context->isLimited() && uint64_t(index) != context->inputIndex()) {
                                        // This branch can only happen in tests or other non-consensus code
                                        // that calls the VM without all the *other* inputs' coins.
                                        return set_error(serror, ScriptError::LIMITED_CONTEXT_NO_SIBLING_INFO);
                                    }
                                    if (const auto &pdata = context->coinTokenData(index); !pdata || !pdata->HasNFT()) {
                                        // no token data, or has token data but is not an NFT, push CScriptNum 0 (empty vec)
                                        stack.push_back(CScriptNum::fromIntUnchecked(0).getvch());
                                    } else {
                                        // Has token data, push commitment bytes, if they are <= MAX_SCRIPT_ELEMENT_SIZE_*
                                        const auto &commitment = pdata->GetCommitment();
                                        if (commitment.size() > maxScriptElementSize) {
                                            // This branch can normally only be taken in tests
                                            return set_error(serror, ScriptError::PUSH_SIZE);
                                        }
                                        // Push the bytes verbatim to the stack
                                        stack.emplace_back(commitment.begin(), commitment.end());
                                    }
                                } break;

                                case OP_UTXOTOKENAMOUNT: {
                                    if ( ! is_valid_input_index()) {
                                        return false; // serror set by is_invalid_input_index lambda
                                    }
                                    if (context->isLimited() && uint64_t(index) != context->inputIndex()) {
                                        // This branch can only happen in tests or other non-consensus code
                                        // that calls the VM without all the *other* inputs' coins.
                                        return set_error(serror, ScriptError::LIMITED_CONTEXT_NO_SIBLING_INFO);
                                    }
                                    if (const auto &pdata = context->coinTokenData(index); !pdata) {
                                        // no token data, push VM number 0 (empty vector)
                                        stack.push_back(CScriptNum::fromIntUnchecked(0).getvch());
                                    } else {
                                        // push the amount as a CScriptNum amount. Note it can be zero for NFT-only
                                        // tokens, in which case an empty vector {} will be pushed.
                                        auto const bn = CScriptNum::fromInt(pdata->GetAmount().getint64()).value();
                                        stack.push_back(bn.getvch());
                                    }
                                } break;

                                case OP_OUTPUTTOKENCATEGORY: {
                                    if ( ! is_valid_output_index()) {
                                        return false; // serror set by is_invalid_output_index lambda
                                    }
                                    auto const& output = context->tx().vout()[index];
                                    if (const auto &pdata = output.tokenDataPtr; !pdata) {
                                        // no token data, push CScriptNum 0 (empty vec)
                                        stack.push_back(CScriptNum::fromIntUnchecked(0).getvch());
                                    } else {
                                        // has token data, push token id (32 bytes) + *maybe* 0x1 or 0x2 (1 byte)
                                        const auto &tokId = pdata->GetId();
                                        valtype vch;
                                        // only push the capability if it's one of: 0x1 (mutable) or 0x2 (minting)
                                        const bool pushCapByte = pdata->IsMintingNFT() || pdata->IsMutableNFT();
                                        vch.reserve(tokId.size() + pushCapByte);
                                        vch.insert(vch.end(), tokId.begin(), tokId.end());
                                        if (pushCapByte) vch.push_back(static_cast<uint8_t>(pdata->GetCapability()));
                                        if (vch.size() > maxScriptElementSize) {
                                            // This branch cannot be taken in the current code, but is left in defensively.
                                            return set_error(serror, ScriptError::PUSH_SIZE);
                                        }
                                        stack.push_back(std::move(vch));
                                    }
                                } break;

                                case OP_OUTPUTTOKENCOMMITMENT: {
                                    if ( ! is_valid_output_index()) {
                                        return false; // serror set by is_invalid_output_index lambda
                                    }
                                    auto const& output = context->tx().vout()[index];
                                    if (const auto &pdata = output.tokenDataPtr; !pdata || !pdata->HasNFT()) {
                                        // no token data, or has token data but is not an NFT, push CScriptNum 0 (empty vec)
                                        stack.push_back(CScriptNum::fromIntUnchecked(0).getvch());
                                    } else {
                                        // Has token data, push commitment bytes, if they are <= MAX_SCRIPT_ELEMENT_SIZE_*
                                        const auto &commitment = pdata->GetCommitment();
                                        if (commitment.size() > maxScriptElementSize) {
                                            // This branch can normally only be taken in tests
                                            return set_error(serror, ScriptError::PUSH_SIZE);
                                        }
                                        // Push the bytes verbatim to the stack
                                        stack.emplace_back(commitment.begin(), commitment.end());
                                    }
                                } break;

                                case OP_OUTPUTTOKENAMOUNT: {
                                    if ( ! is_valid_output_index()) {
                                        return false; // serror set by is_invalid_output_index lambda
                                    }
                                    auto const& output = context->tx().vout()[index];
                                    if (const auto &pdata = output.tokenDataPtr; !pdata) {
                                        // no token data, push VM number 0 (empty vector)
                                        stack.push_back(CScriptNum::fromIntUnchecked(0).getvch());
                                    } else {
                                        // push the amount as a CScriptNum amount. Note it can be zero for NFT-only
                                        // tokens, in which case an empty vector {} will be pushed.
                                        auto const bn = CScriptNum::fromInt(pdata->GetAmount().getint64()).value();
                                        stack.push_back(bn.getvch());
                                    }
                                } break;

                                default: {
                                    assert(!"invalid opcode");
                                    break;
                                }
                            }
                            // Tally push cost
                            metrics.TallyPushOp(stack.back().size());
                        } break; // end of Native Introspection opcodes (Unary)

                        default:
                            return set_error(serror, ScriptError::BAD_OPCODE);
                    } // end switch (opcode)
                } // end if (vfExec)

                // Size limits
                if (stack.size() + altstack.size() + functionTable.size() > MAX_STACK_SIZE) {
                    return set_error(serror, ScriptError::STACK_SIZE);
                }

                // Enforce May 2025 VM limits
                if (chipVmLimitsEnabled) {
                    // Check that this opcode did not cause us to exceed opCost and/or hashIters limits.
                    // Note: `metrics` may lack a valid "scriptLimits" object in rare cases (tests only), in which case
                    // the below two limit checks are always going to return false.
                    if (metrics.IsOverOpCostLimit(flags)) {
                        return set_error(serror, ScriptError::OP_COST);
                    }
                    if (metrics.IsOverHashItersLimit()) {
                        return set_error(serror, ScriptError::TOO_MANY_HASH_ITERS);
                    }

                    // Conditional stack may not exceed depth of 100.
                    if (!may2026Enabled && curFrame.vfExec.size() > may2025::MAX_CONDITIONAL_STACK_DEPTH) {
                        return set_error(serror, ScriptError::CONDITIONAL_STACK_DEPTH);
                    }
                }

                // Enforce May 2026 rules
                if (may2026Enabled) {
                    // Total control stack depth (cum. vfExec + num. OP_INVOKE control stack frames) may not exceed 100.
                    if (evalStack.depth() > may2026::MAX_CONTROL_STACK_DEPTH) {
                        return set_error(serror, ScriptError::CONTROL_STACK_DEPTH);
                    }
                }
            } // end while(pc < pend && !newEvalFrameWasPushed)

            if (newEvalFrameWasPushed) {
                assert(!evalStack.empty() && &evalStack.top() != &curFrame); // invariant must hold if we get here
                // jump to end of outer `do` loop
                continue;
            }

            // Either the top-most `initialScript` has an unbalanced control flow, or an OP_INVOKE'd inner script does;
            // this is disallowed.
            if (!curFrame.vfExec.empty()) {
                return set_error(serror, ScriptError::UNBALANCED_CONDITIONAL);
            }
            if (!curFrame.controlStack.empty()) {
                return set_error(serror, ScriptError::UNBALANCED_CONTROL_FLOW);
            }

            // End of either `initialScript` or of an OP_INVOKE'd inner script, pop this frame.
            // Note that this invalidates refs to: `curFrame`, `pc`, `pbegincodehash`, `pend`
            evalStack.popFrame();

        } while (!evalStack.empty()); // end outer do loop
    } catch (const ScriptEvaluationError &e) {
        return set_error(serror, e.scriptError);
    } catch (...) {
        return set_error(serror, ScriptError::UNKNOWN);
    }

    return set_success(serror);
}

/**
 * Wrapper that serializes like CTransaction, but with the modifications
 *  required for the signature hash done in-place
 */
class CTransactionViewSignatureSerializer {
    //! reference to the spending transaction (the one being serialized)
    const CTransactionView txTo;
    //! output script being consumed
    const ByteView scriptCode;
    //! input index of txTo being signed
    const unsigned int nIn;
    //! container for hashtype flags
    const SigHashType sigHashType;

public:
    CTransactionViewSignatureSerializer(CTransactionView txToIn, const ByteView &scriptCodeIn, unsigned nInIn,
                                        SigHashType sigHashTypeIn)
        : txTo(txToIn), scriptCode(scriptCodeIn), nIn(nInIn), sigHashType(sigHashTypeIn) {}

    /** Serialize the passed scriptCode, skipping OP_CODESEPARATORs */
    template <typename S> void SerializeScriptCode(S &s) const {
        const uint8_t *it = scriptCode.data(), *itBegin = it, * const end = scriptCode.data() + scriptCode.size();
        opcodetype opcode;
        unsigned int nCodeSeparators = 0;
        while (GetScriptOp(it, end, opcode, nullptr)) {
            if (opcode == OP_CODESEPARATOR) {
                ++nCodeSeparators;
            }
        }
        ::WriteCompactSize(s, scriptCode.size() - nCodeSeparators);
        it = itBegin;
        while (GetScriptOp(it, end, opcode, nullptr)) {
            if (opcode == OP_CODESEPARATOR) {
                s.write((char *)&itBegin[0], it - itBegin - 1);
                itBegin = it;
            }
        }
        if (itBegin != end) {
            s.write((char *)&itBegin[0], it - itBegin);
        }
    }

    /** Serialize an input of txTo */
    template <typename S> void SerializeInput(S &s, unsigned int nInput) const {
        // In case of SIGHASH_ANYONECANPAY, only the input being signed is
        // serialized
        if (sigHashType.hasAnyoneCanPay()) {
            nInput = nIn;
        }
        // Serialize the prevout
        ::Serialize(s, txTo.vin()[nInput].prevout);
        // Serialize the script
        if (nInput != nIn) {
            // Blank out other inputs' signatures
            ::Serialize(s, CScript());
        } else {
            SerializeScriptCode(s);
        }
        // Serialize the nSequence
        if (nInput != nIn &&
            (sigHashType.getBaseType() == BaseSigHashType::SINGLE ||
             sigHashType.getBaseType() == BaseSigHashType::NONE)) {
            // let the others update at will
            ::Serialize(s, (int)0);
        } else {
            ::Serialize(s, txTo.vin()[nInput].nSequence);
        }
    }

    /** Serialize an output of txTo */
    template <typename S>
    void SerializeOutput(S &s, unsigned int nOutput) const {
        if (sigHashType.getBaseType() == BaseSigHashType::SINGLE && nOutput != nIn) {
            // Do not lock-in the txout payee at other indices as txin
            ::Serialize(s, CTxOut());
        } else {
            ::Serialize(s, txTo.vout()[nOutput]);
        }
    }

    /** Serialize txTo */
    template <typename S> void Serialize(S &s) const {
        // Serialize nVersion
        ::Serialize(s, txTo.nVersion());
        // Serialize vin
        unsigned int nInputs =
            sigHashType.hasAnyoneCanPay() ? 1 : txTo.vin().size();
        ::WriteCompactSize(s, nInputs);
        for (unsigned int nInput = 0; nInput < nInputs; nInput++) {
            SerializeInput(s, nInput);
        }
        // Serialize vout
        unsigned int nOutputs =
            (sigHashType.getBaseType() == BaseSigHashType::NONE)
                ? 0
                : ((sigHashType.getBaseType() == BaseSigHashType::SINGLE)
                       ? nIn + 1
                       : txTo.vout().size());
        ::WriteCompactSize(s, nOutputs);
        for (unsigned int nOutput = 0; nOutput < nOutputs; ++nOutput) {
            SerializeOutput(s, nOutput);
        }
        // Serialize nLockTime
        ::Serialize(s, txTo.nLockTime());
    }
};

uint256 GetPrevoutHash(const ScriptExecutionContext &context) {
    CHashWriter ss(SER_GETHASH, 0);
    for (const auto &txin : context.tx().vin()) {
        ss << txin.prevout;
    }
    return ss.GetHash();
}

uint256 GetSequenceHash(const ScriptExecutionContext &context) {
    CHashWriter ss(SER_GETHASH, 0);
    for (const auto &txin : context.tx().vin()) {
        ss << txin.nSequence;
    }
    return ss.GetHash();
}

uint256 GetOutputsHash(const ScriptExecutionContext &context) {
    CHashWriter ss(SER_GETHASH, 0);
    for (const auto &txout : context.tx().vout()) {
        ss << txout;
    }
    return ss.GetHash();
}

uint256 GetUtxosHash(const ScriptExecutionContext &context) {
    assert(!context.isLimited());
    const size_t nInputs = context.tx().vin().size();
    CHashWriter ss(SER_GETHASH, 0);
    for (size_t i = 0; i < nInputs; ++i) {
        const Coin &coin = context.coin(i);
        ss << coin.GetTxOut();
    }
    return ss.GetHash();
}

} // namespace

void PrecomputedTransactionData::PopulateFromContext(const ScriptExecutionContext &context) {
    hashPrevouts = GetPrevoutHash(context);
    hashSequence = GetSequenceHash(context);
    hashOutputs = GetOutputsHash(context);
    if (!context.isLimited()) {
        hashUtxos = GetUtxosHash(context);
    } else {
        hashUtxos.reset();
    }
    populated = true;
}

SignatureHashResult SignatureHash(const ByteView &scriptCode, const ScriptExecutionContext &context,
                                  SigHashType sigHashType, const PrecomputedTransactionData *cache, uint32_t flags) {
    const unsigned nIn = context.inputIndex();
    const CTransactionView &txTo = context.tx();
    assert(nIn < txTo.vin().size());

    if (sigHashType.hasFork() && (flags & SCRIPT_ENABLE_SIGHASH_FORKID)) {
        uint256 hashPrevouts;
        uint256 hashSequence;
        uint256 hashOutputs;
        std::optional<uint256> hashUtxos;

        if (!sigHashType.hasAnyoneCanPay()) {
            hashPrevouts = cache ? cache->hashPrevouts : GetPrevoutHash(context);
        }

        if (!sigHashType.hasAnyoneCanPay() && sigHashType.getBaseType() != BaseSigHashType::SINGLE
            && sigHashType.getBaseType() != BaseSigHashType::NONE) {
            hashSequence = cache ? cache->hashSequence : GetSequenceHash(context);
        }

        if (sigHashType.hasUtxos() && (flags & SCRIPT_ENABLE_TOKENS)) {
            if (cache && cache->hashUtxos) {
                hashUtxos = *cache->hashUtxos;
            } else if (!context.isLimited()) {
                hashUtxos = GetUtxosHash(context);
            }
        }

        if (const auto bt = sigHashType.getBaseType(); bt != BaseSigHashType::SINGLE && bt != BaseSigHashType::NONE) {
            hashOutputs = cache ? cache->hashOutputs : GetOutputsHash(context);
        } else if (bt == BaseSigHashType::SINGLE && nIn < txTo.vout().size()) {
            CHashWriter ss(SER_GETHASH, 0);
            ss << txTo.vout()[nIn];
            hashOutputs = ss.GetHash();
        }

        CHashWriter ss(SER_GETHASH, 0);
        // Version
        ss << txTo.nVersion();
        // Input prevouts/nSequence (none/all, depending on flags)
        ss << hashPrevouts;
        // SIGHASH_UTXOS requires Upgrade9 SCRIPT_ENABLE_TOKENS, otherwise skip
        if (sigHashType.hasUtxos() && (flags & SCRIPT_ENABLE_TOKENS)) {
            if (!hashUtxos) {
                // This should never happen in production because in production we have real "non limited" contexts.
                throw SignatureHashMissingUtxoDataError(
                    strprintf("SignatureHash error: SIGHASH_UTXOS requested but missing utxo data,"
                              " txid: %s, inputNum: %i", txTo.GetId().ToString(), nIn));
            }
            ss << *hashUtxos;
        }
        ss << hashSequence;
        // The input being signed (replacing the scriptSig with [tokenBlob?] + scriptCode + amount). The prevout may
        // already be contained in hashPrevout, and the nSequence may already be contained in hashSequence.
        ss << txTo.vin()[nIn].prevout;
        const CTxOut &prevTxOut = context.coin().GetTxOut();
        if (prevTxOut.tokenDataPtr && (flags & SCRIPT_ENABLE_TOKENS)) {
            // New! For tokens (Upgrade9). If we had tokenData we inject it as a blob of:
            //    token::PREFIX_BYTE + ser_token_data
            // right *before* scriptCode's length byte.  This *intentionally* makes it so that unupgraded software
            // cannot send tokens (and thus cannot unintentionally burn tokens).
            //
            // Note: The serialization operation for token::OutputData may throw if the data it is serializing is not
            // sane.  The data will always be sane when verifying or producing sigs in production. However, the below
            // may throw in tests that intentionally sabotage the tokenData to be inconsistent.
            ss << token::PREFIX_BYTE << *prevTxOut.tokenDataPtr;
        }
        WriteCompactSize(ss, scriptCode.size());
        ss << scriptCode;
        ss << prevTxOut.nValue;
        ss << txTo.vin()[nIn].nSequence;
        // Outputs (none/one/all, depending on flags)
        ss << hashOutputs;
        // Locktime
        ss << txTo.nLockTime();
        // Sighash type
        ss << sigHashType;

        return {ss.GetHash(), ss.GetNumBytesWritten()};
    }

    // Check for invalid use of SIGHASH_SINGLE
    if (sigHashType.getBaseType() == BaseSigHashType::SINGLE && nIn >= txTo.vout().size()) {
        //  nOut out of range
        static const uint256 one(uint256S("0000000000000000000000000000000000000000000000000000000000000001"));
        return {one, 0u};
    }

    // Wrapper to serialize only the necessary parts of the transaction being
    // signed
    const CTransactionViewSignatureSerializer txTmp(txTo, scriptCode, nIn, sigHashType);

    // Serialize and hash
    CHashWriter ss(SER_GETHASH, 0);
    ss << txTmp << sigHashType;
    return {ss.GetHash(), ss.GetNumBytesWritten()};
}

bool BaseSignatureChecker::VerifySignature(const ByteView &vchSig,
                                           const CPubKey &pubkey,
                                           const uint256 &sighash) const {
    if (vchSig.size() == 64) {
        return pubkey.VerifySchnorr(sighash, vchSig);
    } else {
        return pubkey.VerifyECDSA(sighash, vchSig);
    }
}

ContextOptSignatureChecker::~ContextOptSignatureChecker() {}

bool TransactionSignatureChecker::CheckSig(const ByteView &vchSigIn, const std::vector<uint8_t> &vchPubKey,
                                           const ByteView &scriptCode, uint32_t flags, size_t *pnBytesHashed) const {
    if (pnBytesHashed) *pnBytesHashed = 0u;
    CPubKey const pubkey(vchPubKey);
    if (!pubkey.IsValid()) {
        return false;
    }

    // Hash type is one byte tacked on to the end of the signature
    ByteView vchSig(vchSigIn);
    if (vchSig.empty()) {
        return false;
    }
    SigHashType const sigHashType = GetHashType(vchSig);
    vchSig = vchSig.first(vchSig.size() - 1u); // pop_back()

    const auto & [sighash, bytesHashed] = SignatureHash(scriptCode, context, sigHashType, this->txdata, flags);
    if (pnBytesHashed) *pnBytesHashed = bytesHashed;

    return VerifySignature(vchSig, pubkey, sighash);
}

bool TransactionSignatureChecker::CheckLockTime(const CScriptNum &nLockTime) const {
    const CTransactionView &txTo = context.tx();
    const unsigned nIn = context.inputIndex();
    // There are two kinds of nLockTime: lock-by-blockheight and
    // lock-by-blocktime, distinguished by whether nLockTime <
    // LOCKTIME_THRESHOLD.
    //
    // We want to compare apples to apples, so fail the script unless the type
    // of nLockTime being tested is the same as the nLockTime in the
    // transaction.
    if (!((txTo.nLockTime() < LOCKTIME_THRESHOLD && nLockTime < LOCKTIME_THRESHOLD)
          || (txTo.nLockTime() >= LOCKTIME_THRESHOLD && nLockTime >= LOCKTIME_THRESHOLD))) {
        return false;
    }

    // Now that we know we're comparing apples-to-apples, the comparison is a
    // simple numeric one.
    if (nLockTime > static_cast<int64_t>(txTo.nLockTime())) { // CScriptNum has many overloads - ensure the right one is selected
        return false;
    }

    // Finally the nLockTime feature can be disabled and thus
    // CHECKLOCKTIMEVERIFY bypassed if every txin has been finalized by setting
    // nSequence to maxint. The transaction would be allowed into the
    // blockchain, making the opcode ineffective.
    //
    // Testing if this vin is not final is sufficient to prevent this condition.
    // Alternatively we could test all inputs, but testing just this input
    // minimizes the data required to prove correct CHECKLOCKTIMEVERIFY
    // execution.
    if (CTxIn::SEQUENCE_FINAL == txTo.vin()[nIn].nSequence) {
        return false;
    }

    return true;
}

bool TransactionSignatureChecker::CheckSequence(const CScriptNum &nSequence) const {
    const CTransactionView &txTo = context.tx();
    const unsigned nIn = context.inputIndex();
    // Relative lock times are supported by comparing the passed in operand to
    // the sequence number of the input.
    const int64_t txToSequence = static_cast<int64_t>(txTo.vin()[nIn].nSequence);

    // Fail if the transaction's version number is not set high enough to
    // trigger BIP 68 rules.
    if (static_cast<uint32_t>(txTo.nVersion()) < 2u) {
        return false;
    }

    // Sequence numbers with their most significant bit set are not consensus
    // constrained. Testing that the transaction's sequence number do not have
    // this bit set prevents using this property to get around a
    // CHECKSEQUENCEVERIFY check.
    if (txToSequence & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG) {
        return false;
    }

    // Mask off any bits that do not have consensus-enforced meaning before
    // doing the integer comparisons
    const uint32_t nLockTimeMask = CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG | CTxIn::SEQUENCE_LOCKTIME_MASK;
    const int64_t txToSequenceMasked = txToSequence & nLockTimeMask;

    auto const res = nSequence.safeBitwiseAnd(nLockTimeMask);
    if ( ! res) {
        // Defensive programming: It is impossible that this branch be taken unless the current
        // values of the operands are changed.
        return false;
    }
    auto const nSequenceMasked = *res;

    // There are two kinds of nSequence: lock-by-blockheight and
    // lock-by-blocktime, distinguished by whether nSequenceMasked <
    // CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG.
    //
    // We want to compare apples to apples, so fail the script unless the type
    // of nSequenceMasked being tested is the same as the nSequenceMasked in the
    // transaction.
    if (!((txToSequenceMasked < CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG &&
           nSequenceMasked < CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG) ||
          (txToSequenceMasked >= CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG &&
           nSequenceMasked >= CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG))) {
        return false;
    }

    // Now that we know we're comparing apples-to-apples, the comparison is a
    // simple numeric one.
    if (nSequenceMasked > txToSequenceMasked) {
        return false;
    }

    return true;
}

bool EvalScript(std::vector<valtype> &stack, const CScript &script, uint32_t flags,
                const BaseSignatureChecker &checker, ScriptExecutionMetrics &metrics, ScriptError *serror) {
    if (flags & SCRIPT_ENABLE_MAY2025) {
        return EvalScriptImpl<true>(stack, script, flags, checker, metrics, serror);
    } else {
        return EvalScriptImpl<false>(stack, script, flags, checker, metrics, serror);
    }
}

bool VerifyScript(const CScript &scriptSig, const CScript &scriptPubKey, uint32_t flags, const BaseSignatureChecker &checker,
                  ScriptExecutionMetrics &metricsOut, ScriptError *serror) {
    set_error(serror, ScriptError::UNKNOWN);

    // If FORKID is enabled, we also ensure strict encoding.
    if (flags & SCRIPT_ENABLE_SIGHASH_FORKID) {
        flags |= SCRIPT_VERIFY_STRICTENC;
    }

    bool scriptSigIsKnownToBePushOnly{}; ///< If true, we tested the scriptSig already and it satisfies: `IsPushOnly()`
    if (flags & SCRIPT_VERIFY_SIGPUSHONLY && !(scriptSigIsKnownToBePushOnly = scriptSig.IsPushOnly())) {
        return set_error(serror, ScriptError::SIG_PUSHONLY);
    }

    ScriptExecutionMetrics metrics = {};

    if (flags & SCRIPT_ENABLE_MAY2025) {
        // May 2025: Pre-set metrics.scriptLimits to enforce op cost limits.
        metrics.SetScriptLimits(flags, scriptSig.size());
    }

    std::vector<valtype> stack, stackCopy;
    if ( ! EvalScript(stack, scriptSig, flags, checker, metrics, serror)) {
        // serror is set
        return false;
    }
    bool p2sh_32{};
    const bool is_p2sh = flags & SCRIPT_VERIFY_P2SH && scriptPubKey.IsPayToScriptHash(flags, nullptr, &p2sh_32);
    if (is_p2sh) {
        // For p2sh, take a copy of the scriptSig resultant stack now; we will need it later for the second evaluation.
        stackCopy = stack;
    }
    if ( ! EvalScript(stack, scriptPubKey, flags, checker, metrics, serror)) {
        // serror is set
        return false;
    }
    if (stack.empty() || !CastToBool(stack.back())) {
        return set_error(serror, ScriptError::EVAL_FALSE);
    }

    // Additional validation for spend-to-script-hash transactions:
    if (is_p2sh) {
        // scriptSig must be literals-only or validation fails
        if (!scriptSigIsKnownToBePushOnly && !scriptSig.IsPushOnly()) {
            return set_error(serror, ScriptError::SIG_PUSHONLY);
        }

        // Restore stack.
        swap(stack, stackCopy);

        // stack cannot be empty here, because if it was the P2SH  HASH <> EQUAL
        // scriptPubKey would be evaluated with an empty stack and the
        // EvalScript above would return false.
        assert(!stack.empty());

        const CScript pubKey2(stack.back().begin(), stack.back().end());
        popstack(stack);

        // Bail out early if SCRIPT_DISALLOW_SEGWIT_RECOVERY is not set, the
        // redeem script is a p2sh_20 segwit program, and it was the only item
        // pushed onto the stack.
        //
        // Note; We *never* allow this "unconditional" segwit recovery for
        // p2sh_32 since segwit funds can only be inadvertently locked into
        // p2sh_20 (legacy BTC) scripts, thus this special case for segwit
        // recovery should never apply to p2sh_32.
        if ((flags & SCRIPT_DISALLOW_SEGWIT_RECOVERY) == 0 && !p2sh_32 && stack.empty() && pubKey2.IsWitnessProgram()) {
            // must set metricsOut for all successful returns
            metricsOut = metrics;
            return set_success(serror);
        }

        if ( ! EvalScript(stack, pubKey2, flags, checker, metrics, serror)) {
            // serror is set
            return false;
        }
        if (stack.empty() || !CastToBool(stack.back())) {
            return set_error(serror, ScriptError::EVAL_FALSE);
        }
    }

    // The CLEANSTACK check is only performed after potential P2SH evaluation,
    // as the non-P2SH evaluation of a P2SH script will obviously not result in
    // a clean stack (the P2SH inputs remain). The same holds for witness
    // evaluation.
    if ((flags & SCRIPT_VERIFY_CLEANSTACK) != 0) {
        // Disallow CLEANSTACK without P2SH, as otherwise a switch
        // CLEANSTACK->P2SH+CLEANSTACK would be possible, which is not a
        // softfork (and P2SH should be one).
        assert((flags & SCRIPT_VERIFY_P2SH) != 0);
        if (stack.size() != 1) {
            return set_error(serror, ScriptError::CLEANSTACK);
        }
    }

    if (flags & SCRIPT_VERIFY_INPUT_SIGCHECKS) {
        // This limit is intended for standard use, and is based on an
        // examination of typical and historical standard uses.
        // - allowing P2SH ECDSA multisig with compressed keys, which at an
        // extreme (1-of-15) may have 15 SigChecks in ~590 bytes of scriptSig.
        // - allowing Bare ECDSA multisig, which at an extreme (1-of-3) may have
        // 3 sigchecks in ~72 bytes of scriptSig.
        // - Since the size of an input is 41 bytes + length of scriptSig, then
        // the most dense possible inputs satisfying this rule would be:
        //   2 sigchecks and 26 bytes: 1/33.50 sigchecks/byte.
        //   3 sigchecks and 69 bytes: 1/36.66 sigchecks/byte.
        // The latter can be readily done with 1-of-3 bare multisignatures,
        // however the former is not practically doable with standard scripts,
        // so the practical density limit is 1/36.66.
        static_assert(std::in_range<int>(MAX_SCRIPT_SIZE), "overflow sanity check on max script size");
        static_assert(std::numeric_limits<int>::max() / 43 / 3 > MAX_OPS_PER_SCRIPT_LEGACY,
                      "overflow sanity check on maximum possible sigchecks from sig+redeem+pub scripts");
        if (static_cast<int>(scriptSig.size()) < metrics.GetSigChecks() * 43 - 60) {
            return set_error(serror, ScriptError::INPUT_SIGCHECKS);
        }
    }

    metricsOut = metrics;
    return set_success(serror);
}
