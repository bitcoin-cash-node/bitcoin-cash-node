// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017-2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <crypto/common.h>
#include <prevector.h>
#include <script/bigint.h>
#include <script/container_types.h>
#include <script/script_error.h>
#include <script/script_num_encoding.h>
#include <script/vm_limits.h> // for constants MAX_SCRIPT_SIZE, MAX_STACK_SIZE, etc
#include <serialize.h>

#include <bit>
#include <cassert>
#include <climits>
#include <compare>
#include <cstdint>
#include <cstring>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

/** Script opcodes */
enum opcodetype {
    // push value
    OP_0 = 0x00,
    OP_FALSE = OP_0,
    OP_PUSHDATA1 = 0x4c,
    OP_PUSHDATA2 = 0x4d,
    OP_PUSHDATA4 = 0x4e,
    OP_1NEGATE = 0x4f,
    OP_RESERVED = 0x50,
    OP_1 = 0x51,
    OP_TRUE = OP_1,
    OP_2 = 0x52,
    OP_3 = 0x53,
    OP_4 = 0x54,
    OP_5 = 0x55,
    OP_6 = 0x56,
    OP_7 = 0x57,
    OP_8 = 0x58,
    OP_9 = 0x59,
    OP_10 = 0x5a,
    OP_11 = 0x5b,
    OP_12 = 0x5c,
    OP_13 = 0x5d,
    OP_14 = 0x5e,
    OP_15 = 0x5f,
    OP_16 = 0x60,

    // control
    OP_NOP = 0x61,
    OP_VER = 0x62,            // Historical (early Bitcoin)
    OP_IF = 0x63,
    OP_NOTIF = 0x64,
    /* OP_VERIF = 0x65, */    // Historical (early Bitcoin)
    /* OP_VERNOTIF = 0x66, */ // Historical (early Bitcoin)
    OP_BEGIN = 0x65,          // after upgrade12 (May 2026)
    OP_UNTIL = 0x66,          // after upgrade12 (May 2026)
    OP_ELSE = 0x67,
    OP_ENDIF = 0x68,
    OP_VERIFY = 0x69,
    OP_RETURN = 0x6a,

    // stack ops
    OP_TOALTSTACK = 0x6b,
    OP_FROMALTSTACK = 0x6c,
    OP_2DROP = 0x6d,
    OP_2DUP = 0x6e,
    OP_3DUP = 0x6f,
    OP_2OVER = 0x70,
    OP_2ROT = 0x71,
    OP_2SWAP = 0x72,
    OP_IFDUP = 0x73,
    OP_DEPTH = 0x74,
    OP_DROP = 0x75,
    OP_DUP = 0x76,
    OP_NIP = 0x77,
    OP_OVER = 0x78,
    OP_PICK = 0x79,
    OP_ROLL = 0x7a,
    OP_ROT = 0x7b,
    OP_SWAP = 0x7c,
    OP_TUCK = 0x7d,

    // splice ops
    OP_CAT = 0x7e,
    OP_SPLIT = 0x7f,   // after monolith upgrade (May 2018)
    OP_NUM2BIN = 0x80, // after monolith upgrade (May 2018)
    OP_BIN2NUM = 0x81, // after monolith upgrade (May 2018)
    OP_SIZE = 0x82,

    // bit logic
    OP_INVERT = 0x83, // after upgrade12 (May 2026); Existed in early Bitcoin before being disabled.
    OP_AND = 0x84,
    OP_OR = 0x85,
    OP_XOR = 0x86,
    OP_EQUAL = 0x87,
    OP_EQUALVERIFY = 0x88,

    // function support
    OP_DEFINE = 0x89, // after upgrade12 (May 2026), was: OP_RESERVED1
    OP_INVOKE = 0x8a, // after upgrade12 (May 2026), was: OP_RESERVED2

    // numeric
    OP_1ADD = 0x8b,
    OP_1SUB = 0x8c,
    /* OP_2MUL = 0x8d, */ // Historical (early Bitcoin)
    /* OP_2DIV = 0x8e, */ // Historical (early Bitcoin)
    OP_LSHIFTNUM = 0x8d, // after upgrade12 (May 2026); arithmetic left-shift, defined as in C++20
    OP_RSHIFTNUM = 0x8e, // after upgrade12 (May 2026); arithmetic right-shift, defined as in C++20
    OP_NEGATE = 0x8f,
    OP_ABS = 0x90,
    OP_NOT = 0x91,
    OP_0NOTEQUAL = 0x92,

    OP_ADD = 0x93,
    OP_SUB = 0x94,
    OP_MUL = 0x95,
    OP_DIV = 0x96,
    OP_MOD = 0x97,
    /* OP_LSHIFT = 0x98, */ // Historical (early Bitcoin)
    /* OP_RSHIFT = 0x99, */ // Historical (early Bitcoin)
    OP_LSHIFTBIN = 0x98, // after upgrade12 (May 2026); binary blob left-shift (non-arithmetic)
    OP_RSHIFTBIN = 0x99, // after upgrade12 (May 2026); binary blob right-shift (non-arithmetic)

    OP_BOOLAND = 0x9a,
    OP_BOOLOR = 0x9b,
    OP_NUMEQUAL = 0x9c,
    OP_NUMEQUALVERIFY = 0x9d,
    OP_NUMNOTEQUAL = 0x9e,
    OP_LESSTHAN = 0x9f,
    OP_GREATERTHAN = 0xa0,
    OP_LESSTHANOREQUAL = 0xa1,
    OP_GREATERTHANOREQUAL = 0xa2,
    OP_MIN = 0xa3,
    OP_MAX = 0xa4,

    OP_WITHIN = 0xa5,

    // crypto
    OP_RIPEMD160 = 0xa6,
    OP_SHA1 = 0xa7,
    OP_SHA256 = 0xa8,
    OP_HASH160 = 0xa9,
    OP_HASH256 = 0xaa,
    OP_CODESEPARATOR = 0xab,
    OP_CHECKSIG = 0xac,
    OP_CHECKSIGVERIFY = 0xad,
    OP_CHECKMULTISIG = 0xae,
    OP_CHECKMULTISIGVERIFY = 0xaf,

    // expansion
    OP_NOP1 = 0xb0,
    OP_CHECKLOCKTIMEVERIFY = 0xb1,
    OP_NOP2 = OP_CHECKLOCKTIMEVERIFY,
    OP_CHECKSEQUENCEVERIFY = 0xb2,
    OP_NOP3 = OP_CHECKSEQUENCEVERIFY,
    OP_NOP4 = 0xb3,
    OP_NOP5 = 0xb4,
    OP_NOP6 = 0xb5,
    OP_NOP7 = 0xb6,
    OP_NOP8 = 0xb7,
    OP_NOP9 = 0xb8,
    OP_NOP10 = 0xb9,

    // More crypto
    OP_CHECKDATASIG = 0xba,
    OP_CHECKDATASIGVERIFY = 0xbb,

    // additional byte string operations
    OP_REVERSEBYTES = 0xbc,

    // Available codepoints
    // 0xbd,
    // 0xbe,
    // 0xbf,

    // Native Introspection opcodes
    OP_INPUTINDEX = 0xc0,
    OP_ACTIVEBYTECODE = 0xc1,
    OP_TXVERSION = 0xc2,
    OP_TXINPUTCOUNT = 0xc3,
    OP_TXOUTPUTCOUNT = 0xc4,
    OP_TXLOCKTIME = 0xc5,
    OP_UTXOVALUE = 0xc6,
    OP_UTXOBYTECODE = 0xc7,
    OP_OUTPOINTTXHASH = 0xc8,
    OP_OUTPOINTINDEX = 0xc9,
    OP_INPUTBYTECODE = 0xca,
    OP_INPUTSEQUENCENUMBER = 0xcb,
    OP_OUTPUTVALUE = 0xcc,
    OP_OUTPUTBYTECODE = 0xcd,

    // Native Introspection of tokens (SCRIPT_ENABLE_TOKENS must be set)
    OP_UTXOTOKENCATEGORY = 0xce,
    OP_UTXOTOKENCOMMITMENT = 0xcf,
    OP_UTXOTOKENAMOUNT = 0xd0,
    OP_OUTPUTTOKENCATEGORY = 0xd1,
    OP_OUTPUTTOKENCOMMITMENT = 0xd2,
    OP_OUTPUTTOKENAMOUNT = 0xd3,

    OP_RESERVED3 = 0xd4,
    OP_RESERVED4 = 0xd5,

    // The first op_code value after all defined opcodes
    FIRST_UNDEFINED_OP_VALUE,

    // Invalid opcode if executed, but used for special token prefix if at
    // position 0 in scriptPubKey. See: primitives/token.h
    SPECIAL_TOKEN_PREFIX = 0xef,

    INVALIDOPCODE = 0xff,   ///< Not a real OPCODE!
};

// Maximum value that an opcode can be
static const unsigned int MAX_OPCODE = FIRST_UNDEFINED_OP_VALUE - 1;

const char *GetOpName(opcodetype opcode);

/**
 * Check whether the given stack element data would be minimally pushed using
 * the given opcode.
 */
bool CheckMinimalPush(const std::vector<uint8_t> &data, opcodetype opcode);

// Used by EvalScript() internally in interpreter.cpp
struct ScriptEvaluationError : std::runtime_error {
    ScriptError scriptError;
    explicit ScriptEvaluationError(const std::string &str, ScriptError err = ScriptError::UNKNOWN)
        : std::runtime_error(str), scriptError(err) {}
    explicit ScriptEvaluationError(ScriptError err) : ScriptEvaluationError(ScriptErrorString(err), err) {}
};

// Subclass of above, used in the ScriptNum classes below to indicate encoding, overflow, or other script num error.
struct scriptnum_error : ScriptEvaluationError {
    using ScriptEvaluationError::ScriptEvaluationError;
};

/**
 * Base template class for CScriptNum and ScriptInt. This class implements
 * some of the functionality common to both subclasses, and also captures
 * some enforcement of the consensus rules related to:
 *
 * UsesBigInt == false:
 *  - valid 64 bit range (INT64_MIN is forbidden)
 *  - trapping for arithmetic operations that overflow or that produce a
 *    result equal to INT64_MIN
 *
 * UsesBigInt == true:
 *  - numbers that would exceed MAXIMUM_ELEMENT_SIZE_BIG_INT [-2^79999 + 1, 2^79999 - 1].
 */
template <typename Derived, bool UsesBigInt = false>
struct ScriptIntBase {

    using IntType = std::conditional_t<UsesBigInt, BigInt, int64_t>;

protected:
    IntType value_;

    /* 10KB limit or +/- 2^79999 - 1; If changing this also update script_error.cpp to denote the new valid range. */
    static constexpr size_t MAXIMUM_ELEMENT_SIZE_BIG_INT = may2025::MAX_SCRIPT_ELEMENT_SIZE;
    static constexpr size_t MAX_BIG_INT_BITS = MAXIMUM_ELEMENT_SIZE_BIG_INT * 8u - 1u;

    // Maximum number consensus-legal bits for IntType (63 or 79999)
    static constexpr size_t MAX_BITS = UsesBigInt ? MAX_BIG_INT_BITS : 63;

    static
    const BigInt &bigIntConsensusMax() {
        static const BigInt ret = BigInt(2).pow(MAX_BIG_INT_BITS) - 1u;
        return ret;
    }

    static
    const BigInt &bigIntConsensusMin() {
        static const BigInt ret = -bigIntConsensusMax();
        return ret;
    }

    // If UsesBigInt == true; checks that `x` is within the MAXIMUM_ELEMENT_SIZE_BIG_INT range,
    // otherwise checks that x is not INT64_MIN
    static
    bool validRange(IntType const& x) {
        if constexpr (UsesBigInt) {
            return x >= bigIntConsensusMin() && x <= bigIntConsensusMax();
        } else {
            return x > std::numeric_limits<int64_t>::min();
        }
    }


    static
    std::optional<Derived> derivedIfInRange(IntType x) {
        if ( ! validRange(x)) {
            return std::nullopt;
        }
        return Derived(std::move(x));
    }

    explicit
    ScriptIntBase(IntType x) noexcept(!UsesBigInt)
        : value_(std::move(x))
    {}

public:
    /**
     * Factory method to safely construct an instance from a raw int64_t
     * or BigInt.
     *
     * If UsesBigInt==false: We enforce a strict range of
     * [INT64_MIN+1, INT64_MAX].
     *
     * If UsesBigInt==true: We enforce the range that corresponds to a
     * big integer whose serialized size does not exceed
     * MAXIMUM_ELEMENT_SIZE_BIG_INT bytes [-2^79999 + 1, 2^79999 - 1].
     */
    static
    std::optional<Derived> fromInt(IntType x) noexcept(!UsesBigInt) {
        return derivedIfInRange(std::move(x));
    }

    /// Performance/convenience optimization: Construct an instance from a raw
    /// int64_t or BigInt, where the caller already knows that the supplied value
    /// is in range.
    static
    Derived fromIntUnchecked(IntType x) noexcept(!UsesBigInt) {
        return Derived(std::move(x));
    }

    // Comparison ops; Note: Must declare opeator<=> and operator== in this way so as to avoid ambiguous resolution for
    // derived classes.
    friend std::strong_ordering operator<=>(Derived const &a, IntType const& x) noexcept { return a.value_ <=> x; }
    friend bool operator==(Derived const &a, IntType const& x) noexcept { return operator<=>(a, x) == 0; }

    friend std::strong_ordering operator<=>(Derived const &a, Derived const& b) noexcept { return operator<=>(a, b.value_); }
    friend bool operator==(Derived const& a, Derived const& b) noexcept { return operator<=>(a, b.value_) == 0; }

    // Arithmetic operations
    std::optional<Derived> safeAdd(IntType const& x) const noexcept(!UsesBigInt) {
        std::optional<Derived> ret = Derived(value_);
        if (! ret->safeAddInPlace(x)) {
            ret.reset();
        }
        return ret;
    }

    std::optional<Derived> safeAdd(Derived const& x) const noexcept(!UsesBigInt) {
        return safeAdd(x.value_);
    }

    std::optional<Derived> safeAdd(int64_t x) const requires UsesBigInt { // (BigInt only) optimization for int64_t
        return derivedIfInRange(value_ + x);
    }

    [[nodiscard]]
    bool safeAddInPlace(IntType const& x) noexcept(!UsesBigInt) {
        if constexpr (UsesBigInt) {
            bool const ok = validRange(value_ += x);
            if (!ok) [[unlikely]] value_ -= x; // failure; undo effects of above to restore previous state
            return ok;
        } else {
            int64_t result;
            bool const overflow = __builtin_add_overflow(value_, x, &result);
            if (overflow || !validRange(result)) {
                return false;
            }
            value_ = result;
            return true;
        }
    }

    [[nodiscard]]
    bool safeAddInPlace(Derived const& x) noexcept(!UsesBigInt) {
        return safeAddInPlace(x.value_);
    }

    [[nodiscard]]
    bool safeAddInPlace(int64_t x) requires UsesBigInt { // (BigInt only) optimization for int64_t
        bool const ok = validRange(value_ += x);
        if (!ok) [[unlikely]] value_ -= x; // failure; undo effects of above to restore previous state
        return ok;
    }

    [[nodiscard]]
    bool safeIncr() noexcept(!UsesBigInt) {
        if constexpr (UsesBigInt) {
            bool const ok = validRange(++value_);
            if (!ok) [[unlikely]] --value_; // failure; undo effects of above to restore previous state
            return ok;
        } else {
            int64_t result;
            bool const overflow = __builtin_add_overflow(value_, 1u, &result);
            if (overflow || !validRange(result)) {
                return false;
            }
            value_ = result;
            return true;
        }
    }

    std::optional<Derived> safeSub(IntType const& x) const noexcept(!UsesBigInt) {
        std::optional<Derived> ret = Derived(value_);
        if (! ret->safeSubInPlace(x)) {
            ret.reset();
        }
        return ret;
    }

    std::optional<Derived> safeSub(Derived const& x) const noexcept(!UsesBigInt) {
        return safeSub(x.value_);
    }

    std::optional<Derived> safeSub(int64_t x) const requires UsesBigInt { // (BigInt only) optimization for int64_t
        return derivedIfInRange(value_ - x);
    }

    [[nodiscard]]
    bool safeSubInPlace(IntType const& x) noexcept(!UsesBigInt) {
        if constexpr (UsesBigInt) {
            bool const ok = validRange(value_ -= x);
            if (!ok) [[unlikely]] value_ += x; // failure; undo effects of above to restore previous state
            return ok;
        } else {
            int64_t result;
            bool const overflow = __builtin_sub_overflow(value_, x, &result);
            if (overflow || !validRange(result)) {
                return false;
            }
            value_ = result;
            return true;
        }
    }

    [[nodiscard]]
    bool safeSubInPlace(Derived const& x) noexcept(!UsesBigInt) {
        return safeSubInPlace(x.value_);
    }

    [[nodiscard]]
    bool safeSubInPlace(int64_t x) requires UsesBigInt { // (BigInt only) optimization for int64_t
        bool const ok = validRange(value_ -= x);
        if (!ok) [[unlikely]] value_ += x; // failure; undo effects of above to restore previous state
        return ok;
    }

    [[nodiscard]]
    bool safeDecr() noexcept(!UsesBigInt) {
        if constexpr (UsesBigInt) {
            bool const ok = validRange(--value_);
            if (!ok) [[unlikely]] ++value_; // failure; undo effects of above to restore previous state
            return ok;
        } else {
            int64_t result;
            bool const overflow = __builtin_sub_overflow(value_, 1u, &result);
            if (overflow || !validRange(result)) {
                return false;
            }
            value_ = result;
            return true;
        }
    }

    std::optional<Derived> safeMul(IntType const& x) const noexcept(!UsesBigInt) {
        std::optional<Derived> ret = Derived(value_);
        if (! ret->safeMulInPlace(x)) {
            ret.reset();
        }
        return ret;
    }

    std::optional<Derived> safeMul(Derived const& x) const noexcept(!UsesBigInt) {
        return safeMul(x.value_);
    }

    std::optional<Derived> safeMul(int64_t x) const requires UsesBigInt { // (BigInt only) optimization for int64_t
        return derivedIfInRange(value_ * x);
    }

    [[nodiscard]]
    bool safeMulInPlace(IntType const& x) noexcept(!UsesBigInt) {
        if constexpr (UsesBigInt) {
            bool const ok = validRange(value_ *= x);
            if (!ok) [[unlikely]] {
                assert(x != 0); // should never happen; if triggered, some bug exists with validRange()
                value_ /= x; // failure; undo effects of above to restore previous state
            }
            return ok;
        } else {
            int64_t result;
            bool const overflow = __builtin_mul_overflow(value_, x, &result);
            if (overflow || !validRange(result)) {
                return false;
            }
            value_ = result;
            return true;;
        }
    }

    [[nodiscard]]
    bool safeMulInPlace(Derived const& x) noexcept(!UsesBigInt) {
        return safeMulInPlace(x.value_);
    }

    [[nodiscard]]
    bool safeMulInPlace(int64_t x) requires UsesBigInt { // (BigInt only) optimization for int64_t
        bool const ok = validRange(value_ *= x);
        if (!ok) [[unlikely]] {
            assert(x != 0); // should never happen; if triggered, some bug exists with validRange()
            value_ /= x; // failure; undo effects of above to restore previous state
        }
        return ok;
    }

    Derived operator/(IntType const& x) const noexcept(!UsesBigInt) {
        Derived ret(value_);
        ret.operator/=(x);
        return ret;
    }

    Derived operator/(Derived const& x) const noexcept(!UsesBigInt) {
        return operator/(x.value_);
    }

    Derived operator/(int64_t x) const requires UsesBigInt { // (BigInt only) optimization for int64_t
        return Derived(value_ / x);
    }

    Derived &operator/=(Derived const& x) noexcept(!UsesBigInt) {
        return operator/=(x.value_);
    }

    Derived &operator/=(IntType const& x) noexcept(!UsesBigInt) {
        if constexpr ( ! UsesBigInt) {
            if (x == -1 && ! validRange(value_)) {
                // Guard against overflow, which can't normally happen unless class is misused
                // by the fromIntUnchecked() factory method (may happen in tests).
                // This will return INT64_MIN which is what ARM & x86 does anyway for INT64_MIN / -1.
                return static_cast<Derived &>(*this);
            }
        }
        value_ /= x;
        return static_cast<Derived &>(*this);
    }

    Derived &operator/=(int64_t x) requires UsesBigInt { // (BigInt only) optimization for int64_t
        value_ /= x;
        return static_cast<Derived &>(*this);
    }

    Derived operator%(IntType const& x) const noexcept(!UsesBigInt) {
        Derived ret(value_);
        ret.operator%=(x);
        return ret;
    }

    Derived operator%(Derived const& x) const noexcept(!UsesBigInt) {
        return operator%(x.value_);
    }

    Derived operator%(int64_t x) const requires UsesBigInt { // (BigInt only) optimization for int64_t
        return Derived(value_ % x);
    }

    Derived &operator%=(IntType const& x) noexcept(!UsesBigInt) {
        if constexpr ( ! UsesBigInt) {
            if (x == -1 && ! validRange(value_)) {
                // INT64_MIN % -1 is UB in C++, but mathematically it would yield 0
                value_ = 0;
                return static_cast<Derived &>(*this);
            }
        }
        value_ %= x;
        return static_cast<Derived &>(*this);
    }

    Derived &operator%=(Derived const& x) noexcept(!UsesBigInt) {
        return operator%=(x.value_);
    }

    Derived &operator%=(int64_t x) requires UsesBigInt { // (BigInt only) optimization for int64_t
        value_ %= x;
        return static_cast<Derived &>(*this);
    }

    // Bitwise operations
    std::optional<Derived> safeBitwiseAnd(IntType const& x) const noexcept(!UsesBigInt) {
        return derivedIfInRange(value_ & x);
    }

    std::optional<Derived> safeBitwiseAnd(Derived const& x) const noexcept(!UsesBigInt) {
        return safeBitwiseAnd(x.value_);
    }

    Derived &negate() noexcept(!UsesBigInt) {
        if constexpr (UsesBigInt) {
            value_.negate();
        } else {
            // Defensive programming: -INT64_MIN is UB
            value_ = validRange(value_) ? -value_ : value_;
        }
        return static_cast<Derived &>(*this);
    }

    Derived operator-() const noexcept(!UsesBigInt) { return Derived(value_).negate(); }

    std::conditional_t<UsesBigInt, std::optional<int64_t>, int64_t>
    getint64() const noexcept {
        if constexpr (UsesBigInt) {
            return value_.getInt();
        } else {
            return value_;
        }
    }

    /// Returns the number of characters needed to represent the contained absolute value if it were to be printed
    /// as a binary string. Note: `0` returns 1, `-1` returns 1, `3` returns 2, `-3` returns 2, etc.
    size_t absValNumBits() const {
        if constexpr (UsesBigInt) {
            return value_.absValNumBits();
        } else {
            const uint64_t uval = value_ < 0 ? -static_cast<uint64_t>(value_) // safely cast to positive
                                             :  static_cast<uint64_t>(value_);
            return std::max<unsigned>(1, std::bit_width(uval));
        }
    }

    /// Performs operator<<= on the underlying value_; returns true if the result is in consensus-legal range, false
    /// otherwise. Note that unlike the safe*() functions, on a false return `value_` *may or may not* remain shifted,
    /// in other words the effects of this function are not guaranteed to get rolled-back on a false return.
    [[nodiscard]]
    bool checkedLeftShift(unsigned const bitcount) {
        if (!value_) return true; // fast-path; 0 left-shifted any number of bits is 0
        if (bitcount + absValNumBits() > MAX_BITS) {
            // would definitely fail, don't even bother
            return false;
        }
        if constexpr (UsesBigInt) {
            value_ <<= static_cast<unsigned long>(bitcount);
        } else {
            bool const neg = value_ < 0;
            uint64_t const uval = neg ? -static_cast<uint64_t>(value_) // safely cast to positive
                                      :  static_cast<uint64_t>(value_);
            value_ = static_cast<int64_t>(uval << bitcount);
            if (neg) value_ = -value_;
        }
        return validRange(value_); // should always return true here, but checked for paranoia
    }

    /// Performs operator>>= on the underlying value_; returns true if the result is in consensus-legal range, false
    /// otherwise. Note that unlike the safe*() functions, on a false return `value_` *may or may not* remain shifted,
    /// in other words the effects of this function are not guaranteed to get rolled-back on a false return.
    ///
    /// False return is only possible if the original value was already outside of consensus-legal range, and
    /// the result of the right-shift did nothing to correct the situation.
    [[nodiscard]]
    bool checkedRightShift(unsigned const bitcount) {
        if (!value_) return true; // fast path; 0 right-shifted any number of bits is 0
        if constexpr (UsesBigInt) {
            if (bitcount >= absValNumBits()) {
                // Fast-path, excessive right-shift yields -1 for negative & 0 for positive numbers
                value_ = value_.sign() < 0 ? -1 : 0;
                return true;
            }
            value_ >>= static_cast<unsigned long>(bitcount);
        } else {
            value_ >>= std::min(bitcount, 63u);
        }
        return validRange(value_);
    }
};

/**
 * A ScriptInt is a "write-only" class designed to be used with
 * CScript in order to tell the CScript serialization engine to
 * represent small numbers in a more compact way.  It is
 * interchangeable with CScriptNum for serialization purposes,
 * except that for small numbers in the range [-1, 16] ScriptInt
 * ends up serializing slightly smaller, saving one byte.
 *
 * This is because the CScript class serializes ScriptInt differently
 * than it does CScriptNum for integers in the range [-1, 16].
 *
 * Whereas CScriptNum is always pushed as an encapsulated byte blob,
 * ScriptInt instances in the range [-1, 16] are pushed as raw bytes
 * directly (with some offsetting around OP_16 as the anchor).
 *
 * For numbers outside the [-1, 16] range, ScriptInt serializes
 * identically to CScriptNum.
 *
 * When the resulting script is interpreted by the script interpreter,
 * any values that are serialized in this more compact way are internally
 * transformed and normalized into CScriptNum instances on the stack
 * (see interpreter.cpp).  So the purpose of this class is simply as
 * a "type tag" to tell CScript to serialize in the more compact form,
 * if possible.
 *
 * In short, these two serialize differently:
 *
 *   CScript() << CScriptNum::fromIntUnchecked(10); // [PUSH(1) 0x0a] (2 bytes)
 *   CScript() << ScriptInt::fromIntUnchecked(10);  // [0x5a] (1 byte)
 *
 * However, for integers outside the range [-1, 16], the serialization
 * is identical:
 *
 *   CScript() << CScriptNum::fromIntUnchecked(42); // [PUSH(1) 0x2a] (2 bytes)
 *   CScript() << ScriptInt::fromIntUnchecked(42);  // Same as above
 *
 * Note that due to quirks in how CScriptNum serializes 0, these two
 * also serialize identically:
 *
 *   CScript() << CScriptNum::fromIntUnchecked(0);  // [PUSH(0)] == [0x00] (1 byte)
 *   CScript() << ScriptInt::fromIntUnchecked(0);   // [0x00] (1 byte)
 */
struct ScriptInt : ScriptIntBase<ScriptInt> {
    friend ScriptIntBase;

private:
    explicit
    ScriptInt(int64_t x) noexcept
        : ScriptIntBase(x)
    {}
};

template<typename Derived, bool UsesBigInt>
struct ScriptNumCommon : ScriptIntBase<Derived, UsesBigInt>, ScriptNumEncoding {

    using Base = ScriptIntBase<Derived, UsesBigInt>;

    int32_t getint32() const noexcept {
        if (this->value_ > std::numeric_limits<int32_t>::max()) {
            return std::numeric_limits<int32_t>::max();
        } else if (this->value_ < std::numeric_limits<int32_t>::min()) {
            return std::numeric_limits<int32_t>::min();
        }
        if constexpr (UsesBigInt) {
            // Dereferencing the optional here is guaranteed to not throw due to the check at the top of this function.
            return this->value_.getInt().value();
        } else {
            return this->value_;
        }
    }

    /// Throws `scriptnum_error` if `vch` is not a valid script number encoding.
    static
    void throwIfInvalidScriptNumEncoding(std::vector<uint8_t> const& vch, bool fRequireMinimal, size_t maxIntegerSize) {
        if (vch.size() > maxIntegerSize) {
            throw scriptnum_error("script number overflow",
                                  maxIntegerSize > 8u ? ScriptError::INVALID_NUMBER_RANGE_BIG_INT
                                                      : maxIntegerSize == 8u ? ScriptError::INVALID_NUMBER_RANGE_64_BIT
                                                                             : ScriptError::INVALID_NUMBER_RANGE);
        }
        if (fRequireMinimal && ! IsMinimallyEncoded(vch, maxIntegerSize)) {
            throw scriptnum_error("non-minimally encoded script number", ScriptError::MINIMALNUM);
        }
    }

protected:
    using Base::ScriptIntBase;
    using IntType = typename Base::IntType;

    static
    IntType fromBytes(std::vector<uint8_t> const& vch, bool fRequireMinimal, size_t maxIntegerSize) {
        throwIfInvalidScriptNumEncoding(vch, fRequireMinimal, maxIntegerSize);
        return Derived::set_vch(vch);
    }

};

/**
 * CScriptNum is used to encapsulate signed numbers as byte blobs in a CScript.
 * Its specified range is over [INT64_MIN+1, INT64_MAX].  Attempts to encapsulate
 * a number outside this range are undefined behavior.
 *
 * Note that before Upgrade8, consensus rules forbade a CScriptNum significantly
 * outside the 32 bit range (with some corner case exceptions for temporaries in
 * the interpreter).
 *
 * After Upgrade8 we allow 64 bit numbers in the range [INT64_MIN+1, INT64_MAX].
 * We forbid INT64_MIN, however, since this would encode to a 9 byte CScriptNum
 * and we prefer to keep things simple and restrict CScriptNum to 8 bytes.
 *
 * A CScriptNum gets serialized to a non-2's complement notation, in little-endian
 * byte order. The most significant bit (in the last, most significant byte) is
 * the sign bit. The other bits preceeding it (little endian) are the magnitude.
 *
 * This means that INT64_MIN would get serialized to 9 bytes in this encoding,
 * which is why it is forbidden (since we prefer to limit them to 8 serialized
 * bytes, for simplicity's sake).
 */
struct CScriptNum : ScriptNumCommon<CScriptNum, false> {
    /**
     * Pre Upgrade8 Hardfork semantics:
     * Numeric opcodes (OP_1ADD, etc) are restricted to operating on 4-byte
     * integers. The semantics are subtle, though: operands must be in the range
     * [-2^31 + 1, 2^31 - 1], but results may overflow (and are valid as long as
     * they are not used in a subsequent numeric operation). CScriptNum enforces
     * those semantics by storing results as an int64 and allowing out-of-range
     * values to be returned as a vector of bytes but throwing an exception if
     * arithmetic is done or the result is interpreted as an integer.
     *
     * Post Upgrade8 Hardfork semantics:
     * Arithmetic opcodes (OP_1ADD, etc) are restricted to operating on 8-byte signed integers.
     * Negative integers are encoding using sign and magnitude, so operands must be in the range
     * [-2^63 + 1, 2^63 - 1].
     * Arithmetic operators throw an exception if overflow is detected.
     */

    friend ScriptIntBase;
    friend ScriptNumCommon;

    static constexpr size_t MAXIMUM_ELEMENT_SIZE_32_BIT = 4;
    static constexpr size_t MAXIMUM_ELEMENT_SIZE_64_BIT = 8;

private:
    explicit
    CScriptNum(int64_t x) noexcept
        : ScriptNumCommon(x)
    {}

public:
    explicit
    CScriptNum(const std::vector<uint8_t> &vch, bool fRequireMinimal, size_t maxIntegerSize)
        : ScriptNumCommon(fromBytes(vch, fRequireMinimal, maxIntegerSize))
    {}

    std::vector<uint8_t> getvch() const { return serialize(value_); }

    static
    std::vector<uint8_t> serialize(int64_t value) {
        if (value == 0) {
            return {};
        }

        std::vector<uint8_t> result;
        const bool neg = value < 0;
        // NB: -INT64_MIN in 2's complement is UB, so we must guard against it here.
        uint64_t absvalue = neg && validRange(value) ? -value : value;

        while (absvalue) {
            result.push_back(absvalue & 0xff);
            absvalue >>= 8;
        }

        // - If the most significant byte is >= 0x80 and the value is positive,
        // push a new zero-byte to make the significant byte < 0x80 again.
        // - If the most significant byte is >= 0x80 and the value is negative,
        // push a new 0x80 byte that will be popped off when converting to an
        // integral.
        // - If the most significant byte is < 0x80 and the value is negative,
        // add 0x80 to it, since it will be subtracted and interpreted as a
        // negative when converting to an integral.
        if (result.back() & 0x80) {
            result.push_back(neg ? 0x80 : 0);
        } else if (neg) {
            result.back() |= 0x80;
        }

        return result;
    }

private:
    static
    int64_t fromBytes(std::vector<uint8_t> const& vch, bool fRequireMinimal, size_t maxIntegerSize) {
        if (maxIntegerSize > MAXIMUM_ELEMENT_SIZE_64_BIT) {
            throw scriptnum_error("maxIntegerSize cannot be greater than 8");
        }
        return ScriptNumCommon::fromBytes(vch, fRequireMinimal, maxIntegerSize);
    }

    ///! Precondition: vch.size() must be <= 8.
    static
    int64_t set_vch(const std::vector<uint8_t> &vch) {
        if (vch.empty()) {
            return 0;
        }

        int64_t result = 0;
        for (size_t i = 0; i != vch.size(); ++i) {
            result |= int64_t(vch[i]) << 8 * i;
        }

        // If the input vector's most significant byte is 0x80, remove it from
        // the result's msb and return a negative.
        if (vch.back() & 0x80) {
            return -int64_t(result & ~(0x80ULL << (8 * (vch.size() - 1))));
        }

        return result;
    }
};

/*
 * A drop-in replacement for CScriptNum that can represent arbitrarily large integers,
 * (up to a consensus limit of MAXIMUM_ELEMENT_SIZE_BIG_INT). Internally it uses the BigInt
 * class which supports arithmetic operations for arbitrary precision integers.
 *
 * Aside from not overflowing when doing math beyond 64-bits, this class behaves more or less
 * identically to the legacy CScriptNum.
 **/
struct ScriptBigInt : ScriptNumCommon<ScriptBigInt, true> {

    friend ScriptIntBase;
    friend ScriptNumCommon;

private:
    // Called by ScriptIntBase
    explicit ScriptBigInt(BigInt x)
        : ScriptNumCommon(std::move(x)) {}

public:
    explicit
    ScriptBigInt(const std::vector<uint8_t> &vch, bool fRequireMinimal, size_t maxIntegerSize)
        : ScriptNumCommon(fromBytes(vch, fRequireMinimal, maxIntegerSize))
    {}

    std::vector<uint8_t> getvch() const { return value_.serialize(); }

    /// Returns the underlying BigInt; the returned BigInt is not guaranteed to be in valid consensus-legal range
    /// for pushing to the stack (a situation which may occur in tests).
    const BigInt &getBigInt() const { return value_; }

    // Promote these base class static protected methods to public (for tests, etc).
    using ScriptIntBase::validRange;
    using ScriptIntBase::bigIntConsensusMin;
    using ScriptIntBase::bigIntConsensusMax;
    using ScriptIntBase::MAXIMUM_ELEMENT_SIZE_BIG_INT;
    using ScriptIntBase::MAX_BITS;

private:
    // Called by ScriptNumCommon::fromBytes
    static BigInt set_vch(const std::vector<uint8_t> &vch) {
        BigInt ret;
        ret.unserialize(vch);
        return ret;
    }
};

/**
 * This is a union type of CScriptNum and ScriptBigInt which encapsulates the functionality of the two classes in
 * a single wrapper class. The functionality encapsulated is that which is used by the script interpreter in EvalScript
 * (interpreter.cpp) for working with script numbers. This class is an optimization to provide fast native int64_t math
 * for small ints and to provide for auto-switching to BigInt for larger integers when calculations exceed the range
 * [INT64_MIN + 1, INT64_MAX] (inclusive).
 */
class FastBigNum : public ScriptNumEncoding {
    std::variant<CScriptNum, ScriptBigInt> var;

    explicit FastBigNum(CScriptNum &&csn) : var{std::move(csn)} {}
    explicit FastBigNum(ScriptBigInt &&sbi) : var{std::move(sbi)} {}

    // Switches `var` to use ScriptBigInt (if it is not already doing so), preserving the stored value.
    ScriptBigInt &ensureScriptBigInt();

    // Member function pointer to: CScriptNum that accepts a CScriptNum and returns an optonal
    using CSN_Mem_Fn = std::optional<CScriptNum> (CScriptNum::*)(const CScriptNum &) const;
    // Member function pointer to: ScriptBigInt that accepts a BigInt and returns a bool
    using SBI_Mem_Fn = bool (ScriptBigInt::*)(const BigInt &);
    // Member function pointer to: ScriptBigInt that accepts an int64_t and returns a bool
    using SBI_Mem_Fn_I64 = bool (ScriptBigInt::*)(int64_t);
    // Generic helper for the safe*() public arith ops functions that does the proper juggling of arith. on mixed types
    bool doInPlaceSafeArithOp(const FastBigNum &o, CSN_Mem_Fn csnMemFn, SBI_Mem_Fn sbiMemFn, SBI_Mem_Fn_I64 sbiMemFnI64);

    // Member function pointer to: CScriptNum that accepts a CScriptNum and returns non-const CScriptNum &
    using CSN_Mem_Fn_2 = CScriptNum& (CScriptNum::*)(const CScriptNum &);
    // Member function pointer to: ScriptBigInt that accepts a BigInt and returns non-const ScriptBigInt &
    using SBI_Mem_Fn_2 = ScriptBigInt& (ScriptBigInt::*)(const BigInt &);
    // Member function pointer to: ScriptBigInt that accepts an int64_t and returns non-const ScriptBigInt &
    using SBI_Mem_Fn_2_I64 = ScriptBigInt& (ScriptBigInt::*)(int64_t);
    // Generic helper for some public arith ops functions that does the proper juggling of arith. on mixed types
    FastBigNum &doInPlaceArithOp(const FastBigNum &o, CSN_Mem_Fn_2 csnMemFn, SBI_Mem_Fn_2 sbiMemFn, SBI_Mem_Fn_2_I64 sbiMemFnI64);

    // Quickly returns whether the contained value is 0 or not (faster than operator==(0))
    bool isZero() const;

public:
    // Construct from a serialized byte vector as would come in from the script interpreter. Auto-selects the correct
    // size based on the size of the input vch and `maxIntegerSize`. Throws on error (as do the underlying CScriptNum
    // and ScriptBigInt classes).
    FastBigNum(const std::vector<uint8_t> &vch, bool fRequireMinimal, size_t maxIntegerSize);

    static FastBigNum fromIntUnchecked(int64_t x) {
        if (auto opt = CScriptNum::fromInt(x)) {
            return FastBigNum(std::move(*opt));
        } else {
            // `x` == INT64_MIN, use BigInt instead
            return FastBigNum(ScriptBigInt::fromIntUnchecked(x));
        }
    }

    // Returns true if we are using native ints (CScriptNum as the backing class), false if using BigInt (ScriptBigInt)
    bool usesNative() const { return std::holds_alternative<CScriptNum>(var); }

    int32_t getint32() const { return std::visit([](const auto &num){ return num.getint32(); }, var); }

    std::optional<int64_t> getint64() const {
        return std::visit([](const auto &num) -> std::optional<int64_t> { return num.getint64(); }, var);
    }

    std::vector<uint8_t> getvch() const { return std::visit([](const auto &num){ return num.getvch(); }, var); }

    [[nodiscard]] bool safeAddInPlace(const FastBigNum &o) {
        return doInPlaceSafeArithOp(o, &CScriptNum::safeAdd, &ScriptBigInt::safeAddInPlace, &ScriptBigInt::safeAddInPlace);
    }
    [[nodiscard]] bool safeIncr() { return safeAddInPlace(FastBigNum::fromIntUnchecked(1)); }
    [[nodiscard]] bool safeSubInPlace(const FastBigNum &o) {
        return doInPlaceSafeArithOp(o, &CScriptNum::safeSub, &ScriptBigInt::safeSubInPlace, &ScriptBigInt::safeSubInPlace);
    }
    [[nodiscard]] bool safeDecr() { return safeSubInPlace(FastBigNum::fromIntUnchecked(1)); }
    [[nodiscard]] bool safeMulInPlace(const FastBigNum &o) {
        return doInPlaceSafeArithOp(o, &CScriptNum::safeMul, &ScriptBigInt::safeMulInPlace, &ScriptBigInt::safeMulInPlace);
    }

    FastBigNum &operator/=(const FastBigNum &o) {
        if (o.isZero()) throw std::invalid_argument("Attempted division by 0 in FastBigNum::operator/=");
        return doInPlaceArithOp(o, &CScriptNum::operator/=, &ScriptBigInt::operator/=, &ScriptBigInt::operator/=);
    }

    FastBigNum &operator%=(const FastBigNum &o) {
        if (o.isZero()) throw std::invalid_argument("Attempted modulo by 0 in FastBigNum::operator%=");
        return doInPlaceArithOp(o, &CScriptNum::operator%=, &ScriptBigInt::operator%=, &ScriptBigInt::operator%=);
    }

    FastBigNum &negate() { std::visit([](auto &bn) { bn.negate(); }, var); return *this; }

    size_t absValNumBits() const { return std::visit([](const auto &num){ return num.absValNumBits(); }, var); }

    [[nodiscard]] bool checkedLeftShift(unsigned bitcount);

    [[nodiscard]] bool checkedRightShift(unsigned bitcount) {
        return std::visit([bitcount](auto &num){ return num.checkedRightShift(bitcount); }, var);
    }

    std::strong_ordering operator<=>(const FastBigNum &o) const;

    std::strong_ordering operator<=>(const int64_t val) const {
        return *this <=> FastBigNum(CScriptNum::fromIntUnchecked(val));
    }

    bool operator==(const FastBigNum &o) const { return (*this <=> o) == 0; }

    bool operator==(const int64_t o) const { return (*this <=> o) == 0; }
};

/**
 * We use a prevector for the script to reduce the considerable memory overhead
 * of vectors in cases where they normally contain a small number of small
 * elements. Tests in October 2015 showed use of this reduced dbcache memory
 * usage by 23% and made an initial sync 13% faster.
 */
using CScriptBase = prevector<28, uint8_t>;

bool GetScriptOp(const uint8_t *&pc, const uint8_t *end, opcodetype &opcodeRet, std::vector<uint8_t> *pvchRet);

/** Serialized script, used inside transaction inputs and outputs */
class CScript : public CScriptBase {
protected:
    CScript &push_int64(int64_t n) {
        if (n == -1 || (n >= 1 && n <= 16)) {
            push_back(n + (OP_1 - 1));
        } else if (n == 0) {
            push_back(OP_0);
        } else {
            *this << CScriptNum::serialize(n);
        }
        return *this;
    }

public:
    CScript() {}
    CScript(std::vector<uint8_t>::const_iterator pbegin,
            std::vector<uint8_t>::const_iterator pend)
        : CScriptBase(pbegin, pend) {}
    CScript(const uint8_t *pbegin, const uint8_t *pend)
        : CScriptBase(pbegin, pend) {}

    SERIALIZE_METHODS(CScript, obj) { READWRITEAS(CScriptBase, obj); }

    CScript &operator+=(const CScript &b) {
        reserve(size() + b.size());
        insert(end(), b.begin(), b.end());
        return *this;
    }

    friend CScript operator+(const CScript &a, const CScript &b) {
        CScript ret = a;
        ret += b;
        return ret;
    }

    explicit CScript(opcodetype b) {
        operator<<(b);
    }
    explicit CScript(const CScriptNum &b) {
        operator<<(b);
    }
    explicit CScript(const std::vector<uint8_t> &b) { operator<<(b); }

    CScript &operator<<(opcodetype opcode) {
        if (opcode < 0 || opcode > 0xff) {
            throw std::runtime_error("CScript::operator<<(): invalid opcode");
        }
        insert(end(), uint8_t(opcode));
        return *this;
    }

    CScript &operator<<(const CScriptNum &b) {
        *this << b.getvch();
        return *this;
    }

    CScript &operator<<(const ScriptBigInt &b) {
        *this << b.getvch();
        return *this;
    }

    CScript& operator<<(ScriptInt const& x) {
        return push_int64(x.getint64());
    }

    /// Append a byte blob to the script, including the pushdata opcode, if any, and the length byte(s) prepended.
    ///
    /// Note that unlike the streams classes in streams.h, pushing a vector vs pushing a span (ByteView) will yield
    /// identical results, with the length byte(s) *always* present; e.g. the following are identical:
    ///     `script << someVector`
    ///     `script << std::span{someVector}`
    CScript &operator<<(const ByteView &b) {
        if (!b.empty() && b.data() >= begin() && b.data() < end()) [[unlikely]] {
            // Detect class mis-use which may result in UB: an attempt to push a (sub)script onto itself, and compensate
            // by allocating a temporary vector to hold the bytes to be pushed.
            return this->operator<<(ByteView{std::vector<uint8_t>(b.begin(), b.end())});
        }
        if (b.size() < OP_PUSHDATA1) {
            insert(end(), uint8_t(b.size()));
        } else if (b.size() <= 0xff) {
            insert(end(), OP_PUSHDATA1);
            insert(end(), uint8_t(b.size()));
        } else if (b.size() <= 0xffff) {
            insert(end(), OP_PUSHDATA2);
            uint8_t _data[2];
            WriteLE16(_data, b.size());
            insert(end(), _data, _data + sizeof(_data));
        } else {
            insert(end(), OP_PUSHDATA4);
            uint8_t _data[4];
            WriteLE32(_data, b.size());
            insert(end(), _data, _data + sizeof(_data));
        }
        insert(end(), b.begin(), b.end());
        return *this;
    }

    /// Intentionally unimplemented; it's not clear if this should push the script or concatenate scripts. If there's
    /// ever a need for pushing one script onto another script, one may cast the argument to `ByteView`, e.g.:
    ///     `script << ByteView{otherScript}`
    CScript &operator<<(const CScript &) = delete;

    bool GetOp(const_iterator &pc, opcodetype &opcodeRet,
               std::vector<uint8_t> &vchRet) const {
        return GetScriptOp(pc, end(), opcodeRet, &vchRet);
    }

    bool GetOp(const_iterator &pc, opcodetype &opcodeRet) const {
        return GetScriptOp(pc, end(), opcodeRet, nullptr);
    }

    /** Encode/decode small integers: */
    static int DecodeOP_N(opcodetype opcode) {
        if (opcode == OP_0) {
            return 0;
        }

        assert(opcode >= OP_1 && opcode <= OP_16);
        return int(opcode) - int(OP_1 - 1);
    }
    static opcodetype EncodeOP_N(int n) {
        assert(n >= 0 && n <= 16);
        if (n == 0) {
            return OP_0;
        }

        return (opcodetype)(OP_1 + n - 1);
    }

    /**
     * @brief IsPayToScriptHash - Returns true if this script follows the p2sh_20 (or p2sh_32) scriptPubKey template.
     * @param flags - If SCRIPT_ENABLE_P2SH_32 is in flags, then we will also detect p2sh_32, otherwise we will never
     *                detect p2sh_32 and return false for any p2sh_32 scriptPubKeys.
     * @param hash_out - Optional out param. If not nullptr, and if the return value is true, then *hash_out will
     *                   receive a copy of the actual hash bytes embedded in the scriptPubKey. Note that *hash_out is
     *                   not modified on false return, and is only modified on true return.
     * @param is_p2sh_32 - Optional out param.  If not nullptr, *is_p2sh_32 is set to false always unless
     *                     SCRIPT_ENABLE_P2SH_32 is set in `flags` and the scriptPubKey in question follows the p2sh_32,
     *                     scriptPubKey template, in which case *is_p2sh_32 is set to true.
     * @return true if the script is p2sh_20, or true if flags contains SCRIPT_ENABLE_P2SH_32 and the script is p2sh_32,
     *         false otherwise.
     */
    bool IsPayToScriptHash(uint32_t flags, std::vector<uint8_t> *hash_out = nullptr, bool *is_p2sh_32 = nullptr) const;
    bool IsPayToPubKeyHash() const;
    bool IsCommitment(const std::vector<uint8_t> &data) const;
    bool IsWitnessProgram(int *pversion = nullptr, std::vector<uint8_t> *pprogram = nullptr) const;
    bool IsWitnessProgram(int &version, std::vector<uint8_t> &program) const {
        return IsWitnessProgram(&version, &program);
    }

    /**
     * Called by IsStandardTx and P2SH/BIP62 VerifyScript (which makes it
     * consensus-critical).
     */
    bool IsPushOnly(const_iterator pc) const;
    bool IsPushOnly() const;

    /** Check if the script contains valid OP_CODES */
    bool HasValidOps(uint32_t scriptFlags) const;

    /**
     * Returns whether the script is guaranteed to fail at execution, regardless
     * of the initial stack. This allows outputs to be pruned instantly when
     * entering the UTXO set.
     *
     * Note that this function is called by Consensus::CheckTxInputs in
     * tx_verify.cpp, so modifying this function's pre/post conditions will
     * modify consensus!
     */
    bool IsUnspendable() const {
        const auto sz = size();
        return (sz > 0u && *begin() == OP_RETURN) || (sz > MAX_SCRIPT_SIZE);
    }

    void clear() {
        // The default prevector::clear() does not release memory
        CScriptBase::clear();
        shrink_to_fit();
    }
};

class CReserveScript {
public:
    CScript reserveScript;
    virtual void KeepScript() {}
    CReserveScript() {}
    virtual ~CReserveScript() {}
};
