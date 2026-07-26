// Copyright (c) 2025-present The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <utility>
#include <vector>

//! The stack element type is a simple vector of uint8_t
using StackVec = std::vector<uint8_t>;

//! Provides an abstraction on top of a simple byte vector to memoize (cache) known properties of a stack item.
//!
//! Currently we memoize the following:
//!   - Whether this stack element is known to evaluate to: boolean true, boolean false, or not yet known
//!
//! Future VM optimizations may cache additional information here (such as script number value, etc).
class StackItem {
    StackVec vch;
    std::optional<bool> cachedBool;

public:
    StackItem() noexcept = default;
    // Converting constructors
    StackItem(const StackVec &vchIn, std::optional<bool> cachedBoolIn = std::nullopt)
        : vch(vchIn), cachedBool(cachedBoolIn) {}
    StackItem(StackVec &&vchIn, std::optional<bool> cachedBoolIn = std::nullopt) noexcept
        : vch(std::move(vchIn)), cachedBool(cachedBoolIn) {}
    // Copy and move
    StackItem(const StackItem &) = default;
    StackItem(StackItem &&o) noexcept { *this = std::move(o); }

    StackItem &operator=(const StackItem &) = default;
    StackItem &operator=(StackItem &&o) noexcept {
        vch = std::move(o.vch);
        cachedBool = std::move(o.cachedBool);
        // explicitly clear and invalidate any caches `o` may have, to preserve class invariants, since `o` has mutated
        o.resetCaches();
        return *this;
    }

    // Preferred getter when modification is not necessary; caches do not get invalidated
    const StackVec & vec() const { return vch; }

    // Returning the mutable data resets any item-specific caches, since caller may modify the returned value.
    StackVec & mutableVec() {
        resetCaches();
        return vch;
    }

    // Convenience
    size_t size() const { return vec().size(); }
    bool empty() const { return vec().empty(); }
    StackVec::const_reference at(size_t i) const { return vec().at(i); }
    StackVec::const_reference operator[](size_t i) const { return vec()[i]; }
    friend inline void swap(StackItem &a, StackItem &b) {
        StackItem tmp(std::move(a));
        a = std::move(b);
        b = std::move(tmp);
    }

    // Cache ops
    std::optional<bool> getCachedBool() const { return cachedBool; }
    void setCachedBool(std::optional<bool> b) { cachedBool = b; }
    void resetCachedBool() { setCachedBool(std::nullopt); }
    // Resets all cached values
    void resetCaches() { resetCachedBool(); }

    // Equality -- note that equality only compares the vectors and not any cached metadata
    bool operator==(const StackItem &o) const noexcept { return vch == o.vch; }
    bool operator!=(const StackItem &o) const noexcept { return vch != o.vch; }
};

using StackT = std::vector<StackItem>; ///< used by the script interpreter as the stack type

using ByteView = std::span<const uint8_t>; ///< read-only view into a vector or other array type
