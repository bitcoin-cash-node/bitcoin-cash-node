// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2021-present The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <util/hwaccel.h>

#include <cassert>
#include <cstdint>
#include <string>
#include <type_traits>
#include <vector>

/** Template base class for fixed-sized opaque blobs. */
template <unsigned int BITS> class base_blob {
protected:
    static constexpr unsigned WIDTH = BITS / 8;
    static_assert(WIDTH * 8 == BITS && WIDTH > 0, "BITS must be evenly divisible by 8 and larger than 0");
    uint8_t m_data[WIDTH];

public:
    constexpr base_blob() noexcept : m_data{0} {}

    /// type tag + convenience member for uninitialized c'tor
    static constexpr struct Uninitialized_t {} Uninitialized{};

    /// Uninitialized data constructor -- to be used when we want to avoid a
    /// redundant zero-initialization in cases where we know we will fill-in
    /// the data immediately anyway (e.g. for random generators, etc).
    /// Select this c'tor with e.g.: uint256 foo{uint256::Uninitialized}
    explicit constexpr base_blob(Uninitialized_t /* type tag to select this c'tor */) noexcept {}

    explicit base_blob(const std::vector<uint8_t> &vch) noexcept;

    constexpr bool IsNull() const noexcept {
        if (std::is_constant_evaluated()) {
            unsigned i = 0;
            do {
                if (m_data[i] != 0)
                    return false;
            } while (++i < WIDTH);
            return true;
        } else {
            return hwaccel::IsAllZeros({m_data, WIDTH});
        }
    }

    constexpr void SetNull() noexcept { *this = base_blob{}; }

    constexpr int Compare(const base_blob &other) const noexcept {
        // compare MSB-first (in reverse because data is little endian)
        unsigned i = WIDTH - 1;
        do {
            const uint8_t a = m_data[i];
            const uint8_t b = other.m_data[i];

            if (a > b) {
                return 1;
            }
            if (a < b) {
                return -1;
            }
        } while (i-- != 0);

        return 0;
    }

    friend inline constexpr bool operator==(const base_blob &a, const base_blob &b) noexcept {
        return a.Compare(b) == 0;
    }
    friend inline constexpr bool operator!=(const base_blob &a, const base_blob &b) noexcept {
        return a.Compare(b) != 0;
    }
    friend inline constexpr bool operator<(const base_blob &a, const base_blob &b) noexcept {
        return a.Compare(b) < 0;
    }
    friend inline constexpr bool operator<=(const base_blob &a, const base_blob &b) noexcept {
        return a.Compare(b) <= 0;
    }
    friend inline constexpr bool operator>(const base_blob &a, const base_blob &b) noexcept {
        return a.Compare(b) > 0;
    }
    friend inline constexpr bool operator>=(const base_blob &a, const base_blob &b) noexcept {
        return a.Compare(b) >= 0;
    }

    std::string GetHex() const;
    void SetHex(const char *psz) noexcept;
    void SetHex(const std::string &str) noexcept;
    std::string ToString() const { return GetHex(); }

    constexpr const uint8_t *data() const noexcept { return &m_data[0]; }
    constexpr uint8_t *data() noexcept { return &m_data[0]; }

    constexpr uint8_t *begin() noexcept { return &m_data[0]; }

    constexpr uint8_t *end() noexcept { return begin() + size(); }

    constexpr const uint8_t *begin() const noexcept { return &m_data[0]; }

    constexpr const uint8_t *end() const noexcept { return begin() + size(); }

    static constexpr unsigned size() noexcept { return WIDTH; }

    constexpr uint64_t GetUint64(int pos) const noexcept {
        const uint8_t *const ptr = &m_data[pos * 8];
        return uint64_t(ptr[0]) | (uint64_t(ptr[1]) << 8) |
               (uint64_t(ptr[2]) << 16) | (uint64_t(ptr[3]) << 24) |
               (uint64_t(ptr[4]) << 32) | (uint64_t(ptr[5]) << 40) |
               (uint64_t(ptr[6]) << 48) | (uint64_t(ptr[7]) << 56);
    }

    template <typename Stream> void Serialize(Stream &s) const {
        s.write(reinterpret_cast<const char *>(begin()), size());
    }

    template <typename Stream> void Unserialize(Stream &s) {
        s.read(reinterpret_cast<char *>(begin()), size());
    }
};

/**
 * 160-bit opaque blob.
 * @note This type is called uint160 for historical reasons only. It is an
 * opaque blob of 160 bits and has no integer operations.
 */
class uint160 : public base_blob<160> {
public:
    using base_blob<160>::base_blob; ///< inherit constructors
};

/**
 * 256-bit opaque blob.
 * @note This type is called uint256 for historical reasons only. It is an
 * opaque blob of 256 bits and has no integer operations. Use arith_uint256 if
 * those are required.
 */
class uint256 : public base_blob<256> {
public:
    using base_blob<256>::base_blob; ///< inherit constructors
};

/**
 * uint256 from const char *.
 * This is a separate function because the constructor uint256(const char*) can
 * result in dangerously catching uint256(0).
 */
inline uint256 uint256S(const char *str) noexcept {
    uint256 rv{uint256::Uninitialized};
    rv.SetHex(str);
    return rv;
}

/**
 * uint256 from std::string.
 * This is a separate function because the constructor uint256(const std::string
 * &str) can result in dangerously catching uint256(0) via std::string(const
 * char*).
 */
inline uint256 uint256S(const std::string &str) noexcept {
    uint256 rv{uint256::Uninitialized};
    rv.SetHex(str);
    return rv;
}

inline uint160 uint160S(const char *str) noexcept {
    uint160 rv{uint160::Uninitialized};
    rv.SetHex(str);
    return rv;
}
inline uint160 uint160S(const std::string &str) noexcept {
    uint160 rv{uint160::Uninitialized};
    rv.SetHex(str);
    return rv;
}
