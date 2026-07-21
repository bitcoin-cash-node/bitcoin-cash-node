// Copyright (c) 2026-present The Bitcoin Cash Node developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#include <util/hwaccel.h>

#include <cstring>

#if defined(__x86_64__) && (defined(__clang__) || defined(__GNUC__)) && __has_include(<immintrin.h>)
#  define USE_X86_SIMD 1
#  include <immintrin.h>
#elif defined(__aarch64__) && __has_include(<arm_neon.h>)
#  define USE_ARM64_SIMD 1
#  include <arm_neon.h>
#endif

namespace hwaccel {

namespace detail {
    //! All-zero check for any n. Bulk of the range is done in 128-byte (or 64-byte) blocks (8 uint128s or 8 uint64s)
    //! with a key feature being that we do only one branch per block; the sub-blockSize remainder is folded via
    //! possibly overlapping wordSize loads.
    bool IsAllZerosPortable(const std::span<const std::byte> &bytes) noexcept {
#if HAVE_INT128
        using WordType = unsigned __int128;
#else
        using WordType = uint64_t;
#endif
        static constexpr size_t wordSize = sizeof(WordType);
        auto ReadWord = [](const std::byte *p) noexcept {
            WordType w;
            std::memcpy(&w, p, wordSize);
            return w;
        };

        const std::byte *p = bytes.data();
        const size_t n = bytes.size();

        if (n < wordSize) {
            std::byte acc{0};
            for (size_t i = 0; i < n; ++i) { acc |= p[i]; }
            return acc == std::byte{0};
        }
        const std::byte *end = p + n;
        if (n <= 2u * wordSize) {
            // Two possibly-overlapping loads cover [0, n) exactly.
            return (ReadWord(p) | ReadWord(end - wordSize)) == 0;
        }
        constexpr size_t blockSize = 8u * wordSize;
        while (static_cast<size_t>(end - p) >= blockSize) {
            const WordType a = ReadWord(p) | ReadWord(p + wordSize);
            const WordType b = ReadWord(p + 2u*wordSize) | ReadWord(p + 3u*wordSize);
            const WordType c = ReadWord(p + 4u*wordSize) | ReadWord(p + 5u*wordSize);
            const WordType d = ReadWord(p + 6u*wordSize) | ReadWord(p + 7u*wordSize);
            if ((a | b) | (c | d)) { return false; }
            p += blockSize;
        }
        WordType acc = 0;
        while (static_cast<size_t>(end - p) >= wordSize) { acc |= ReadWord(p); p += wordSize; }
        if (p < end) { acc |= ReadWord(end - wordSize); } // overlapping load; safe since at this point n >= wordSize
        return acc == 0;
    }
} // namespace detail

namespace {
#if USE_X86_SIMD
    // x86-64 kernels, selected once at runtime by CPU capability. They are only
    // invoked with n >= 128 but remain correct for any n. All three were fuzzed
    // against the reference byte loop for equivalence (sizes 0..10000, all
    // alignments, negative-zero patterns).

    // Unaligned vector loads expressed as memcpy: folds to (v)movups, and unlike
    // casting the byte pointer for _mm_loadu_si128 it does not trip -Wcast-align.
    inline __m128i Read128(const std::byte *p) noexcept {
        __m128i v;
        std::memcpy(&v, p, sizeof(v));
        return v;
    }

    __attribute__((target("avx2")))
    inline __m256i Read256(const std::byte *p) noexcept {
        __m256i v;
        std::memcpy(&v, p, sizeof(v));
        return v;
    }

    [[maybe_unused]]
    bool IsAllZerosSSE2(const std::span<const std::byte> &bytes) noexcept {
        const size_t n = bytes.size();
        if (n < 128u) return detail::IsAllZerosPortable(bytes);
        const std::byte *p = bytes.data();
        const std::byte *end = p + n;
        const __m128i zero = _mm_setzero_si128();
        while (end - p >= 128) {
            const __m128i a = _mm_or_si128(Read128(p), Read128(p + 16));
            const __m128i b = _mm_or_si128(Read128(p + 32), Read128(p + 48));
            const __m128i c = _mm_or_si128(Read128(p + 64), Read128(p + 80));
            const __m128i d = _mm_or_si128(Read128(p + 96), Read128(p + 112));
            const __m128i acc = _mm_or_si128(_mm_or_si128(a, b), _mm_or_si128(c, d));
            if (_mm_movemask_epi8(_mm_cmpeq_epi8(acc, zero)) != 0xFFFF) return false;
            p += 128;
        }
        __m128i acc = _mm_setzero_si128();
        while (end - p >= 16) { acc = _mm_or_si128(acc, Read128(p)); p += 16; }
        if (p < end) acc = _mm_or_si128(acc, Read128(end - 16)); // overlapping load; safe: n >= 128
        return _mm_movemask_epi8(_mm_cmpeq_epi8(acc, zero)) == 0xFFFF;
    }

    [[maybe_unused]]
    __attribute__((target("avx2")))
    bool IsAllZerosAVX2(const std::span<const std::byte> &bytes) noexcept {
        const size_t n = bytes.size();
        if (n < 128u) return detail::IsAllZerosPortable(bytes);
        const std::byte *p = bytes.data();
        const std::byte *end = p + n;
        while (end - p >= 256) {
            const __m256i a = _mm256_or_si256(Read256(p), Read256(p + 32));
            const __m256i b = _mm256_or_si256(Read256(p + 64), Read256(p + 96));
            const __m256i c = _mm256_or_si256(Read256(p + 128), Read256(p + 160));
            const __m256i d = _mm256_or_si256(Read256(p + 192), Read256(p + 224));
            const __m256i acc = _mm256_or_si256(_mm256_or_si256(a, b), _mm256_or_si256(c, d));
            if (!_mm256_testz_si256(acc, acc)) return false;
            p += 256;
        }
        __m256i acc = _mm256_setzero_si256();
        while (end - p >= 32) { acc = _mm256_or_si256(acc, Read256(p)); p += 32; }
        if (p < end) acc = _mm256_or_si256(acc, Read256(end - 32)); // overlapping load; safe: n >= 128
        return _mm256_testz_si256(acc, acc);
    }

    [[maybe_unused]]
    __attribute__((target("avx512f")))
    bool IsAllZerosAVX512(const std::span<const std::byte> &bytes) noexcept {
        const size_t n = bytes.size();
        if (n < 512u) return IsAllZerosAVX2(bytes);
        const std::byte *p = bytes.data();
        const std::byte *end = p + n;
        // Check the first (possibly misaligned) 64 bytes, then round p up to a
        // 64-byte boundary so no load in the bulk loop splits a cache line.
        const __m512i head = _mm512_loadu_si512(p);
        if (_mm512_test_epi64_mask(head, head)) return false;
        p += 64u - (uintptr_t(p) & 63u);
        while (end - p >= 512) {
            const __m512i a = _mm512_or_si512(_mm512_load_si512(p), _mm512_load_si512(p + 64));
            const __m512i b = _mm512_or_si512(_mm512_load_si512(p + 128), _mm512_load_si512(p + 192));
            const __m512i c = _mm512_or_si512(_mm512_load_si512(p + 256), _mm512_load_si512(p + 320));
            const __m512i d = _mm512_or_si512(_mm512_load_si512(p + 384), _mm512_load_si512(p + 448));
            const __m512i acc = _mm512_or_si512(_mm512_or_si512(a, b), _mm512_or_si512(c, d));
            if (_mm512_test_epi64_mask(acc, acc)) return false;
            p += 512;
        }
        __m512i acc = _mm512_setzero_si512();
        while (end - p >= 64) { acc = _mm512_or_si512(acc, _mm512_load_si512(p)); p += 64; }
        if (p < end) acc = _mm512_or_si512(acc, _mm512_loadu_si512(end - 64)); // safe: n >= 512
        return _mm512_test_epi64_mask(acc, acc) == 0;
    }
#endif // USE_X86_SIMD
#if USE_ARM64_SIMD
    // Horizontal max (single umaxv)
    static inline bool neon_nonzero_maxv(uint8x16_t v) noexcept {
        return vmaxvq_u32(vreinterpretq_u32_u8(v)) != 0;
    }
    /// Returns true if all bytes are zero. Features 8x unrolled accumulated OR (128 bytes per iteration).
    bool IsAllZerosARM64(const std::span<const std::byte> &bytes) noexcept {
        const uint8_t *p = reinterpret_cast<const uint8_t *>(bytes.data());
        const size_t n = bytes.size();
        const uint8_t *end = p + n;
        while (end - p >= 128) {
            const uint8x16_t a = vorrq_u8(vld1q_u8(p), vld1q_u8(p + 16));
            const uint8x16_t b = vorrq_u8(vld1q_u8(p + 32), vld1q_u8(p + 48));
            const uint8x16_t c = vorrq_u8(vld1q_u8(p + 64), vld1q_u8(p + 80));
            const uint8x16_t d = vorrq_u8(vld1q_u8(p + 96), vld1q_u8(p + 112));
            const uint8x16_t acc = vorrq_u8(vorrq_u8(a, b), vorrq_u8(c, d));
            if (neon_nonzero_maxv(acc)) return false;
            p += 128;
        }
        uint8x16_t acc = vdupq_n_u8(0);
        while (end - p >= 16) { acc = vorrq_u8(acc, vld1q_u8(p)); p += 16; }
        if (p < end) acc = vorrq_u8(acc, vld1q_u8(end - 16)); // overlap; safe: n >= 128
        return !neon_nonzero_maxv(acc);
    }
#endif
} // namespace

bool IsAllZeros(std::span<const std::byte> bytes) noexcept {
#if USE_X86_SIMD
    if (bytes.size() >= 128u) {
#  if HAVE_X86_BUILTIN_CPU_SUPPORTS
        static const auto hwspecific = [] {
            if (__builtin_cpu_supports("avx512f")) return &IsAllZerosAVX512;
            if (__builtin_cpu_supports("avx2")) return &IsAllZerosAVX2;
            if (__builtin_cpu_supports("sse2")) return &IsAllZerosSSE2;
            return &detail::IsAllZerosPortable;
        }();
        return hwspecific(bytes);
#  else
        // Cross-compiling on Linux for macOS x86-64 leads to this compile-time branch (such as on gitian builds).
        // This is because clang-18 that we use to cross-compile when using gitian expects the runtime libs to provide
        // the symbol: __cpu_model, but the macOS SDK does not have this symbol (perhaps it's inlined on apple-clang?).
        //
        // We can remove this branch for darwin x86-64 when we go beyond clang-18 for the cross compiler on gitian.
        return detail::IsAllZerosPortable(bytes);
#  endif /* HAVE_X86_BUILTIN_CPU_SUPPORTS */
    }
#elif USE_ARM64_SIMD
    if (bytes.size() >= 128u) {
        return IsAllZerosARM64(bytes);
    }
#endif
    return detail::IsAllZerosPortable(bytes);
}

} // namespace hwaccel
