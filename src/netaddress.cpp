// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017-2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifdef HAVE_CONFIG_H
#include <config/bitcoin-config.h>
#endif

#include <crypto/common.h>
#include <crypto/sha3.h>
#include <hash.h>
#include <netaddress.h>
#include <prevector.h>
#include <random.h>
#include <tinyformat.h>
#include <util/asmap.h>
#include <util/bit_cast.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <span.h>

#include <algorithm>
#include <array>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <ios>
#include <iterator>
#include <limits>
#include <string_view>
#include <tuple>

static constexpr uint8_t pchSingleAddressNetmask[16] =
    {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

CNetAddr::BIP155Network CNetAddr::GetBIP155Network() const {
    switch (m_net) {
        case NET_IPV4:
            return BIP155Network::IPV4;
        case NET_IPV6:
            return BIP155Network::IPV6;
        case NET_ONION:
            switch (m_addr.size()) {
                case ADDR_TORV2_SIZE:
                    return BIP155Network::TORV2;
                case ADDR_TORV3_SIZE:
                    return BIP155Network::TORV3;
                default:
                    assert(false);
            }
        case NET_I2P:
            return BIP155Network::I2P;
        case NET_CJDNS:
            return BIP155Network::CJDNS;
        case NET_INTERNAL:   // should have been handled before calling this function
        case NET_UNROUTABLE: // m_net is never and should not be set to NET_UNROUTABLE
        case NET_MAX:        // m_net is never and should not be set to NET_MAX
            assert(false);
    } // no default case, so the compiler can warn about missing cases

    assert(false);
}

bool CNetAddr::SetNetFromBIP155Network(uint8_t possible_bip155_net, size_t address_size) {
    switch (possible_bip155_net) {
        case BIP155Network::IPV4:
            if (address_size == ADDR_IPV4_SIZE) {
                m_net = NET_IPV4;
                return true;
            }
            throw std::ios_base::failure(
                strprintf("BIP155 IPv4 address with length %u (should be %u)", address_size, ADDR_IPV4_SIZE));
        case BIP155Network::IPV6:
            if (address_size == ADDR_IPV6_SIZE) {
                m_net = NET_IPV6;
                return true;
            }
            throw std::ios_base::failure(
                strprintf("BIP155 IPv6 address with length %u (should be %u)", address_size, ADDR_IPV6_SIZE));
        case BIP155Network::TORV2:
            if (address_size == ADDR_TORV2_SIZE) {
                m_net = NET_ONION;
                return true;
            }
            throw std::ios_base::failure(
                strprintf("BIP155 TORv2 address with length %u (should be %u)", address_size, ADDR_TORV2_SIZE));
        case BIP155Network::TORV3:
            if (address_size == ADDR_TORV3_SIZE) {
                m_net = NET_ONION;
                return true;
            }
            throw std::ios_base::failure(
                strprintf("BIP155 TORv3 address with length %u (should be %u)", address_size, ADDR_TORV3_SIZE));
        case BIP155Network::I2P:
            if (address_size == ADDR_I2P_SIZE) {
                m_net = NET_I2P;
                return true;
            }
            throw std::ios_base::failure(
                strprintf("BIP155 I2P address with length %u (should be %u)", address_size, ADDR_I2P_SIZE));
        case BIP155Network::CJDNS:
            if (address_size == ADDR_CJDNS_SIZE) {
                m_net = NET_CJDNS;
                return true;
            }
            throw std::ios_base::failure(
                strprintf("BIP155 CJDNS address with length %u (should be %u)", address_size, ADDR_CJDNS_SIZE));
    }

    // Don't throw on addresses with unknown network ids (maybe from the future).
    // Instead silently drop them and have the unserialization code consume
    // subsequent ones which may be known to us.
    return false;
}

void CNetAddr::SetIP(const CNetAddr &ipIn) {
    // Size check.
    switch (ipIn.m_net) {
        case NET_IPV4:
            assert(ipIn.m_addr.size() == ADDR_IPV4_SIZE);
            break;
        case NET_IPV6:
            assert(ipIn.m_addr.size() == ADDR_IPV6_SIZE);
            break;
        case NET_ONION:
            assert(ipIn.m_addr.size() == ADDR_TORV2_SIZE || ipIn.m_addr.size() == ADDR_TORV3_SIZE);
            break;
        case NET_I2P:
            assert(ipIn.m_addr.size() == ADDR_I2P_SIZE);
            break;
        case NET_CJDNS:
            assert(ipIn.m_addr.size() == ADDR_CJDNS_SIZE);
            break;
        case NET_INTERNAL:
            assert(ipIn.m_addr.size() == ADDR_INTERNAL_SIZE);
            break;
        case NET_UNROUTABLE:
        case NET_MAX:
            assert(false);
    } // no default case, so the compiler can warn about missing cases

    m_net = ipIn.m_net;
    m_addr = ipIn.m_addr;
}

void CNetAddr::SetLegacyIPv6(Span<const uint8_t> ipv6) {
    assert(ipv6.size() == ADDR_IPV6_SIZE);

    size_t skip{};

    if (HasPrefix(ipv6, IPV4_IN_IPV6_PREFIX)) {
        // IPv4-in-IPv6
        m_net = NET_IPV4;
        skip = IPV4_IN_IPV6_PREFIX.size();
    } else if (HasPrefix(ipv6, TORV2_IN_IPV6_PREFIX)) {
        // TORv2-in-IPv6
        m_net = NET_ONION;
        skip = TORV2_IN_IPV6_PREFIX.size();
    } else if (HasPrefix(ipv6, INTERNAL_IN_IPV6_PREFIX)) {
        // Internal-in-IPv6
        m_net = NET_INTERNAL;
        skip = INTERNAL_IN_IPV6_PREFIX.size();
    } else {
        // IPv6
        m_net = NET_IPV6;
    }
    const auto subspan = ipv6.subspan(skip);
    m_addr.assign(subspan.begin(), subspan.end());
}

/**
 * Create an "internal" address that represents a name or FQDN. CAddrMan uses
 * these fake addresses to keep track of which DNS seeds were used.
 * @returns Whether or not the operation was successful.
 * @see NET_INTERNAL, INTERNAL_IN_IPV6_PREFIX, CNetAddr::IsInternal(), CNetAddr::IsRFC4193()
 */
bool CNetAddr::SetInternal(const std::string &name) {
    if (name.empty()) {
        return false;
    }
    m_net = NET_INTERNAL;
    uint8_t hash[32] = {};
    CSHA256().Write(reinterpret_cast<const uint8_t *>(name.data()), name.size()).Finalize(hash);
    static_assert(ADDR_INTERNAL_SIZE <= 32);
    m_addr.assign(hash, hash + ADDR_INTERNAL_SIZE);
    return true;
}

namespace torv3 {
// https://gitweb.torproject.org/torspec.git/tree/rend-spec-v3.txt#n2135
inline constexpr size_t CHECKSUM_LEN = 2;
inline constexpr std::array<uint8_t, 1> VERSION = {{3}};
inline constexpr size_t TOTAL_LEN = ADDR_TORV3_SIZE + CHECKSUM_LEN + VERSION.size();
using ChecksumBytes = std::array<uint8_t, CHECKSUM_LEN>;

static ChecksumBytes Checksum(Span<const uint8_t> addr_pubkey) {
    // TORv3 CHECKSUM = H(".onion checksum" | PUBKEY | VERSION)[:2]
    using namespace std::string_view_literals;
    SHA3_256 hasher;

    hasher.Write(MakeUInt8Span(".onion checksum"sv));
    hasher.Write(addr_pubkey);
    hasher.Write(VERSION);

    std::array<uint8_t, SHA3_256::OUTPUT_SIZE> checksum_full;

    hasher.Finalize(checksum_full);

    ChecksumBytes ret;
    static_assert(checksum_full.size() >= ret.size());
    std::copy_n(checksum_full.begin(), ret.size(), ret.begin());
    return ret;
}

}; // namespace torv3

/**
 * Parse a TOR address and set this object to it.
 *
 * @returns Whether or not the operation was successful.
 *
 * @see CNetAddr::IsTor()
 */
bool CNetAddr::SetSpecial(const std::string &str) {
    using namespace std::string_view_literals;
    constexpr auto suffix = ".onion"sv;

    if (!ValidAsCString(str) || str.size() <= suffix.size()
        || static_cast<std::string_view>(str).substr(str.size() - suffix.size()) != suffix) {
        return false;
    }

    bool invalid;
    const auto &input = DecodeBase32(str.substr(0, str.size() - suffix.size()).c_str(), &invalid);

    if (invalid) {
        return false;
    }

    switch (input.size()) {
        case ADDR_TORV2_SIZE:
            m_net = NET_ONION;
            m_addr.assign(input.begin(), input.end());
            return true;
        case torv3::TOTAL_LEN: {
            Span<const uint8_t> input_pubkey{input.data(), ADDR_TORV3_SIZE};
            Span<const uint8_t> input_checksum{input.data() + ADDR_TORV3_SIZE, torv3::CHECKSUM_LEN};
            Span<const uint8_t> input_version{input.data() + ADDR_TORV3_SIZE + torv3::CHECKSUM_LEN,
                                              torv3::VERSION.size()};

            const auto calculated_checksum = torv3::Checksum(input_pubkey);

            if (input_checksum != calculated_checksum || input_version != torv3::VERSION) {
                return false;
            }

            m_net = NET_ONION;
            m_addr.assign(input_pubkey.begin(), input_pubkey.end());
            return true;
        }
    }

    return false;
}

CNetAddr::CNetAddr(const struct in_addr &ipv4Addr) {
    static_assert(sizeof(ipv4Addr) == ADDR_IPV4_SIZE, "struct in_addr must be exactly ADDR_IPV4_SIZE bytes (4)");
    m_net = NET_IPV4;
    const uint8_t *ptr = reinterpret_cast<const uint8_t *>(&ipv4Addr);
    m_addr.assign(ptr, ptr + ADDR_IPV4_SIZE);
}

CNetAddr::CNetAddr(const struct in6_addr &ipv6Addr, const uint32_t scope) {
    static_assert(sizeof(ipv6Addr) == ADDR_IPV6_SIZE, "struct in6_addr must be exactly ADDR_IPV6_SIZE bytes (16)");
    SetLegacyIPv6({reinterpret_cast<const uint8_t *>(&ipv6Addr), ADDR_IPV6_SIZE});
    scopeId = scope;
}

bool CNetAddr::IsBindAny() const {
    if (!IsIPv4() && !IsIPv6()) {
        return false;
    }

    return std::all_of(m_addr.begin(), m_addr.end(), [](uint8_t b) { return b == 0; });
}

bool CNetAddr::IsIPv4() const {
    return m_net == NET_IPV4;
}

bool CNetAddr::IsIPv6() const {
    return m_net == NET_IPV6;
}

bool CNetAddr::IsRFC1918() const {
    return IsIPv4() && (
        m_addr[0] == 10 ||
        (m_addr[0] == 192 && m_addr[1] == 168) ||
        (m_addr[0] == 172 && m_addr[1] >= 16 && m_addr[1] <= 31));
}

bool CNetAddr::IsRFC2544() const {
    return IsIPv4() && m_addr[0] == 198 && (m_addr[1] == 18 || m_addr[1] == 19);
}

bool CNetAddr::IsRFC3927() const {
    return IsIPv4() && HasPrefix(m_addr, std::array<uint8_t, 2>{{169, 254}});
}

bool CNetAddr::IsRFC6598() const {
    return IsIPv4() && m_addr[0] == 100 && m_addr[1] >= 64 && m_addr[1] <= 127;
}

bool CNetAddr::IsRFC5737() const {
    return IsIPv4() && (HasPrefix(m_addr, std::array<uint8_t, 3>{{192, 0, 2}}) ||
                        HasPrefix(m_addr, std::array<uint8_t, 3>{{198, 51, 100}}) ||
                        HasPrefix(m_addr, std::array<uint8_t, 3>{{203, 0, 113}}));
}

bool CNetAddr::IsRFC3849() const {
    return IsIPv6() && HasPrefix(m_addr, std::array<uint8_t, 4>{{0x20, 0x01, 0x0D, 0xB8}});
}

bool CNetAddr::IsRFC3964() const {
    return IsIPv6() && HasPrefix(m_addr, std::array<uint8_t, 2>{{0x20, 0x02}});
}

bool CNetAddr::IsRFC6052() const {
    return IsIPv6() &&
           HasPrefix(m_addr, std::array<uint8_t, 12>{{0x00, 0x64, 0xFF, 0x9B, 0x00, 0x00,
                                                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00}});
}

bool CNetAddr::IsRFC4380() const {
    return IsIPv6() && HasPrefix(m_addr, std::array<uint8_t, 4>{{0x20, 0x01, 0x00, 0x00}});
}

bool CNetAddr::IsRFC4862() const {
    return IsIPv6() && HasPrefix(m_addr, std::array<uint8_t, 8>{{0xFE, 0x80, 0x00, 0x00,
                                                                 0x00, 0x00, 0x00, 0x00}});
}

bool CNetAddr::IsRFC4193() const {
    return IsIPv6() && (m_addr[0] & 0xFE) == 0xFC;
}

bool CNetAddr::IsRFC6145() const {
    return IsIPv6() &&
           HasPrefix(m_addr, std::array<uint8_t, 12>{{0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                                      0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00}});
}

bool CNetAddr::IsRFC4843() const {
    return IsIPv6() && HasPrefix(m_addr, std::array<uint8_t, 3>{{0x20, 0x01, 0x00}}) &&
           (m_addr[3] & 0xF0) == 0x10;
}

bool CNetAddr::IsRFC7343() const {
    return IsIPv6() && HasPrefix(m_addr, std::array<uint8_t, 3>{{0x20, 0x01, 0x00}}) &&
           (m_addr[3] & 0xF0) == 0x20;
}

bool CNetAddr::IsHeNet() const {
    return IsIPv6() && HasPrefix(m_addr, std::array<uint8_t, 4>{{0x20, 0x01, 0x04, 0x70}});
}

/**
 * Check whether this object represents a TOR address.
 * @see CNetAddr::SetSpecial(const std::string &)
 */
bool CNetAddr::IsTor() const {
    return m_net == NET_ONION;
}

/**
 * Check whether this object represents an I2P address.
 */
bool CNetAddr::IsI2P() const {
    return m_net == NET_I2P;
}

/**
 * Check whether this object represents a CJDNS address.
 */
bool CNetAddr::IsCJDNS() const {
    return m_net == NET_CJDNS;
}

bool CNetAddr::IsLocal() const {
    // IPv4 loopback (127.0.0.0/8 or 0.0.0.0/8)
    if (IsIPv4() && (m_addr[0] == 127 || m_addr[0] == 0)) {
        return true;
    }

    // IPv6 loopback (::1/128)
    constexpr uint8_t pchLocal[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    if (IsIPv6() && Span{m_addr} == Span{pchLocal}) {
        return true;
    }

    return false;
}

/**
 * @returns Whether or not this network address is a valid address that @a could
 *          be used to refer to an actual host.
 *
 * @note A valid address may or may not be publicly routable on the global
 *       internet. As in, the set of valid addresses is a superset of the set of
 *       publicly routable addresses.
 *
 * @see CNetAddr::IsRoutable()
 */
bool CNetAddr::IsValid() const
{
    // unspecified IPv6 address (::/128)
    constexpr uint8_t ipNone6[16] = {};
    if (IsIPv6() && Span{m_addr} == Span{ipNone6}) {
        return false;
    }

    // documentation IPv6 address
    if (IsRFC3849()) {
        return false;
    }

    if (IsInternal()) {
        return false;
    }

    if (IsIPv4()) {
        const uint32_t addr = ReadBE32(m_addr.data());
        if (addr == INADDR_ANY || addr == INADDR_NONE) {
            return false;
        }
    }

    return true;
}

/**
 * @returns Whether or not this network address is publicly routable on the
 *          global internet.
 *
 * @note A routable address is always valid. As in, the set of routable addreses
 *       is a subset of the set of valid addresses.
 *
 * @see CNetAddr::IsValid()
 */
bool CNetAddr::IsRoutable() const {
    return IsValid() &&
           !(IsRFC1918() || IsRFC2544() || IsRFC3927() || IsRFC4862() ||
             IsRFC6598() || IsRFC5737() || (IsRFC4193() && !IsTor()) ||
             IsRFC4843() || IsRFC7343() || IsLocal() || IsInternal());
}

/**
 * @returns Whether or not this is a dummy address that represents a name.
 *
 * @see CNetAddr::SetInternal(const std::string &)
 */
bool CNetAddr::IsInternal() const {
    return m_net == NET_INTERNAL;
}

bool CNetAddr::IsAddrV1Compatible() const {
    switch (m_net) {
        case NET_IPV4:
        case NET_IPV6:
        case NET_INTERNAL:
            return true;
        case NET_ONION:
            return m_addr.size() == ADDR_TORV2_SIZE;
        case NET_I2P:
        case NET_CJDNS:
            return false;
        case NET_UNROUTABLE: // m_net is never and should not be set to NET_UNROUTABLE
        case NET_MAX:        // m_net is never and should not be set to NET_MAX
            assert(false);
    } // no default case, so the compiler can warn about missing cases

    assert(false);
}

Network CNetAddr::GetNetwork() const {
    if (IsInternal()) {
        return NET_INTERNAL;
    }

    if (!IsRoutable()) {
        return NET_UNROUTABLE;
    }

    return m_net;
}

static std::string IPv4ToString(Span<const uint8_t> a) {
    assert(a.size() == ADDR_IPV4_SIZE);
    return strprintf("%u.%u.%u.%u", a[0], a[1], a[2], a[3]);
}

static std::string IPv6ToString(Span<const uint8_t> a) {
    assert(a.size() == ADDR_IPV6_SIZE);
    // clang-format off
    return strprintf("%x:%x:%x:%x:%x:%x:%x:%x",
                     ReadBE16(&a[0]),
                     ReadBE16(&a[2]),
                     ReadBE16(&a[4]),
                     ReadBE16(&a[6]),
                     ReadBE16(&a[8]),
                     ReadBE16(&a[10]),
                     ReadBE16(&a[12]),
                     ReadBE16(&a[14]));
    // clang-format on
}

std::string CNetAddr::ToStringIP() const {
    switch (m_net) {
        case NET_IPV4:
            return IPv4ToString(m_addr);
        case NET_IPV6: {
            CService serv(*this, 0);
            if (const auto optPair = serv.GetSockAddr()) {
                auto &[sockaddr, socklen] = *optPair;
                char name[1025] = "";
                if (!getnameinfo((const struct sockaddr *)&sockaddr, socklen, name, sizeof(name), nullptr, 0,
                                 NI_NUMERICHOST)) {
                    return std::string(name);
                }
            }
            return IPv6ToString(m_addr);
        }
        case NET_ONION:
            switch (m_addr.size()) {
                case ADDR_TORV2_SIZE:
                    return EncodeBase32(m_addr) + ".onion";
                case ADDR_TORV3_SIZE: {
                    const auto checksum = torv3::Checksum(m_addr);

                    // TORv3 onion_address = base32(PUBKEY | CHECKSUM | VERSION) + ".onion"
                    prevector<torv3::TOTAL_LEN, uint8_t> address{m_addr.begin(), m_addr.end()};
                    address.insert(address.end(), checksum.begin(), checksum.end());
                    address.insert(address.end(), torv3::VERSION.begin(), torv3::VERSION.end());

                    return EncodeBase32(address) + ".onion";
                }
                default:
                    assert(false);
            }
        case NET_I2P:
            return EncodeBase32(m_addr, false /* don't pad with = */) + ".b32.i2p";
        case NET_CJDNS:
            return IPv6ToString(m_addr);
        case NET_INTERNAL:
            return EncodeBase32(m_addr) + ".internal";
        case NET_UNROUTABLE: // m_net is never and should not be set to NET_UNROUTABLE
        case NET_MAX:        // m_net is never and should not be set to NET_MAX
            assert(false);
            break; // prevent compiler warnings if compiling with -Wimplicit-fallthrough
    } // no default case, so the compiler can warn about missing cases

    assert(false);
    return {}; // not reached: prevent compiler warnings about missing return
}

std::string CNetAddr::ToString() const {
    return ToStringIP();
}

bool operator==(const CNetAddr &a, const CNetAddr &b) {
    return a.m_net == b.m_net && a.m_addr == b.m_addr;
}

bool operator<(const CNetAddr &a, const CNetAddr &b) {
    return std::tie(a.m_net, a.m_addr) < std::tie(b.m_net, b.m_addr);
}

/**
 * Try to get our IPv4 address.
 *
 * @param[out] pipv4Addr The in_addr struct to which to copy.
 *
 * @returns Whether or not the operation was successful, in particular, whether
 *          or not our address was an IPv4 address.
 *
 * @see CNetAddr::IsIPv4()
 */
bool CNetAddr::GetInAddr(struct in_addr *pipv4Addr) const {
    if (!IsIPv4()) {
        return false;
    }
    assert(sizeof(*pipv4Addr) == m_addr.size());
    std::memcpy(pipv4Addr, m_addr.data(), m_addr.size());
    return true;
}

/**
 * Try to get our IPv6 address.
 *
 * @param[out] pipv6Addr The in6_addr struct to which to copy.
 *
 * @returns Whether or not the operation was successful, in particular, whether
 *          or not our address was an IPv6 address.
 *
 * @see CNetAddr::IsIPv6()
 */
bool CNetAddr::GetIn6Addr(struct in6_addr *pipv6Addr) const {
    if (!IsIPv6()) {
        return false;
    }
    assert(sizeof(*pipv6Addr) == m_addr.size());
    std::memcpy(pipv6Addr, m_addr.data(), m_addr.size());
    return true;
}

bool CNetAddr::HasLinkedIPv4() const {
    return IsRoutable() && (IsIPv4() || IsRFC6145() || IsRFC6052() || IsRFC3964() || IsRFC4380());
}

uint32_t CNetAddr::GetLinkedIPv4() const {
    if (IsIPv4()) {
        return ReadBE32(m_addr.data());
    } else if (IsRFC6052() || IsRFC6145()) {
        // mapped IPv4, SIIT translated IPv4: the IPv4 address is the last 4 bytes of the address
        return ReadBE32(Span{m_addr}.last(ADDR_IPV4_SIZE).data());
    } else if (IsRFC3964()) {
        // 6to4 tunneled IPv4: the IPv4 address is in bytes 2-6
        return ReadBE32(Span{m_addr}.subspan(2, ADDR_IPV4_SIZE).data());
    } else if (IsRFC4380()) {
        // Teredo tunneled IPv4: the IPv4 address is in the last 4 bytes of the address, but bitflipped
        return ~ReadBE32(Span{m_addr}.last(ADDR_IPV4_SIZE).data());
    }
    assert(false);
}

Network CNetAddr::GetNetClass() const {
    // Make sure that if we return NET_IPV6, then IsIPv6() is true. The callers expect that.

    // Check for "internal" first because such addresses are also !IsRoutable()
    // and we don't want to return NET_UNROUTABLE in that case.
    if (IsInternal()) {
        return NET_INTERNAL;
    }
    if (!IsRoutable()) {
        return NET_UNROUTABLE;
    }
    if (HasLinkedIPv4()) {
        return NET_IPV4;
    }
    return m_net;
}

uint32_t CNetAddr::GetMappedAS(const std::vector<bool> &asmap) const {
    if (Network net_class;
            asmap.size() == 0 || ((net_class = GetNetClass()) != NET_IPV4 && net_class != NET_IPV6)) {
        return 0; // Indicates not found, safe because AS0 is reserved per RFC7607.
    }
    std::vector<bool> ip_bits(128);
    if (HasLinkedIPv4()) {
        // For lookup, treat as if it was just an IPv4 address (IPV4_IN_IPV6_PREFIX + IPv4 bits)
        for (int8_t byte_i = 0; byte_i < 12; ++byte_i) {
            for (uint8_t bit_i = 0; bit_i < 8; ++bit_i) {
                ip_bits[byte_i * 8 + bit_i] = (IPV4_IN_IPV6_PREFIX[byte_i] >> (7 - bit_i)) & 1;
            }
        }
        uint32_t ipv4 = GetLinkedIPv4();
        for (int i = 0; i < 32; ++i) {
            ip_bits[96 + i] = (ipv4 >> (31 - i)) & 1;
        }
    } else {
        // Use all 128 bits of the IPv6 address otherwise
        assert(IsIPv6());
        for (int8_t byte_i = 0; byte_i < 16; ++byte_i) {
            uint8_t cur_byte = m_addr[byte_i];
            for (uint8_t bit_i = 0; bit_i < 8; ++bit_i) {
                ip_bits[byte_i * 8 + bit_i] = (cur_byte >> (7 - bit_i)) & 1;
            }
        }
    }
    uint32_t mapped_as = Interpret(asmap, ip_bits);
    return mapped_as;
}

/**
 * Get the canonical identifier of our network group
 *
 * The groups are assigned in a way where it should be costly for an attacker to
 * obtain addresses with many different group identifiers, even if it is cheap
 * to obtain addresses with the same identifier.
 *
 * @note No two connections will be attempted to addresses with the same network
 *       group.
 */
std::vector<uint8_t> CNetAddr::GetGroup(const std::vector<bool> &asmap) const {
    std::vector<uint8_t> vchRet;
    // If non-empty asmap is supplied and the address is IPv4/IPv6,
    // return ASN to be used for bucketing.
    uint32_t asn = GetMappedAS(asmap);
    if (asn != 0) { // Either asmap was empty, or address has non-asmappable net class (e.g. TOR).
        vchRet.push_back(NET_IPV6); // IPv4 and IPv6 with same ASN should be in the same bucket
        for (int i = 0; i < 4; i++) {
            vchRet.push_back((asn >> (8 * i)) & 0xFF);
        }
        return vchRet;
    }

    vchRet.push_back(static_cast<uint8_t>(GetNetClass()));
    int nBits{0};

    if (IsLocal()) {
        // all local addresses belong to the same group
    } else if (IsInternal()) {
        // all internal-usage addresses get their own group
        nBits = ADDR_INTERNAL_SIZE * 8;
    } else if (!IsRoutable()) {
        // all other unroutable addresses belong to the same group
    } else if (HasLinkedIPv4()) {
        // IPv4 addresses (and mapped IPv4 addresses) use /16 groups
        uint32_t ipv4 = GetLinkedIPv4();
        vchRet.push_back((ipv4 >> 24) & 0xFF);
        vchRet.push_back((ipv4 >> 16) & 0xFF);
        return vchRet;
    } else if (IsTor() || IsI2P() || IsCJDNS()) {
        nBits = 4;
    } else if (IsHeNet()) {
        // for he.net, use /36 groups
        nBits = 36;
    } else {
        // for the rest of the IPv6 network, use /32 groups
        nBits = 32;
    }

    // Push our address onto vchRet.
    const size_t num_bytes = nBits / 8;
    vchRet.insert(vchRet.end(), m_addr.begin(), m_addr.begin() + num_bytes);
    nBits %= 8;
    // ...for the last byte, push nBits and for the rest of the byte push 1's
    if (nBits > 0) {
        assert(num_bytes < m_addr.size());
        vchRet.push_back(m_addr[num_bytes] | ((1 << (8 - nBits)) - 1));
    }

    return vchRet;
}

std::vector<uint8_t> CNetAddr::GetAddrBytes() const {
    std::vector<uint8_t> ret;
    if (IsAddrV1Compatible()) {
        const auto v1arr = SerializeV1Array();
        ret.reserve(v1arr.size());
        ret.assign(v1arr.begin(), v1arr.end());
    } else {
        ret.reserve(m_addr.size());
        ret.assign(m_addr.begin(), m_addr.end());
    }
    return ret;
}

uint64_t CNetAddr::GetHash() const {
    const uint256 hash = Hash(m_addr);
    uint64_t nRet;
    static_assert(sizeof(nRet) <= hash.size());
    std::memcpy(&nRet, &*hash.begin(), sizeof(nRet));
    return nRet;
}

/** Calculates a metric for how reachable (*this) is from a given partner */
int CNetAddr::GetReachabilityFrom(const CNetAddr *paddrPartner) const {

    // private extensions to enum Network, only returned by GetExtNetwork, and only
    // used in GetReachabilityFrom
    static constexpr int NET_UNKNOWN = NET_MAX + 0;
    static constexpr int NET_TEREDO = NET_MAX + 1;
    static auto GetExtNetwork = [](const CNetAddr *addr) -> int {
        if (addr == nullptr) {
            return NET_UNKNOWN;
        }
        if (addr->IsRFC4380()) {
            return NET_TEREDO;
        }
        return addr->GetNetwork();
    };

    enum Reachability {
        REACH_UNREACHABLE,
        REACH_DEFAULT,
        REACH_TEREDO,
        REACH_IPV6_WEAK,
        REACH_IPV4,
        REACH_IPV6_STRONG,
        REACH_PRIVATE
    };

    if (!IsRoutable() || IsInternal()) {
        return REACH_UNREACHABLE;
    }

    int ourNet = GetExtNetwork(this);
    int theirNet = GetExtNetwork(paddrPartner);
    bool fTunnel = IsRFC3964() || IsRFC6052() || IsRFC6145();

    switch (theirNet) {
        case NET_IPV4:
            switch (ourNet) {
                default:
                    return REACH_DEFAULT;
                case NET_IPV4:
                    return REACH_IPV4;
            }
        case NET_IPV6:
            switch (ourNet) {
                default:
                    return REACH_DEFAULT;
                case NET_TEREDO:
                    return REACH_TEREDO;
                case NET_IPV4:
                    return REACH_IPV4;
                // only prefer giving our IPv6 address if it's not tunnelled
                case NET_IPV6:
                    return fTunnel ? REACH_IPV6_WEAK : REACH_IPV6_STRONG;
            }
        case NET_ONION:
            switch (ourNet) {
                default:
                    return REACH_DEFAULT;
                // Tor users can connect to IPv4 as well
                case NET_IPV4:
                    return REACH_IPV4;
                case NET_ONION:
                    return REACH_PRIVATE;
            }
        case NET_TEREDO:
            switch (ourNet) {
                default:
                    return REACH_DEFAULT;
                case NET_TEREDO:
                    return REACH_TEREDO;
                case NET_IPV6:
                    return REACH_IPV6_WEAK;
                case NET_IPV4:
                    return REACH_IPV4;
            }
        case NET_UNKNOWN:
        case NET_UNROUTABLE:
        default:
            switch (ourNet) {
                default:
                    return REACH_DEFAULT;
                case NET_TEREDO:
                    return REACH_TEREDO;
                case NET_IPV6:
                    return REACH_IPV6_WEAK;
                case NET_IPV4:
                    return REACH_IPV4;
                // either from Tor, or don't care about our address
                case NET_ONION:
                    return REACH_PRIVATE;
            }
    }
}

CService::CService(const struct sockaddr_in &addr)
    : CNetAddr(addr.sin_addr), port(ntohs(addr.sin_port)) {
    assert(addr.sin_family == AF_INET);
}

CService::CService(const struct sockaddr_in6 &addr)
    : CNetAddr(addr.sin6_addr, addr.sin6_scope_id),
      port(ntohs(addr.sin6_port)) {
    assert(addr.sin6_family == AF_INET6);
}

bool CService::SetSockAddr(const sockaddr_storage &addr) {
    switch (addr.ss_family) {
        case AF_INET:
            *this = CService(bit_cast<sockaddr_in>(addr));
            return true;
        case AF_INET6:
            *this = CService(bit_cast<sockaddr_in6>(addr));
            return true;
        default:
            return false;
    }
}

bool operator==(const CService &a, const CService &b) {
    return static_cast<CNetAddr>(a) == static_cast<CNetAddr>(b) &&
           a.port == b.port;
}

bool operator<(const CService &a, const CService &b) {
    return static_cast<CNetAddr>(a) < static_cast<CNetAddr>(b) ||
           (static_cast<CNetAddr>(a) == static_cast<CNetAddr>(b) &&
            a.port < b.port);
}

/**
 * Obtain the IPv4/6 socket address this represents.
 *
 * @returns An optional sockaddr / length pair when successful.
 */
std::optional<std::pair<sockaddr_storage, socklen_t>> CService::GetSockAddr() const {
    std::optional<std::pair<sockaddr_storage, socklen_t>> ret;
    if (IsIPv4()) {
        constexpr socklen_t addrlen = sizeof(sockaddr_in);
        static_assert(addrlen <= sizeof(sockaddr_storage));
        sockaddr_in addrin = {}; // 0-init
        if (!GetInAddr(&addrin.sin_addr)) {
            return ret;
        }
        addrin.sin_family = AF_INET;
        addrin.sin_port = htons(port);
        ret.emplace(sockaddr_storage{}, addrlen);
        std::memcpy(&ret->first, &addrin, addrlen);
    } else if (IsIPv6()) {
        constexpr socklen_t addrlen = sizeof(sockaddr_in6);
        static_assert(addrlen <= sizeof(sockaddr_storage));
        sockaddr_in6 addrin6 = {}; // 0-init
        if (!GetIn6Addr(&addrin6.sin6_addr)) {
            return ret;
        }
        addrin6.sin6_scope_id = scopeId;
        addrin6.sin6_family = AF_INET6;
        addrin6.sin6_port = htons(port);
        ret.emplace(sockaddr_storage{}, addrlen);
        std::memcpy(&ret->first, &addrin6, addrlen);
    }
    return ret;
}

/**
 * @returns An identifier unique to this service's address and port number.
 */
std::vector<uint8_t> CService::GetKey() const {
    auto key = GetAddrBytes();
    key.push_back(port >> 8); // most significant byte of our port
    key.push_back(port & 0x0FF); // least significant byte of our port
    return key;
}

std::string CService::ToStringPort() const {
    return strprintf("%u", port);
}

std::string CService::ToStringIPPort() const {
    if (IsIPv4() || IsTor() || IsI2P() || IsInternal()) {
        return ToStringIP() + ":" + ToStringPort();
    } else {
        return "[" + ToStringIP() + "]:" + ToStringPort();
    }
}

std::string CService::ToString() const {
    return ToStringIPPort();
}

CSubNet::CSubNet(const CNetAddr &addr, uint8_t mask) : CSubNet() {
    valid = (addr.IsIPv4() && mask <= ADDR_IPV4_SIZE * 8) || (addr.IsIPv6() && mask <= ADDR_IPV6_SIZE * 8);
    if (!valid) {
        return;
    }

    assert(mask <= sizeof(netmask) * 8);

    network = addr;

    uint8_t n = mask;
    for (size_t i = 0; i < network.m_addr.size(); ++i) {
        const uint8_t bits = n < 8 ? n : 8;
        netmask[i] = static_cast<uint8_t>(0xFFu << (8u - bits)); // Set first bits.
        network.m_addr[i] &= netmask[i]; // Normalize network according to netmask.
        n -= bits;
    }
}

/**
 * @returns The number of 1-bits in the prefix of the specified subnet mask. If
 *          the specified subnet mask is not a valid one, -1.
 */
static inline int NetmaskBits(uint8_t x) {
    switch (x) {
        case 0x00:
            return 0;
        case 0x80:
            return 1;
        case 0xc0:
            return 2;
        case 0xe0:
            return 3;
        case 0xf0:
            return 4;
        case 0xf8:
            return 5;
        case 0xfc:
            return 6;
        case 0xfe:
            return 7;
        case 0xff:
            return 8;
        default:
            return -1;
    }
}

CSubNet::CSubNet(const CNetAddr &addr, const CNetAddr &mask) : CSubNet() {
    valid = (addr.IsIPv4() || addr.IsIPv6()) && addr.m_net == mask.m_net;
    if (!valid) {
        return;
    }
    // Check if `mask` contains 1-bits after 0-bits (which is an invalid netmask).
    bool zeros_found = false;
    for (auto b : mask.m_addr) {
        const int num_bits = NetmaskBits(b);
        if (num_bits == -1 || (zeros_found && num_bits != 0)) {
            valid = false;
            return;
        }
        if (num_bits < 8) {
            zeros_found = true;
        }
    }

    assert(mask.m_addr.size() <= sizeof(netmask));

    std::memcpy(netmask, mask.m_addr.data(), mask.m_addr.size());

    network = addr;

    // Normalize network according to netmask
    for (size_t x = 0; x < network.m_addr.size(); ++x) {
        network.m_addr[x] &= netmask[x];
    }
}

CSubNet::CSubNet(const CNetAddr &addr) : CSubNet() {
    static_assert(sizeof(netmask) == sizeof(pchSingleAddressNetmask),
                  "netmask and pchSingleAddressNetmask must be the same size");

    valid = addr.IsIPv4() || addr.IsIPv6();
    if (!valid) {
        return;
    }

    assert(addr.m_addr.size() <= sizeof(netmask));

    std::memcpy(netmask, pchSingleAddressNetmask, addr.m_addr.size());

    network = addr;
}

/**
 * @returns True if this subnet is valid, the specified address is valid, and
 *          the specified address belongs in this subnet.
 */
bool CSubNet::Match(const CNetAddr &addr) const {
    if (!valid || !addr.IsValid() || network.m_net != addr.m_net) {
        return false;
    }
    assert(network.m_addr.size() == addr.m_addr.size());
    for (size_t x = 0; x < addr.m_addr.size(); ++x) {
        if ((addr.m_addr[x] & netmask[x]) != network.m_addr[x]) {
            return false;
        }
    }
    return true;
}

uint8_t CSubNet::GetCIDRLength() const {
    assert(network.m_addr.size() <= std::size(netmask));
    uint8_t cidr = 0;
    for (size_t i = 0; i < network.m_addr.size(); ++i) {
        const int bits = NetmaskBits(netmask[i]);
        if (bits <= 0) break; // end of mask
        cidr += bits;
    }
    return cidr;
}

std::pair<CNetAddr, uint8_t> CSubNet::GetCIDR() const {
    return {network, GetCIDRLength()};
}

std::string CSubNet::ToString() const {
    return network.ToString() + strprintf("/%u", GetCIDRLength());
}

bool CSubNet::IsSingleIP() const {
    assert(network.m_addr.size() <= sizeof(netmask));
    return 0 == std::memcmp(netmask, pchSingleAddressNetmask, network.m_addr.size());
}

bool CSubNet::SanityCheck() const {
    if (!(network.IsIPv4() || network.IsIPv6())) return false;

    for (size_t x = 0; x < network.m_addr.size(); ++x) {
        if (network.m_addr[x] & ~netmask[x]) return false;
    }

    return true;
}

bool operator==(const CSubNet &a, const CSubNet &b) {
    return a.valid == b.valid && a.network == b.network &&
           !std::memcmp(a.netmask, b.netmask, 16);
}

bool operator<(const CSubNet &a, const CSubNet &b) {
    return a.network < b.network ||
           (a.network == b.network && std::memcmp(a.netmask, b.netmask, 16) < 0);
}


// std::unordered_map support --

size_t SaltedNetAddrHasher::operator()(const CNetAddr &addr) const
{
    return static_cast<size_t>(SerializeSipHash(addr, k0(), k1()));
}

size_t SaltedSubNetHasher::operator()(const CSubNet &subnet) const
{
    return static_cast<size_t>(SerializeSipHash(subnet, k0(), k1()));
}

bool SanityCheckASMap(const std::vector<bool> &asmap) {
    return SanityCheckASMap(asmap, 128); // For IP address lookups, the input is 128 bits
}
