// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (C) 2020 Tom Zander <tomz@freedommail.ch>
// Copyright (c) 2017-present The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <protocol.h>

#include <chainparams.h>
#include <config.h>
#include <util/strencodings.h>
#include <util/system.h>

#ifndef WIN32
#include <arpa/inet.h>
#endif
#include <atomic>

static std::atomic<bool> g_initial_block_download_completed(false);

namespace NetMsgType {
const char *const VERSION = "version";
const char *const VERACK = "verack";
const char *const ADDR = "addr";
const char *const ADDRV2 = "addrv2";
const char *const SENDADDRV2 = "sendaddrv2";
const char *const INV = "inv";
const char *const GETDATA = "getdata";
const char *const MERKLEBLOCK = "merkleblock";
const char *const GETBLOCKS = "getblocks";
const char *const GETHEADERS = "getheaders";
const char *const TX = "tx";
const char *const HEADERS = "headers";
const char *const BLOCK = "block";
const char *const GETADDR = "getaddr";
const char *const MEMPOOL = "mempool";
const char *const PING = "ping";
const char *const PONG = "pong";
const char *const NOTFOUND = "notfound";
const char *const FILTERLOAD = "filterload";
const char *const FILTERADD = "filteradd";
const char *const FILTERCLEAR = "filterclear";
const char *const REJECT = "reject";
const char *const SENDHEADERS = "sendheaders";
const char *const FEEFILTER = "feefilter";
const char *const SENDCMPCT = "sendcmpct";
const char *const CMPCTBLOCK = "cmpctblock";
const char *const GETBLOCKTXN = "getblocktxn";
const char *const BLOCKTXN = "blocktxn";
const char *const EXTVERSION = "extversion";
const char *const DSPROOF = "dsproof-beta";

bool IsBlockLike(const std::string &msg_type) {
    return msg_type == NetMsgType::BLOCK ||
           msg_type == NetMsgType::CMPCTBLOCK ||
           msg_type == NetMsgType::BLOCKTXN;
}
}; // namespace NetMsgType

/**
 * All known message types. Keep this in the same order as the list of messages
 * above and in protocol.h.
 */
static const std::vector<std::string> allNetMessageTypesVec{{
    NetMsgType::VERSION,     NetMsgType::VERACK,     NetMsgType::ADDR,        NetMsgType::ADDRV2,
    NetMsgType::SENDADDRV2,  NetMsgType::INV,        NetMsgType::GETDATA,     NetMsgType::MERKLEBLOCK,
    NetMsgType::GETBLOCKS,   NetMsgType::GETHEADERS, NetMsgType::TX,          NetMsgType::HEADERS,
    NetMsgType::BLOCK,       NetMsgType::GETADDR,    NetMsgType::MEMPOOL,     NetMsgType::PING,
    NetMsgType::PONG,        NetMsgType::NOTFOUND,   NetMsgType::FILTERLOAD,  NetMsgType::FILTERADD,
    NetMsgType::FILTERCLEAR, NetMsgType::REJECT,     NetMsgType::SENDHEADERS, NetMsgType::FEEFILTER,
    NetMsgType::SENDCMPCT,   NetMsgType::CMPCTBLOCK, NetMsgType::GETBLOCKTXN, NetMsgType::BLOCKTXN,
    NetMsgType::EXTVERSION,  NetMsgType::DSPROOF,
}};

CMessageHeader::CMessageHeader(const MessageMagic &pchMessageStartIn) : pchMessageStart(pchMessageStartIn) {}

CMessageHeader::CMessageHeader(const MessageMagic &pchMessageStartIn,
                               const char *pszCommand,
                               unsigned int nMessageSizeIn,
                               const CheckSum &pchCheckSumIn)
    : pchMessageStart(pchMessageStartIn), nMessageSize{nMessageSizeIn}, pchCheckSum(pchCheckSumIn) {
    // Copy the command name
    size_t i = 0;
    for (; i < pchCommand.size() && pszCommand[i] != 0; ++i) {
        pchCommand[i] = pszCommand[i];
    }
    // Assert that the command name passed in is not longer than COMMAND_SIZE
    assert(pszCommand[i] == 0);
}

std::string CMessageHeader::GetCommand() const {
    // return std::string(pchCommand.begin(), pchCommand.end());
    return std::string(pchCommand.data(),
                       pchCommand.data() +
                           strnlen(pchCommand.data(), COMMAND_SIZE));
}

static bool
CheckHeaderMagicAndCommand(const CMessageHeader &header,
                           const CMessageHeader::MessageMagic &magic) {
    // Check start string
    if (std::memcmp(header.pchMessageStart.data(), magic.data(), magic.size()) != 0) {
        return false;
    }

    // Check the command string for errors
    for (const char *p1 = header.pchCommand.data(), *end = header.pchCommand.data() + header.pchCommand.size();
         p1 < end; ++p1) {
        if (*p1 == 0) {
            // Must be all zeros after the first zero
            for (; p1 < end; ++p1) {
                if (*p1 != 0) {
                    return false;
                }
            }
        } else if (*p1 < ' ' || *p1 > 0x7E) {
            return false;
        }
    }

    return true;
}

bool CMessageHeader::IsValid(const Config &config) const {
    // Check start string
    if (!CheckHeaderMagicAndCommand(*this,
                                    config.GetChainParams().NetMagic())) {
        return false;
    }

    // Message size
    if (IsOversized(config)) {
        LogPrintf("CMessageHeader::IsValid(): (%s, %u bytes) is oversized\n",
                  GetCommand(), nMessageSize);
        return false;
    }

    return true;
}

/**
 * This is a transition method in order to stay compatible with older code that
 * do not use the config. It assumes message will not get too large. This cannot
 * be used for any piece of code that will download blocks as blocks may be
 * bigger than the permitted size. Idealy, code that uses this function should
 * be migrated toward using the config.
 */
bool CMessageHeader::IsValidWithoutConfig(const MessageMagic &magic) const {
    // Check start string
    if (!CheckHeaderMagicAndCommand(*this, magic)) {
        return false;
    }

    // Message size
    if (nMessageSize > MAX_PROTOCOL_MESSAGE_LENGTH) {
        LogPrintf(
            "CMessageHeader::IsValidForSeeder(): (%s, %u bytes) is oversized\n",
            GetCommand(), nMessageSize);
        return false;
    }

    return true;
}

bool CMessageHeader::IsOversized(const Config &config) const {
    // If the message doesn't not contain a block content, check against
    // MAX_PROTOCOL_MESSAGE_LENGTH.
    if (nMessageSize > MAX_PROTOCOL_MESSAGE_LENGTH &&
        !NetMsgType::IsBlockLike(GetCommand())) {
        return true;
    }

    // Scale the maximum accepted size with the expected maximum block size (ABLA's 2 * BLOCK_DOWNLOAD_WINDOW lookahead
    // guess). Note that the correctness of this size check relies on downloads of blocks never being beyond the active
    // chain tip + BLOCK_DOWNLOAD_WINDOW (enforced elsewhere in the network code).
    if (nMessageSize > 2u * config.GetMaxBlockSizeLookAheadGuess()) {
        return true;
    }

    return false;
}

ServiceFlags GetDesirableServiceFlags(ServiceFlags services) {
    if ((services & NODE_NETWORK_LIMITED) &&
        g_initial_block_download_completed) {
        return ServiceFlags(NODE_NETWORK_LIMITED);
    }
    return ServiceFlags(NODE_NETWORK);
}

void SetServiceFlagsIBDCache(bool state) {
    g_initial_block_download_completed = state;
}

std::string CInv::GetCommand() const {
    std::string cmd;
    switch (GetKind()) {
        case MSG_TX:
            return cmd.append(NetMsgType::TX);
        case MSG_BLOCK:
            return cmd.append(NetMsgType::BLOCK);
        case MSG_FILTERED_BLOCK:
            return cmd.append(NetMsgType::MERKLEBLOCK);
        case MSG_CMPCT_BLOCK:
            return cmd.append(NetMsgType::CMPCTBLOCK);
        case MSG_DOUBLESPENDPROOF:
             return cmd.append(NetMsgType::DSPROOF);
        default:
            throw std::out_of_range(
                strprintf("CInv::GetCommand(): type=%d unknown type", type));
    }
}

std::string CInv::ToString() const {
    try {
        return strprintf("%s %s", GetCommand(), hash.ToString());
    } catch (const std::out_of_range &) {
        return strprintf("0x%08x %s", type, hash.ToString());
    }
}

const std::vector<std::string> &getAllNetMessageTypes() {
    return allNetMessageTypesVec;
}
