// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017-present The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <net.h>
#include <serialize.h>

class CNetMsgMaker {
public:
    explicit CNetMsgMaker(int nVersionIn) : nVersion(nVersionIn) {}

    template <typename... Args>
    CSerializedNetMsg Make(int nFlags, std::string msg_type, Args &&... args) const {
        CSerializedNetMsg msg;
        msg.m_type = std::move(msg_type);
        CVectorWriter{SER_NETWORK, nFlags | nVersion, msg.data_source.GetVec(), 0, std::forward<Args>(args)...};
        return msg;
    }

    template <typename... Args>
    CSerializedNetMsg Make(std::string msg_type, Args &&... args) const {
        return Make(0, std::move(msg_type), std::forward<Args>(args)...);
    }

    const int nVersion;
};
