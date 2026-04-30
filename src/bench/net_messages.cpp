// Copyright (c) 2023-2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>

#include <bench/data.h>
#include <config.h>
#include <net.h>

#include <algorithm>

// Test the speed of calling CNode::ReceiveMsgBytes on real network data containing a mix of messages:
// {
//     "recv_bytes_per_msg_type": {
//         "addr": 30027,
//         "block": 1961326,
//         "extversion": 140,
//         "getdata": 61,
//         "headers": 829,
//         "inv": 45145,
//         "ping": 1472,
//         "pong": 1472,
//         "sendcmpct": 33,
//         "sendheaders": 24,
//         "tx": 32776,
//         "verack": 24,
//         "version": 151
//     },
//     "recv_counts_per_msg_type": {
//         "addr": 1,
//         "block": 27,
//         "extversion": 1,
//         "getdata": 1,
//         "headers": 4,
//         "inv": 733,
//         "ping": 46,
//         "pong": 46,
//         "sendcmpct": 1,
//         "sendheaders": 1,
//         "tx": 103,
//         "verack": 1,
//         "version": 1
//     }
// }
static void CNodeReceiveMsgBytes(benchmark::State &state) {
    const Config &config = ::GetConfig();
    const auto &rawMsgData = benchmark::data::Get_recv_messages();
    assert(!rawMsgData.empty());
    constexpr size_t chunkSize = 0x4000; // read 16KiB at a time
    std::vector<NodeRef> precreatedNodes(state.m_num_iters);
    for (auto & pnode : precreatedNodes) {
        pnode = CNode::Make({}, {}, {}, {}, {}, {}, {}, {}, {}, "", ConnectionType::OUTBOUND_FULL_RELAY);
    }
    assert(!precreatedNodes.empty());

    size_t idx{};
    BENCHMARK_LOOP {
        const auto &pnode = precreatedNodes[idx++ % precreatedNodes.size()];
        auto *cur = reinterpret_cast<const char *>(rawMsgData.data());
        auto *end = reinterpret_cast<const char *>(rawMsgData.data() + rawMsgData.size());
        while (cur < end) {
            const size_t bytesLeft = end - cur;
            const size_t nBytes = std::min(chunkSize, bytesLeft);
            bool completed;
            const bool handled = pnode->ReceiveMsgBytes(config, cur, nBytes, completed);
            assert(handled);
            cur += nBytes;
        }
    }
}

BENCHMARK(CNodeReceiveMsgBytes, 180);
