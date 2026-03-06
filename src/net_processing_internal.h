// Copyright (c) 2021-2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <net_nodeid.h>

#include <cstdint>

// `internal` namespace exposed *FOR TESTS ONLY*
// This namespace is for exposed internals not intended for public usage.
// We would ideally have made these private to the net_processing.cpp
// translation unit only, but since some tests need to see these functions
// (see denialofservice_tests.cpp), we do this instead.
namespace internal {
// This function is used for testing the stale tip eviction logic, see
// denialofservice_tests.cpp.
void UpdateLastBlockAnnounceTime(NodeId node, int64_t time_in_seconds);
} // namespace internal
