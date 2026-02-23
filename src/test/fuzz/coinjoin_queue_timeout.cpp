// Copyright (c) 2026 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <coinjoin/coinjoin.h>

#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>

#include <array>
#include <cassert>
#include <cstdint>
#include <limits>

namespace {
bool IsTimeOutOfBoundsOracle(int64_t queue_time, int64_t current_time, int64_t timeout_window)
{
    __int128 diff = static_cast<__int128>(queue_time) - static_cast<__int128>(current_time);
    if (diff < 0) {
        diff = -diff;
    }
    return diff > static_cast<__int128>(timeout_window);
}
} // namespace

FUZZ_TARGET(coinjoin_queue_timeout)
{
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());

    const int64_t queue_time = fuzzed_data_provider.ConsumeIntegral<int64_t>();
    const int64_t current_time = fuzzed_data_provider.ConsumeIntegral<int64_t>();
    const int64_t timeout_window = fuzzed_data_provider.ConsumeIntegral<int64_t>();

    assert(CCoinJoinQueue::IsTimeOutOfBounds(queue_time, current_time, timeout_window) ==
           IsTimeOutOfBoundsOracle(queue_time, current_time, timeout_window));

    const std::array<int64_t, 12> kEdges{
        std::numeric_limits<int64_t>::min(),
        std::numeric_limits<int64_t>::min() + 1,
        -COINJOIN_QUEUE_TIMEOUT - 1,
        -COINJOIN_QUEUE_TIMEOUT,
        -1,
        0,
        1,
        COINJOIN_QUEUE_TIMEOUT,
        COINJOIN_QUEUE_TIMEOUT + 1,
        std::numeric_limits<int64_t>::max() - 1,
        std::numeric_limits<int64_t>::max(),
        timeout_window,
    };
    for (const int64_t edge_queue : kEdges) {
        for (const int64_t edge_current : kEdges) {
            for (const int64_t edge_timeout : kEdges) {
                assert(CCoinJoinQueue::IsTimeOutOfBounds(edge_queue, edge_current, edge_timeout) ==
                       IsTimeOutOfBoundsOracle(edge_queue, edge_current, edge_timeout));
            }
        }
    }
}
