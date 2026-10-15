#include <node/peerman_args.h>

#include <net_processing.h>
#include <util/system.h>

#include <algorithm>
#include <limits>

namespace node {

void ApplyArgsManOptions(const ArgsManager& argsman, PeerManager::Options& options)
{
    if (auto value{argsman.GetBoolArg("-txreconciliation")}) options.reconcile_txs = *value;

    if (auto value{argsman.GetIntArg("-maxorphantxsize")}) {
        options.max_orphan_txs_size = uint32_t(std::clamp<int64_t>(*value, 0, std::numeric_limits<uint32_t>::max() / 1000000) * 1000000);
    }

    if (auto value{argsman.GetIntArg("-blockreconstructionextratxn")}) {
        options.max_extra_txs = size_t(std::max(int64_t{0}, *value));
    }

    if (auto value{argsman.GetBoolArg("-capturemessages")}) options.capture_messages = *value;
}

} // namespace node

