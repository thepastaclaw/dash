// Copyright (c) 2026 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bls/bls.h>
#include <evo/deterministicmns.h>
#include <evo/netinfo.h>
#include <evo/simplifiedmns.h>
#include <evo/smldiff.h>
#include <llmq/commitment.h>
#include <script/script.h>
#include <script/standard.h>
#include <streams.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/util/setup_common.h>
#include <tinyformat.h>
#include <version.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

const TestingSetup* g_setup;

uint256 HashFromTag(uint64_t tag)
{
    uint256 hash;
    std::array<uint8_t, 8> seed{};
    WriteLE64(seed.data(), tag);
    for (size_t i = 0; i < hash.size(); ++i) {
        hash.begin()[i] = static_cast<uint8_t>(seed[i % seed.size()] + static_cast<uint8_t>(i * 13));
    }
    if (hash.IsNull()) {
        hash.begin()[0] = 1;
    }
    return hash;
}

uint160 Uint160FromTag(uint64_t tag)
{
    uint160 value;
    std::array<uint8_t, 8> seed{};
    WriteLE64(seed.data(), tag);
    for (size_t i = 0; i < value.size(); ++i) {
        value.begin()[i] = static_cast<uint8_t>(seed[i % seed.size()] + static_cast<uint8_t>(i * 7 + 1));
    }
    if (value.IsNull()) {
        value.begin()[0] = 1;
    }
    return value;
}

uint256 ConsumeUInt256(FuzzedDataProvider& fuzzed_data_provider)
{
    const std::vector<uint8_t> bytes = fuzzed_data_provider.ConsumeBytes<uint8_t>(uint256::size());
    if (bytes.size() != uint256::size()) return HashFromTag(0xC3C3C3C3ULL);

    uint256 value;
    std::copy(bytes.begin(), bytes.end(), value.begin());
    return value;
}

std::string AddressFromTag(uint64_t tag)
{
    const uint32_t a = 1 + (tag % 223);
    const uint32_t b = 1 + ((tag / 223) % 254);
    const uint32_t c = 1 + ((tag / (223 * 254)) % 254);
    const uint32_t d = 1 + ((tag / (223 * 254 * 254)) % 254);
    const uint32_t port = 1000 + (tag % 50000);
    return strprintf("%u.%u.%u.%u:%u", a, b, c, d, port);
}

CDeterministicMNCPtr MakeMasternode(const uint64_t internal_id, const uint64_t unique_tag, const int height, const MnType mn_type = MnType::Regular)
{
    auto state = std::make_shared<CDeterministicMNState>();
    state->nVersion = mn_type == MnType::Evo ? ProTxVersion::BasicBLS : ProTxVersion::LegacyBLS;
    state->nRegisteredHeight = height;
    state->nLastPaidHeight = height > 0 ? height - 1 : 0;
    state->nConsecutivePayments = static_cast<int>(unique_tag % 4);
    state->nPoSePenalty = static_cast<int>(unique_tag % 8);
    state->nPoSeRevivedHeight = -1;
    state->nRevocationReason = CProUpRevTx::REASON_NOT_SPECIFIED;
    state->confirmedHash = HashFromTag(unique_tag ^ 0x01010101ULL);
    state->confirmedHashWithProRegTxHash = HashFromTag(unique_tag ^ 0x02020202ULL);
    state->keyIDOwner = CKeyID(Uint160FromTag(unique_tag ^ 0x03030303ULL));
    state->keyIDVoting = CKeyID(Uint160FromTag(unique_tag ^ 0x04040404ULL));
    state->netInfo = NetInfoInterface::MakeNetInfo(state->nVersion);
    if (!state->netInfo ||
        state->netInfo->AddEntry(NetInfoPurpose::CORE_P2P, AddressFromTag(unique_tag)) != NetInfoStatus::Success) {
        throw std::runtime_error("failed to create deterministic masternode netInfo");
    }

    if (mn_type == MnType::Evo) {
        state->platformNodeID = Uint160FromTag(unique_tag ^ 0xABABABABULL);
        state->platformP2PPort = static_cast<uint16_t>(10000 + (unique_tag % 50000));
        state->platformHTTPPort = static_cast<uint16_t>(11000 + (unique_tag % 50000));
    }

    auto dmn = std::make_shared<CDeterministicMN>(internal_id, mn_type);
    dmn->proTxHash = HashFromTag(unique_tag ^ 0x11111111ULL);
    dmn->collateralOutpoint = COutPoint(HashFromTag(unique_tag ^ 0x22222222ULL), static_cast<uint32_t>(unique_tag % 8));
    dmn->nOperatorReward = static_cast<uint16_t>(unique_tag % 10000);
    dmn->pdmnState = state;
    return dmn;
}

std::vector<uint256> GetProTxHashes(const CDeterministicMNList& mn_list)
{
    std::vector<uint256> hashes;
    mn_list.ForEachMN(/*onlyValid=*/false, [&](const CDeterministicMN& dmn) { hashes.push_back(dmn.proTxHash); });
    return hashes;
}

std::vector<std::byte> SerializeMerkleTree(const CPartialMerkleTree& tree)
{
    CDataStream ds(SER_NETWORK, PROTOCOL_VERSION);
    ds << tree;
    return {ds.begin(), ds.end()};
}

bool MutableTxEqual(const CMutableTransaction& lhs, const CMutableTransaction& rhs)
{
    return lhs.vin == rhs.vin &&
           lhs.vout == rhs.vout &&
           lhs.nVersion == rhs.nVersion &&
           lhs.nType == rhs.nType &&
           lhs.nLockTime == rhs.nLockTime &&
           lhs.vExtraPayload == rhs.vExtraPayload;
}

} // namespace

void initialize_simplified_mn_list_diff()
{
    static const auto testing_setup = MakeNoLogFileContext<const TestingSetup>(CBaseChainParams::REGTEST);
    g_setup = testing_setup.get();
}

FUZZ_TARGET(simplified_mn_list_diff, .init = initialize_simplified_mn_list_diff)
{
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());

    const int source_height = fuzzed_data_provider.ConsumeIntegralInRange<int>(0, 10000);
    const uint256 source_hash = ConsumeUInt256(fuzzed_data_provider);
    CDeterministicMNList list_from(source_hash, source_height, 0);

    uint64_t next_internal_id = 1;
    uint64_t next_unique_tag = 1;
    const size_t initial_mn_count = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, 8);
    for (size_t i = 0; i < initial_mn_count; ++i) {
        const MnType mn_type = fuzzed_data_provider.ConsumeBool() ? MnType::Evo : MnType::Regular;
        list_from.AddMN(MakeMasternode(next_internal_id++, next_unique_tag++, source_height, mn_type), /*fBumpTotalCount=*/true);
    }

    CDeterministicMNList list_to(list_from);
    const size_t operation_count = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, 24);
    for (size_t i = 0; i < operation_count; ++i) {
        const uint8_t op = fuzzed_data_provider.ConsumeIntegralInRange<uint8_t>(0, 2);
        if (op == 0) {
            const MnType mn_type = fuzzed_data_provider.ConsumeBool() ? MnType::Evo : MnType::Regular;
            list_to.AddMN(MakeMasternode(next_internal_id++, next_unique_tag++, source_height, mn_type), /*fBumpTotalCount=*/true);
            continue;
        }

        const auto hashes = GetProTxHashes(list_to);
        if (hashes.empty()) continue;
        const size_t index = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, hashes.size() - 1);

        if (op == 1) {
            list_to.RemoveMN(hashes[index]);
            continue;
        }

        const auto old_mn = list_to.GetMN(hashes[index]);
        if (!old_mn) continue;
        auto new_state = std::make_shared<CDeterministicMNState>(*old_mn->pdmnState);
        switch (fuzzed_data_provider.ConsumeIntegralInRange<uint8_t>(0, 9)) {
        case 0:
            new_state->confirmedHash = HashFromTag(next_unique_tag++ ^ 0x33333333ULL);
            break;
        case 1: {
            CBLSSecretKey sk;
            sk.MakeNewKey();
            new_state->nVersion = ProTxVersion::BasicBLS;
            new_state->pubKeyOperator.Set(sk.GetPublicKey(), /*specificLegacyScheme=*/false);
            break;
        }
        case 2:
            new_state->keyIDVoting = CKeyID(Uint160FromTag(next_unique_tag++ ^ 0x06060606ULL));
            break;
        case 3: {
            auto net_info = NetInfoInterface::MakeNetInfo(new_state->nVersion);
            if (net_info && net_info->AddEntry(NetInfoPurpose::CORE_P2P, AddressFromTag(next_unique_tag++)) == NetInfoStatus::Success) {
                new_state->netInfo = std::move(net_info);
            }
            break;
        }
        case 4:
            new_state->scriptPayout = CScript() << OP_DUP << OP_HASH160 << ToByteVector(Uint160FromTag(next_unique_tag++)) << OP_EQUALVERIFY << OP_CHECKSIG;
            break;
        case 5:
            new_state->scriptOperatorPayout = CScript() << OP_DUP << OP_HASH160 << ToByteVector(Uint160FromTag(next_unique_tag++ ^ 0x08080808ULL)) << OP_EQUALVERIFY << OP_CHECKSIG;
            break;
        case 6:
            new_state->BanIfNotBanned(fuzzed_data_provider.ConsumeIntegralInRange<int>(0, 100000));
            break;
        case 7:
            new_state->platformNodeID = Uint160FromTag(next_unique_tag++ ^ 0x12121212ULL);
            break;
        case 8:
            new_state->platformHTTPPort = fuzzed_data_provider.ConsumeIntegral<uint16_t>();
            break;
        case 9:
            new_state->nRegisteredHeight = fuzzed_data_provider.ConsumeIntegralInRange<int>(0, 10000);
            break;
        }
        list_to.UpdateMN(*old_mn, new_state);
    }

    list_to.SetBlockHash(ConsumeUInt256(fuzzed_data_provider));
    list_to.SetHeight(fuzzed_data_provider.ConsumeIntegralInRange<int>(0, 100000));

    CSimplifiedMNListDiff diff;
    diff.baseBlockHash = list_from.GetBlockHash();
    diff.blockHash = list_to.GetBlockHash();
    diff.cbTx = CMutableTransaction{};
    diff.cbTxMerkleTree = CPartialMerkleTree{};

    list_to.ForEachMN(/*onlyValid=*/false, [&](const auto& to_mn) {
        const auto from_mn = list_from.GetMN(to_mn.proTxHash);
        if (!from_mn || to_mn.to_sml_entry() != from_mn->to_sml_entry()) {
            diff.mnList.emplace_back(to_mn.to_sml_entry());
        }
    });
    list_from.ForEachMN(/*onlyValid=*/false, [&](const auto& from_mn) {
        if (!list_to.GetMN(from_mn.proTxHash)) {
            diff.deletedMNs.emplace_back(from_mn.proTxHash);
        }
    });

    CDataStream ds(SER_NETWORK, PROTOCOL_VERSION);
    ds << diff;
    CSimplifiedMNListDiff roundtrip;
    ds >> roundtrip;

    if (roundtrip.baseBlockHash != diff.baseBlockHash || roundtrip.blockHash != diff.blockHash ||
        !MutableTxEqual(roundtrip.cbTx, diff.cbTx) ||
        SerializeMerkleTree(roundtrip.cbTxMerkleTree) != SerializeMerkleTree(diff.cbTxMerkleTree) ||
        roundtrip.deletedMNs != diff.deletedMNs || roundtrip.mnList.size() != diff.mnList.size() ||
        roundtrip.nVersion != diff.nVersion || roundtrip.deletedQuorums != diff.deletedQuorums ||
        roundtrip.newQuorums.size() != diff.newQuorums.size() || roundtrip.quorumsCLSigs != diff.quorumsCLSigs) {
        throw std::runtime_error("simplified_mn_list_diff: serialized fields mismatch");
    }
    for (size_t i = 0; i < diff.mnList.size(); ++i) {
        if (roundtrip.mnList[i] != diff.mnList[i]) {
            throw std::runtime_error("simplified_mn_list_diff: mnList mismatch");
        }
    }

    CDataStream ds_random(fuzzed_data_provider.ConsumeRemainingBytes<uint8_t>(), SER_NETWORK, PROTOCOL_VERSION);
    try {
        CSimplifiedMNListDiff random_diff;
        ds_random >> random_diff;
    } catch (const std::exception&) {
    }
}
