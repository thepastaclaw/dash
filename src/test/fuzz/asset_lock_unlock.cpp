// Copyright (c) 2026 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <consensus/validation.h>
#include <evo/assetlocktx.h>
#include <evo/creditpool.h>
#include <evo/specialtx.h>
#include <llmq/context.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <streams.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/util/mining.h>
#include <test/util/setup_common.h>
#include <validation.h>
#include <validationinterface.h>
#include <version.h>

#include <cassert>
#include <cstdint>
#include <exception>
#include <limits>
#include <set>
#include <vector>

namespace {
const TestingSetup* g_credit_pool_setup;

CScript ConsumeScript(FuzzedDataProvider& fuzzed_data_provider, size_t max_size = 64)
{
    const std::vector<uint8_t> raw_script = fuzzed_data_provider.ConsumeBytes<uint8_t>(
        fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, max_size));
    return CScript(raw_script.begin(), raw_script.end());
}

CScript ConsumeP2PKHScript(FuzzedDataProvider& fuzzed_data_provider)
{
    const std::vector<uint8_t> key_hash = fuzzed_data_provider.ConsumeBytes<uint8_t>(20);
    return CScript() << OP_DUP << OP_HASH160 << key_hash << OP_EQUALVERIFY << OP_CHECKSIG;
}

CAmount ConsumeAmount(FuzzedDataProvider& fuzzed_data_provider)
{
    return fuzzed_data_provider.ConsumeIntegralInRange<CAmount>(-1, static_cast<CAmount>(MAX_MONEY) + 1);
}

std::vector<uint8_t> BuildAssetLockPayload(const uint8_t version, const std::vector<CTxOut>& credit_outputs)
{
    CDataStream ds(SER_NETWORK, PROTOCOL_VERSION);
    ds << version;
    ds << credit_outputs;
    return {UCharCast(ds.data()), UCharCast(ds.data() + ds.size())};
}

CBLSSignature ConsumeBLSSignature(FuzzedDataProvider& fuzzed_data_provider)
{
    CBLSSignature sig;
    auto bytes = fuzzed_data_provider.ConsumeBytes<uint8_t>(CBLSSignature::SerSize);
    bytes.resize(CBLSSignature::SerSize);
    sig.SetBytes(bytes, fuzzed_data_provider.ConsumeBool());
    return sig;
}

uint256 ConsumeUInt256(FuzzedDataProvider& fuzzed_data_provider)
{
    uint256 value;
    auto it = value.begin();
    const std::vector<uint8_t> bytes = fuzzed_data_provider.ConsumeBytes<uint8_t>(32);
    for (uint8_t b : bytes) {
        *it = b;
        ++it;
    }
    return value;
}

void initialize_asset_lock_unlock() { SelectParams(CBaseChainParams::REGTEST); }

void initialize_credit_pool()
{
    static const auto testing_setup = MakeNoLogFileContext<const TestingSetup>(
        CBaseChainParams::REGTEST, {"-dip3params=2:2", "-testactivationheight=v20@2", "-testactivationheight=mn_rr@2"});
    g_credit_pool_setup = testing_setup.get();
    for (int i = 0; i < 3; ++i) {
        MineBlock(g_credit_pool_setup->m_node, CScript() << OP_TRUE);
    }
    SyncWithValidationInterfaceQueue();
}
} // namespace

FUZZ_TARGET(asset_lock_tx, .init = initialize_asset_lock_unlock)
{
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());

    CMutableTransaction tx;
    tx.nVersion = CTransaction::SPECIAL_VERSION;
    tx.nType = TRANSACTION_ASSET_LOCK;

    std::vector<CTxOut> credit_outputs;
    const size_t num_credit_outputs = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(1, 4);
    CAmount credit_outputs_total{0};
    for (size_t i = 0; i < num_credit_outputs; ++i) {
        const CAmount amount = fuzzed_data_provider.ConsumeIntegralInRange<CAmount>(1, 10 * COIN);
        assert(MoneyRange(amount));
        assert(MoneyRange(credit_outputs_total + amount));
        credit_outputs_total += amount;
        credit_outputs.emplace_back(amount, ConsumeP2PKHScript(fuzzed_data_provider));
    }

    SetTxPayload(tx, CAssetLockPayload(credit_outputs));

    tx.vout.emplace_back(credit_outputs_total, CScript() << OP_RETURN << std::vector<uint8_t>{});

    const size_t num_regular_outputs = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, 4);
    for (size_t i = 0; i < num_regular_outputs; ++i) {
        tx.vout.emplace_back(ConsumeAmount(fuzzed_data_provider), ConsumeScript(fuzzed_data_provider));
    }

    const uint8_t scenario = fuzzed_data_provider.ConsumeIntegralInRange<uint8_t>(0, 11);
    switch (scenario) {
    case 0: // bad-assetlocktx-type
        tx.nType = fuzzed_data_provider.ConsumeBool() ? TRANSACTION_ASSET_UNLOCK : TRANSACTION_NORMAL;
        break;
    case 1: // bad-assetlocktx-non-empty-return
        tx.vout[0].scriptPubKey = CScript() << OP_RETURN
                                            << fuzzed_data_provider.ConsumeBytes<uint8_t>(
                                                   fuzzed_data_provider.ConsumeIntegralInRange<size_t>(1, 16));
        break;
    case 2: // bad-assetlocktx-opreturn-outofrange
        tx.vout[0].nValue = fuzzed_data_provider.ConsumeBool() ? 0 : static_cast<CAmount>(MAX_MONEY) + 1;
        break;
    case 3: // bad-assetlocktx-multiple-return
        tx.vout.emplace_back(1, CScript() << OP_RETURN << std::vector<uint8_t>{});
        break;
    case 4: // bad-assetlocktx-no-return
        tx.vout[0].scriptPubKey = ConsumeScript(fuzzed_data_provider);
        if (!tx.vout[0].scriptPubKey.empty() && tx.vout[0].scriptPubKey[0] == OP_RETURN) {
            tx.vout[0].scriptPubKey = CScript() << OP_1;
        }
        break;
    case 5: // bad-assetlocktx-payload
        tx.vExtraPayload = fuzzed_data_provider.ConsumeBytes<uint8_t>(
            fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, 8));
        break;
    case 6: // bad-assetlocktx-version
        tx.vExtraPayload = BuildAssetLockPayload(fuzzed_data_provider.ConsumeBool() ? uint8_t{0}
                                                                                    : std::numeric_limits<uint8_t>::max(),
                                                 credit_outputs);
        break;
    case 7: // bad-assetlocktx-emptycreditoutputs
        tx.vExtraPayload = BuildAssetLockPayload(CAssetLockPayload::CURRENT_VERSION, {});
        break;
    case 8: { // bad-assetlocktx-credit-outofrange
        auto bad_credit_outputs = credit_outputs;
        bad_credit_outputs[0].nValue = fuzzed_data_provider.ConsumeBool() ? 0 : static_cast<CAmount>(MAX_MONEY) + 1;
        tx.vExtraPayload = BuildAssetLockPayload(CAssetLockPayload::CURRENT_VERSION, bad_credit_outputs);
        break;
    }
    case 9: { // bad-assetlocktx-pubKeyHash
        auto bad_credit_outputs = credit_outputs;
        bad_credit_outputs[0].scriptPubKey = ConsumeScript(fuzzed_data_provider);
        if (bad_credit_outputs[0].scriptPubKey.IsPayToPublicKeyHash()) {
            bad_credit_outputs[0].scriptPubKey = CScript() << OP_1;
        }
        tx.vExtraPayload = BuildAssetLockPayload(CAssetLockPayload::CURRENT_VERSION, bad_credit_outputs);
        break;
    }
    case 10: { // bad-assetlocktx-creditamount
        auto bad_credit_outputs = credit_outputs;
        bad_credit_outputs[0].nValue += fuzzed_data_provider.ConsumeBool() ? 1 : -1;
        tx.vExtraPayload = BuildAssetLockPayload(CAssetLockPayload::CURRENT_VERSION, bad_credit_outputs);
        break;
    }
    case 11: // Valid path
        break;
    }

    TxValidationState state;
    const bool result = CheckAssetLockTx(CTransaction(tx), state);
    assert(result == state.IsValid());
}

FUZZ_TARGET(asset_lock_tx_raw, .init = initialize_asset_lock_unlock)
{
    CDataStream ds(buffer, SER_NETWORK, INIT_PROTO_VERSION);
    try {
        const CTransaction tx(deserialize, ds);
        TxValidationState state;
        const bool result = CheckAssetLockTx(tx, state);
        assert(result == state.IsValid());
    } catch (const std::exception&) {
    }
}

FUZZ_TARGET(asset_unlock_fee, .init = initialize_asset_lock_unlock)
{
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());

    CMutableTransaction tx;
    tx.nVersion = CTransaction::SPECIAL_VERSION;
    tx.nType = TRANSACTION_ASSET_UNLOCK;

    const uint8_t payload_version = fuzzed_data_provider.ConsumeIntegral<uint8_t>();
    const uint64_t index = fuzzed_data_provider.ConsumeIntegral<uint64_t>();
    const uint32_t fee = fuzzed_data_provider.ConsumeIntegral<uint32_t>();
    const uint32_t requested_height = fuzzed_data_provider.ConsumeIntegral<uint32_t>();
    const uint256 quorum_hash = ConsumeUInt256(fuzzed_data_provider);
    const CBLSSignature quorum_sig = ConsumeBLSSignature(fuzzed_data_provider);
    SetTxPayload(tx, CAssetUnlockPayload(payload_version, index, fee, requested_height, quorum_hash, quorum_sig));

    if (fuzzed_data_provider.ConsumeBool()) {
        // Trigger payload deserialization failures with short/truncated random bytes.
        tx.vExtraPayload = fuzzed_data_provider.ConsumeBytes<uint8_t>(
            fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, 16));
    } else if (fuzzed_data_provider.ConsumeBool()) {
        // Trigger bad-txns-assetunlock-fee-outofrange.
        SetTxPayload(tx, CAssetUnlockPayload(payload_version, index, 0, requested_height, quorum_hash, quorum_sig));
    }

    CAmount txfee{0};
    TxValidationState state;
    const bool result = GetAssetUnlockFee(CTransaction(tx), txfee, state);
    assert(result == state.IsValid());
}

FUZZ_TARGET(credit_pool_lock_sequence, .init = initialize_credit_pool)
{
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());

    CCreditPool starter;
    starter.locked = fuzzed_data_provider.ConsumeIntegralInRange<CAmount>(0, 1000 * COIN);
    starter.currentLimit = fuzzed_data_provider.ConsumeIntegralInRange<CAmount>(0, CCreditPoolManager::LimitAmountV24);
    starter.latelyUnlocked = fuzzed_data_provider.ConsumeIntegralInRange<CAmount>(0, 1000 * COIN);

    const auto* const pindex_prev = g_credit_pool_setup->m_node.chainman->ActiveChain().Tip();
    const auto& consensus_params = Params().GetConsensus();
    constexpr CAmount block_subsidy = 5 * COIN;
    CCreditPoolDiff credit_pool_diff(starter, pindex_prev, consensus_params, block_subsidy);

    const auto& blockman = g_credit_pool_setup->m_node.chainman->m_blockman;
    const auto& qman = *g_credit_pool_setup->m_node.llmq_ctx->qman;

    const size_t iterations = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(1, 8);
    for (size_t i = 0; i < iterations; ++i) {
        CMutableTransaction tx;
        tx.nVersion = CTransaction::SPECIAL_VERSION;
        tx.nType = TRANSACTION_ASSET_LOCK;

        std::vector<CTxOut> credit_outputs;
        const size_t num_credit_outputs = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(1, 4);
        CAmount credit_outputs_total{0};
        for (size_t j = 0; j < num_credit_outputs; ++j) {
            const CAmount amount = fuzzed_data_provider.ConsumeIntegralInRange<CAmount>(1, 10 * COIN);
            assert(MoneyRange(amount));
            assert(MoneyRange(credit_outputs_total + amount));
            credit_outputs_total += amount;
            credit_outputs.emplace_back(amount, ConsumeP2PKHScript(fuzzed_data_provider));
        }

        SetTxPayload(tx, CAssetLockPayload(credit_outputs));
        tx.vout.emplace_back(credit_outputs_total, CScript() << OP_RETURN << std::vector<uint8_t>{});

        TxValidationState state;
        (void)credit_pool_diff.ProcessLockUnlockTransaction(blockman, qman, CTransaction(tx), state);
    }

    assert(credit_pool_diff.GetTotalLocked() >= 0);
}

FUZZ_TARGET(credit_pool_roundtrip, .init = initialize_asset_lock_unlock)
{
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());

    CCreditPool source;
    source.locked = fuzzed_data_provider.ConsumeIntegralInRange<CAmount>(0, MAX_MONEY);
    source.currentLimit = fuzzed_data_provider.ConsumeIntegralInRange<CAmount>(0, CCreditPoolManager::LimitAmountV24);
    source.latelyUnlocked = fuzzed_data_provider.ConsumeIntegralInRange<CAmount>(0, MAX_MONEY);

    std::set<uint64_t> unique_indexes;
    const size_t count = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, 8);
    for (size_t i = 0; i < count; ++i) {
        const uint64_t index = fuzzed_data_provider.ConsumeIntegral<uint64_t>();
        source.indexes.Add(index);
        unique_indexes.insert(index);
    }

    CDataStream ds(SER_NETWORK, PROTOCOL_VERSION);
    ds << source;

    CCreditPool decoded;
    ds >> decoded;

    assert(decoded.locked == source.locked);
    assert(decoded.currentLimit == source.currentLimit);
    assert(decoded.latelyUnlocked == source.latelyUnlocked);
    assert(decoded.indexes.Size() == unique_indexes.size());
    for (uint64_t index : unique_indexes) {
        assert(decoded.indexes.Contains(index));
    }
}

FUZZ_TARGET(asset_unlock_structural, .init = initialize_credit_pool)
{
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());

    CMutableTransaction tx;
    tx.nVersion = CTransaction::SPECIAL_VERSION;
    tx.nType = TRANSACTION_ASSET_UNLOCK;

    const size_t input_count = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, 2);
    for (size_t i = 0; i < input_count; ++i) {
        tx.vin.emplace_back();
    }

    const size_t output_count = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, 40);
    for (size_t i = 0; i < output_count; ++i) {
        tx.vout.emplace_back(
            fuzzed_data_provider.ConsumeIntegralInRange<CAmount>(0, 10 * COIN),
            ConsumeScript(fuzzed_data_provider));
    }

    const uint8_t payload_version = fuzzed_data_provider.ConsumeIntegral<uint8_t>();
    const uint64_t payload_index = fuzzed_data_provider.ConsumeIntegral<uint64_t>();
    const uint32_t fee = fuzzed_data_provider.ConsumeIntegral<uint32_t>();
    const uint32_t requested_height = fuzzed_data_provider.ConsumeIntegral<uint32_t>();
    const uint256 quorum_hash = ConsumeUInt256(fuzzed_data_provider);
    const CBLSSignature quorum_sig = ConsumeBLSSignature(fuzzed_data_provider);
    SetTxPayload(tx, CAssetUnlockPayload(payload_version, payload_index, fee, requested_height, quorum_hash, quorum_sig));

    CRangesSet indexes;
    const size_t known_count = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, 6);
    for (size_t i = 0; i < known_count; ++i) {
        indexes.Add(fuzzed_data_provider.ConsumeIntegral<uint64_t>());
    }

    const uint8_t mutation = fuzzed_data_provider.ConsumeIntegralInRange<uint8_t>(0, 6);
    switch (mutation) {
    case 0:
        tx.nType = fuzzed_data_provider.ConsumeBool() ? TRANSACTION_ASSET_LOCK : TRANSACTION_NORMAL;
        break;
    case 1:
        tx.vin.emplace_back();
        break;
    case 2:
        tx.vout.resize(CAssetUnlockPayload::MAXIMUM_WITHDRAWALS + 1);
        break;
    case 3:
        tx.vExtraPayload = fuzzed_data_provider.ConsumeBytes<uint8_t>(
            fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, 16));
        break;
    case 4:
        SetTxPayload(tx, CAssetUnlockPayload(fuzzed_data_provider.ConsumeBool() ? uint8_t{0}
                                                                                : std::numeric_limits<uint8_t>::max(),
                                             payload_index, fee, requested_height, quorum_hash, quorum_sig));
        break;
    case 5:
        indexes.Add(payload_index);
        break;
    case 6:
        break;
    }

    const auto& blockman = g_credit_pool_setup->m_node.chainman->m_blockman;
    const auto& qman = *g_credit_pool_setup->m_node.llmq_ctx->qman;
    const auto* const pindex_prev = g_credit_pool_setup->m_node.chainman->ActiveChain().Tip();

    TxValidationState state;
    const bool result = CheckAssetUnlockTx(blockman, qman, CTransaction(tx), pindex_prev, indexes, state);
    assert(result == state.IsValid());
}
