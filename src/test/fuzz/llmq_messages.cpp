// Copyright (c) 2026-present The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <active/context.h>
#include <consensus/consensus.h>
#include <deploymentstatus.h>
#include <llmq/blockprocessor.h>
#include <llmq/commitment.h>
#include <llmq/context.h>
#include <llmq/dkgsession.h>
#include <llmq/dkgsessionmgr.h>
#include <llmq/observer/context.h>
#include <llmq/options.h>
#include <llmq/quorumsman.h>
#include <net.h>
#include <protocol.h>
#include <sync.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/util/mining.h>
#include <test/util/net.h>
#include <test/util/setup_common.h>
#include <test/util/validation.h>
#include <validationinterface.h>

#include <algorithm>
#include <array>
#include <memory>

namespace {
const TestingSetup* g_setup;

const std::array<const char*, 8> LLMQ_MESSAGE_TYPES{
    NetMsgType::QFCOMMITMENT, NetMsgType::QCONTRIB, NetMsgType::QCOMPLAINT, NetMsgType::QJUSTIFICATION,
    NetMsgType::QPCOMMITMENT, NetMsgType::QWATCH,   NetMsgType::QGETDATA,   NetMsgType::QDATA,
};

const CBlockIndex* ConsumeQuorumBaseIndex(FuzzedDataProvider& fuzzed_data_provider, const CChain& chain)
{
    const CBlockIndex* tip = chain.Tip();
    if (tip == nullptr) return nullptr;
    const int depth = fuzzed_data_provider.ConsumeIntegralInRange<int>(0, tip->nHeight);
    return tip->GetAncestor(tip->nHeight - depth);
}

std::vector<bool> ConsumeFixedSizeBits(FuzzedDataProvider& fuzzed_data_provider, size_t size)
{
    std::vector<bool> bits(size);
    for (size_t i = 0; i < size; ++i) {
        bits[i] = fuzzed_data_provider.ConsumeBool();
    }
    return bits;
}

CBLSPublicKey ConsumeBLSPublicKey(FuzzedDataProvider& fuzzed_data_provider)
{
    auto bytes = ConsumeRandomLengthByteVector(fuzzed_data_provider, CBLSPublicKey::SerSize);
    bytes.resize(CBLSPublicKey::SerSize);
    CBLSPublicKey pk;
    pk.SetBytes(bytes, fuzzed_data_provider.ConsumeBool());
    return pk;
}

CBLSSecretKey ConsumeBLSSecretKey(FuzzedDataProvider& fuzzed_data_provider)
{
    auto bytes = ConsumeRandomLengthByteVector(fuzzed_data_provider, CBLSSecretKey::SerSize);
    bytes.resize(CBLSSecretKey::SerSize);
    return CBLSSecretKey(bytes);
}

CBLSSignature ConsumeBLSSignature(FuzzedDataProvider& fuzzed_data_provider)
{
    auto bytes = ConsumeRandomLengthByteVector(fuzzed_data_provider, CBLSSignature::SerSize);
    bytes.resize(CBLSSignature::SerSize);
    CBLSSignature sig;
    sig.SetBytes(bytes, fuzzed_data_provider.ConsumeBool());
    return sig;
}

CDataStream BuildStructuredContribution(FuzzedDataProvider& fuzzed_data_provider, const CChain& chain)
{
    CDataStream vRecv{SER_NETWORK, INIT_PROTO_VERSION};
    const auto& llmqs = Params().GetConsensus().llmqs;
    if (llmqs.empty()) {
        return vRecv;
    }

    const auto& llmq_params = llmqs.at(fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, llmqs.size() - 1));
    const CBlockIndex* pindex = ConsumeQuorumBaseIndex(fuzzed_data_provider, chain);

    llmq::CDKGContribution contribution;
    contribution.llmqType = llmq_params.type;
    contribution.quorumHash = pindex ? pindex->GetBlockHash() : uint256{};
    contribution.proTxHash = ConsumeUInt256(fuzzed_data_provider);

    const size_t member_count = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, static_cast<size_t>(llmq_params.size));
    std::vector<CBLSPublicKey> vvec;
    vvec.reserve(member_count);
    for (size_t i = 0; i < member_count; ++i) {
        vvec.emplace_back(ConsumeBLSPublicKey(fuzzed_data_provider));
    }
    contribution.vvec = std::make_shared<std::vector<CBLSPublicKey>>(std::move(vvec));

    auto encrypted_contributions = std::make_shared<CBLSIESMultiRecipientObjects<CBLSSecretKey>>();
    encrypted_contributions->ephemeralPubKey = ConsumeBLSPublicKey(fuzzed_data_provider);
    encrypted_contributions->ivSeed = ConsumeUInt256(fuzzed_data_provider);
    const size_t blob_count = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, static_cast<size_t>(llmq_params.size));
    encrypted_contributions->blobs.reserve(blob_count);
    for (size_t i = 0; i < blob_count; ++i) {
        encrypted_contributions->blobs.emplace_back(ConsumeRandomLengthByteVector<unsigned char>(fuzzed_data_provider, 512));
    }
    contribution.contributions = std::move(encrypted_contributions);
    contribution.sig = ConsumeBLSSignature(fuzzed_data_provider);

    vRecv << contribution;
    return vRecv;
}

CDataStream BuildStructuredComplaint(FuzzedDataProvider& fuzzed_data_provider, const CChain& chain)
{
    CDataStream vRecv{SER_NETWORK, INIT_PROTO_VERSION};
    const auto& llmqs = Params().GetConsensus().llmqs;
    if (llmqs.empty()) {
        return vRecv;
    }

    const auto& llmq_params = llmqs.at(fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, llmqs.size() - 1));
    const CBlockIndex* pindex = ConsumeQuorumBaseIndex(fuzzed_data_provider, chain);

    llmq::CDKGComplaint complaint(llmq_params);
    complaint.llmqType = llmq_params.type;
    complaint.quorumHash = pindex ? pindex->GetBlockHash() : uint256{};
    complaint.proTxHash = ConsumeUInt256(fuzzed_data_provider);
    complaint.badMembers = ConsumeFixedSizeBits(fuzzed_data_provider, llmq_params.size);
    complaint.complainForMembers = ConsumeFixedSizeBits(fuzzed_data_provider, llmq_params.size);
    complaint.sig = ConsumeBLSSignature(fuzzed_data_provider);

    vRecv << complaint;
    return vRecv;
}

CDataStream BuildStructuredJustification(FuzzedDataProvider& fuzzed_data_provider, const CChain& chain)
{
    CDataStream vRecv{SER_NETWORK, INIT_PROTO_VERSION};
    const auto& llmqs = Params().GetConsensus().llmqs;
    if (llmqs.empty()) {
        return vRecv;
    }

    const auto& llmq_params = llmqs.at(fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, llmqs.size() - 1));
    const CBlockIndex* pindex = ConsumeQuorumBaseIndex(fuzzed_data_provider, chain);

    llmq::CDKGJustification justification;
    justification.llmqType = llmq_params.type;
    justification.quorumHash = pindex ? pindex->GetBlockHash() : uint256{};
    justification.proTxHash = ConsumeUInt256(fuzzed_data_provider);
    const size_t contribution_count = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, static_cast<size_t>(llmq_params.size));
    justification.contributions.reserve(contribution_count);
    for (size_t i = 0; i < contribution_count; ++i) {
        llmq::CDKGJustification::Contribution c;
        c.index = fuzzed_data_provider.ConsumeIntegral<uint32_t>();
        c.key = ConsumeBLSSecretKey(fuzzed_data_provider);
        justification.contributions.emplace_back(std::move(c));
    }
    justification.sig = ConsumeBLSSignature(fuzzed_data_provider);

    vRecv << justification;
    return vRecv;
}

CDataStream BuildStructuredPrematureCommitment(FuzzedDataProvider& fuzzed_data_provider, const CChain& chain)
{
    CDataStream vRecv{SER_NETWORK, INIT_PROTO_VERSION};
    const auto& llmqs = Params().GetConsensus().llmqs;
    if (llmqs.empty()) {
        return vRecv;
    }

    const auto& llmq_params = llmqs.at(fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, llmqs.size() - 1));
    const CBlockIndex* pindex = ConsumeQuorumBaseIndex(fuzzed_data_provider, chain);

    llmq::CDKGPrematureCommitment premature_commitment(llmq_params);
    premature_commitment.llmqType = llmq_params.type;
    premature_commitment.quorumHash = pindex ? pindex->GetBlockHash() : uint256{};
    premature_commitment.proTxHash = ConsumeUInt256(fuzzed_data_provider);
    premature_commitment.validMembers = ConsumeFixedSizeBits(fuzzed_data_provider, llmq_params.size);
    premature_commitment.quorumPublicKey = ConsumeBLSPublicKey(fuzzed_data_provider);
    premature_commitment.quorumVvecHash = ConsumeUInt256(fuzzed_data_provider);
    premature_commitment.quorumSig = ConsumeBLSSignature(fuzzed_data_provider);
    premature_commitment.sig = ConsumeBLSSignature(fuzzed_data_provider);

    vRecv << premature_commitment;
    return vRecv;
}

CDataStream BuildStructuredFinalCommitment(FuzzedDataProvider& fuzzed_data_provider, const CChain& chain)
{
    CDataStream vRecv{SER_NETWORK, INIT_PROTO_VERSION};
    const auto& llmqs = Params().GetConsensus().llmqs;
    if (llmqs.empty()) {
        return vRecv;
    }

    const auto& llmq_params = llmqs.at(fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, llmqs.size() - 1));
    const CBlockIndex* pindex = ConsumeQuorumBaseIndex(fuzzed_data_provider, chain);
    if (pindex == nullptr) {
        return vRecv;
    }

    llmq::CFinalCommitment qc(llmq_params, pindex->GetBlockHash());
    qc.nVersion = llmq::CFinalCommitment::GetVersion(llmq::IsQuorumRotationEnabled(llmq_params, pindex),
                                                     DeploymentActiveAfter(pindex, Params().GetConsensus(),
                                                                           Consensus::DEPLOYMENT_V19));
    qc.quorumIndex = pindex->nHeight % llmq_params.dkgInterval;

    if (fuzzed_data_provider.ConsumeBool()) {
        qc.signers = ConsumeFixedSizeBits(fuzzed_data_provider, llmq_params.size);
    }
    if (fuzzed_data_provider.ConsumeBool()) {
        qc.validMembers = ConsumeFixedSizeBits(fuzzed_data_provider, llmq_params.size);
    }
    if (fuzzed_data_provider.ConsumeBool()) {
        qc.llmqType = static_cast<Consensus::LLMQType>(fuzzed_data_provider.ConsumeIntegral<uint8_t>());
    }
    if (fuzzed_data_provider.ConsumeBool()) {
        qc.quorumHash = ConsumeUInt256(fuzzed_data_provider);
    }
    if (fuzzed_data_provider.ConsumeBool()) {
        qc.quorumIndex = fuzzed_data_provider.ConsumeIntegral<int16_t>();
    }
    if (fuzzed_data_provider.ConsumeBool()) {
        qc.nVersion = fuzzed_data_provider.ConsumeIntegral<uint16_t>();
    }

    vRecv << qc;
    return vRecv;
}
} // namespace

void initialize_llmq_messages()
{
    static const auto testing_setup = MakeNoLogFileContext<const TestingSetup>(
        /*chain_name=*/CBaseChainParams::REGTEST,
        /*extra_args=*/{"-txreconciliation", "-watchquorums=1"});
    g_setup = testing_setup.get();
    for (int i = 0; i < 2 * COINBASE_MATURITY; i++) {
        MineBlock(g_setup->m_node, CScript() << OP_TRUE);
    }
    SyncWithValidationInterfaceQueue();
}

FUZZ_TARGET(llmq_messages, .init = initialize_llmq_messages)
{
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());

    ConnmanTestMsg& connman = *static_cast<ConnmanTestMsg*>(g_setup->m_node.connman.get());
    TestChainState& chainstate = *static_cast<TestChainState*>(&g_setup->m_node.chainman->ActiveChainstate());
    SetMockTime(4102444800); // Keep SPORK_17_QUORUM_DKG_ENABLED active on test chains.
    chainstate.ResetIbd();

    LOCK(NetEventsInterface::g_msgproc_mutex);

    CNode& p2p_node = *ConsumeNodeAsUniquePtr(fuzzed_data_provider).release();
    connman.AddTestNode(p2p_node);
    FillNode(fuzzed_data_provider, connman, p2p_node);

    auto* dkg_session_manager = g_setup->m_node.active_ctx
                                    ? g_setup->m_node.active_ctx->qdkgsman.get()
                                    : (g_setup->m_node.observer_ctx ? g_setup->m_node.observer_ctx->qdkgsman.get()
                                                                    : nullptr);

    const size_t iterations = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(1, 64);
    for (size_t i = 0; i < iterations; ++i) {
        const std::string msg_type = fuzzed_data_provider.PickValueInArray(LLMQ_MESSAGE_TYPES);
        CDataStream vRecv = [&]() {
            if (msg_type == NetMsgType::QFCOMMITMENT && fuzzed_data_provider.ConsumeBool()) {
                return BuildStructuredFinalCommitment(fuzzed_data_provider, chainstate.m_chain);
            }
            if (msg_type == NetMsgType::QCONTRIB && fuzzed_data_provider.ConsumeBool()) {
                return BuildStructuredContribution(fuzzed_data_provider, chainstate.m_chain);
            }
            if (msg_type == NetMsgType::QCOMPLAINT && fuzzed_data_provider.ConsumeBool()) {
                return BuildStructuredComplaint(fuzzed_data_provider, chainstate.m_chain);
            }
            if (msg_type == NetMsgType::QJUSTIFICATION && fuzzed_data_provider.ConsumeBool()) {
                return BuildStructuredJustification(fuzzed_data_provider, chainstate.m_chain);
            }
            if (msg_type == NetMsgType::QPCOMMITMENT && fuzzed_data_provider.ConsumeBool()) {
                return BuildStructuredPrematureCommitment(fuzzed_data_provider, chainstate.m_chain);
            }
            return ConsumeDataStream(fuzzed_data_provider, MAX_PROTOCOL_MESSAGE_LENGTH);
        }();

        try {
            if (msg_type == NetMsgType::QFCOMMITMENT) {
                g_setup->m_node.peerman->PostProcessMessage(
                    g_setup->m_node.llmq_ctx->quorum_block_processor->ProcessMessage(p2p_node, msg_type, vRecv),
                    p2p_node.GetId());
                continue;
            }

            if (dkg_session_manager != nullptr &&
                (msg_type == NetMsgType::QCONTRIB || msg_type == NetMsgType::QCOMPLAINT ||
                 msg_type == NetMsgType::QJUSTIFICATION || msg_type == NetMsgType::QPCOMMITMENT ||
                 msg_type == NetMsgType::QWATCH)) {
                g_setup->m_node.peerman->PostProcessMessage(
                    dkg_session_manager->ProcessMessage(p2p_node, g_setup->m_node.active_ctx != nullptr, msg_type, vRecv),
                    p2p_node.GetId());
                continue;
            }

            g_setup->m_node.peerman->PostProcessMessage(g_setup->m_node.llmq_ctx->qman->ProcessMessage(p2p_node, connman,
                                                                                                       msg_type, vRecv),
                                                        p2p_node.GetId());
        } catch (const std::ios_base::failure&) {
        }
    }

    SyncWithValidationInterfaceQueue();
    g_setup->m_node.connman->StopNodes();
}
