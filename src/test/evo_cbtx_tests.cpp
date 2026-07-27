// Copyright (c) 2026 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/util/llmq_tests.h>
#include <test/util/setup_common.h>

#include <bls/bls.h>
#include <chain.h>
#include <chainlock/chainlock.h>
#include <chainparams.h>
#include <compat/endian.h>
#include <consensus/merkle.h>
#include <consensus/validation.h>
#include <evo/cbtx.h>
#include <evo/evodb.h>
#include <evo/specialtx.h>
#include <evo/specialtxman.h>
#include <hash.h>
#include <llmq/blockprocessor.h>
#include <llmq/commitment.h>
#include <llmq/context.h>
#include <llmq/params.h>
#include <node/context.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <uint256.h>
#include <validation.h>

#include <cstdint>
#include <limits>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include <boost/test/unit_test.hpp>

using namespace llmq;
using namespace llmq::testutils;

BOOST_AUTO_TEST_SUITE(evo_cbtx_tests)

// Out-of-range bestCLHeightDiff (>= pindex->nHeight) must be rejected with
// "bad-cbtx-cldiff" so that the subsequent GetAncestor() call sees a valid height.
//
// The defensive nullptr branch after GetAncestor() returns "bad-cbtx-cldiff-ancestor".
// That branch is unreachable in practice (the range check guarantees the requested
// ancestor height is in [0, pindex->nHeight - 1], for which GetAncestor() never returns
// nullptr) and cannot be exercised from a unit test: a fake CBlockIndex with no pprev
// would trip GetAncestor()'s `assert(pprev)` while walking, not return nullptr.
BOOST_FIXTURE_TEST_CASE(check_cbtx_best_chainlock_rejects_excessive_height_diff, RegTestingSetup)
{
    const auto& consensus_params = Params().GetConsensus();
    const auto& chain = *WITH_LOCK(::cs_main, return &m_node.chainman->ActiveChain());
    auto& qman = *Assert(m_node.llmq_ctx)->qman;
    auto& chainlocks = *Assert(m_node.chainlocks);

    // Standalone fake block index with no predecessor, so the prevBlockCoinbaseChainlock
    // branch is skipped and the validation path under test is reached directly.
    CBlockIndex pindex;
    pindex.nHeight = 5;

    // A structurally-valid BLS signature is required for the IsValid() guard.
    CBLSSecretKey sk;
    sk.MakeNewKey();
    const bool legacy_scheme = bls::bls_legacy_scheme.load();
    CBLSSignature valid_sig = sk.Sign(uint256::ONE, legacy_scheme);
    BOOST_REQUIRE(valid_sig.IsValid());

    CCbTx cbTx;
    cbTx.nVersion = CCbTx::Version::CLSIG_AND_BALANCE;
    cbTx.bestCLSignature = valid_sig;

    // bestCLHeightDiff == nHeight: lower boundary of the rejected range.
    cbTx.bestCLHeightDiff = static_cast<uint32_t>(pindex.nHeight);
    BlockValidationState state;
    BOOST_CHECK(!CheckCbTxBestChainlock(cbTx, &pindex, consensus_params, chain, qman, chainlocks, state));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-cbtx-cldiff");

    // Upper boundary: uint32_t max.
    cbTx.bestCLHeightDiff = std::numeric_limits<uint32_t>::max();
    BlockValidationState state_big;
    BOOST_CHECK(!CheckCbTxBestChainlock(cbTx, &pindex, consensus_params, chain, qman, chainlocks, state_big));
    BOOST_CHECK_EQUAL(state_big.GetRejectReason(), "bad-cbtx-cldiff");
}

namespace {
// These mirror private constants/helpers in llmq/blockprocessor.cpp. There is no public
// API to install mined-commitment state without a full DKG, so the tests reproduce the
// key layout and then assert it round-trips through the public GetMinedCommitment()
// reader -- if the production layout ever changes, VerifyMinedCommitmentInstalled()
// fails loudly instead of the tests silently exercising nothing.
const std::string DB_MINED_COMMITMENT = "q_mc";
const std::string DB_MINED_COMMITMENT_BY_INVERSED_HEIGHT = "q_mcih";

std::tuple<std::string, Consensus::LLMQType, uint32_t> BuildInversedHeightKey(Consensus::LLMQType llmqType,
                                                                              int nMinedHeight)
{
    return std::make_tuple(DB_MINED_COMMITMENT_BY_INVERSED_HEIGHT, llmqType,
                           htobe32_internal(std::numeric_limits<uint32_t>::max() - nMinedHeight));
}

// Store `qc` as if it had been mined at `mined_height` for the genesis quorum base
// (quorumHeight 0). GetMinedCommitmentsUntilBlock iterates inversed-height keys over
// [pindex->nHeight, 0), so the scan height must be >= mined_height and mined_height > 0.
void WriteMinedCommitment(CEvoDB& evoDb, const CFinalCommitment& qc, const uint256& mined_block_hash, int mined_height)
{
    assert(mined_height > 0);
    evoDb.Write(std::make_pair(DB_MINED_COMMITMENT, std::make_pair(qc.llmqType, qc.quorumHash)),
                std::make_pair(qc, mined_block_hash));
    evoDb.Write(BuildInversedHeightKey(qc.llmqType, mined_height), /*quorumHeight=*/0);
}

// Guards against the hand-written key layout above drifting from blockprocessor.cpp.
void VerifyMinedCommitmentInstalled(const CQuorumBlockProcessor& qblockman, const CFinalCommitment& qc,
                                    const uint256& expected_mined_block_hash)
{
    const auto [stored_qc, stored_hash] = qblockman.GetMinedCommitment(qc.llmqType, qc.quorumHash);
    BOOST_REQUIRE_MESSAGE(stored_hash != uint256::ZERO,
                          "DB_MINED_COMMITMENT key layout no longer matches blockprocessor.cpp");
    BOOST_REQUIRE_EQUAL(stored_hash.ToString(), expected_mined_block_hash.ToString());
    BOOST_REQUIRE(::SerializeHash(stored_qc) == ::SerializeHash(qc));
}

uint256 CalcQuorumMerkleRootForCommitment(const CFinalCommitment& qc)
{
    std::vector<uint256> hashes{::SerializeHash(qc)};
    bool mutated{false};
    return ComputeMerkleRoot(hashes, &mutated);
}

CFinalCommitment MakeDistinctCommitment(const Consensus::LLMQParams& params, const uint256& quorum_hash, uint8_t salt)
{
    CFinalCommitment qc = CreateValidCommitment(params, quorum_hash);
    // Force a deterministic difference even if random BLS material collides.
    qc.quorumVvecHash = uint256{std::vector<unsigned char>(32, salt)};
    return qc;
}

CTransactionRef MakeCommitmentTx(const CFinalCommitment& qc, int height)
{
    CFinalCommitmentTxPayload payload;
    payload.nHeight = height;
    payload.commitment = qc;

    CMutableTransaction tx;
    tx.nVersion = 3;
    tx.nType = TRANSACTION_QUORUM_COMMITMENT;
    SetTxPayload(tx, payload);
    return MakeTransactionRef(std::move(tx));
}

CBlock MakeEmptyBlock()
{
    CBlock block;
    block.vtx.emplace_back(MakeTransactionRef(CMutableTransaction{}));
    return block;
}

uint256 CalcQuorumMerkleRoot(const CBlock& block, const CBlockIndex* pindex, const CQuorumBlockProcessor& qblockman)
{
    uint256 merkle_root;
    BlockValidationState state;
    BOOST_REQUIRE(CalcCbTxMerkleRootQuorums(block, pindex, qblockman, merkle_root, state));
    return merkle_root;
}

const CBlockIndex* GenesisIndex(const node::NodeContext& node)
{
    LOCK(cs_main);
    return node.chainman->ActiveChain()[0];
}

// Activate DIP0003 immediately so GetCommitmentsFromBlock accepts a commitment payload at
// a low height without building a long fake chain.
struct Dip3ActiveSetup : public RegTestingSetup {
    Dip3ActiveSetup() :
        RegTestingSetup({"-dip3params=1:1"})
    {
    }
};
} // anonymous namespace

// A disconnect that undoes a mined commitment must not leave CalcCbTxMerkleRootQuorums
// serving the old branch's commitment hash.
//
// The defect is specifically in the base-hash -> commitment-hash LRU. The outer
// whole-result cache is keyed by the active base-block list, which does change across a
// real reorg, so it is not itself the stale layer. This test therefore drives the LRU
// directly: it warms the cache at a base list that is *unchanged* by the swap, which is
// exactly the condition under which the LRU (and only the LRU) can answer staleley.
BOOST_FIXTURE_TEST_CASE(qc_hash_cache_invalidated_on_commitment_branch_change, Dip3ActiveSetup)
{
    auto& evoDb = *Assert(m_node.evodb);
    auto& qblockman = *Assert(m_node.llmq_ctx)->quorum_block_processor;
    const auto& params = GetLLMQParams(Consensus::LLMQType::LLMQ_TEST);

    const CBlockIndex* pindex_genesis = GenesisIndex(m_node);
    BOOST_REQUIRE(pindex_genesis != nullptr);
    const uint256 quorum_hash = pindex_genesis->GetBlockHash();

    const CFinalCommitment qc_a = MakeDistinctCommitment(params, quorum_hash, /*salt=*/0x11);
    const CFinalCommitment qc_b = MakeDistinctCommitment(params, quorum_hash, /*salt=*/0x22);
    BOOST_REQUIRE(::SerializeHash(qc_a) != ::SerializeHash(qc_b));

    const uint256 mined_hash_a = GetTestBlockHash(1);
    const uint256 mined_hash_b = GetTestBlockHash(2);
    const uint256 scan_hash = GetTestBlockHash(3);
    constexpr int mined_height = 1;

    CBlockIndex pindex_scan;
    pindex_scan.nHeight = mined_height;
    pindex_scan.pprev = const_cast<CBlockIndex*>(pindex_genesis);
    pindex_scan.phashBlock = &scan_hash;

    {
        auto dbTx = evoDb.BeginTransaction();
        WriteMinedCommitment(evoDb, qc_a, mined_hash_a, mined_height);
        dbTx->Commit();
    }
    VerifyMinedCommitmentInstalled(qblockman, qc_a, mined_hash_a);

    const CBlock block = MakeEmptyBlock();
    // Warm both cache layers against commitment A.
    BOOST_CHECK_EQUAL(CalcQuorumMerkleRoot(block, &pindex_scan, qblockman).ToString(),
                      CalcQuorumMerkleRootForCommitment(qc_a).ToString());

    // Swap evoDb to commitment B for the same base, leaving the active base-block list
    // untouched -- only the mined commitment differs, as across a branch swap.
    {
        auto dbTx = evoDb.BeginTransaction();
        WriteMinedCommitment(evoDb, qc_b, mined_hash_b, mined_height);
        dbTx->Commit();
    }
    VerifyMinedCommitmentInstalled(qblockman, qc_b, mined_hash_b);

    // After invalidation the replacement commitment must be visible. Asserting only this
    // pins the desired behavior; it deliberately does not assert what the stale cache
    // would have returned beforehand.
    qblockman.InvalidateCachedQcHashes();
    BOOST_CHECK_EQUAL(CalcQuorumMerkleRoot(block, &pindex_scan, qblockman).ToString(),
                      CalcQuorumMerkleRootForCommitment(qc_b).ToString());
}

// End-to-end seam: UndoBlock() itself must perform the invalidation, so a replacement
// commitment mined on the new branch is observed without any explicit cache call.
BOOST_FIXTURE_TEST_CASE(qc_hash_cache_invalidated_by_undoblock, Dip3ActiveSetup)
{
    auto& evoDb = *Assert(m_node.evodb);
    auto& qblockman = *Assert(m_node.llmq_ctx)->quorum_block_processor;
    const auto& params = GetLLMQParams(Consensus::LLMQType::LLMQ_TEST);

    const CBlockIndex* pindex_genesis = GenesisIndex(m_node);
    BOOST_REQUIRE(pindex_genesis != nullptr);
    const uint256 quorum_hash = pindex_genesis->GetBlockHash();

    const CFinalCommitment qc_a = MakeDistinctCommitment(params, quorum_hash, /*salt=*/0x33);
    const CFinalCommitment qc_b = MakeDistinctCommitment(params, quorum_hash, /*salt=*/0x44);
    BOOST_REQUIRE(::SerializeHash(qc_a) != ::SerializeHash(qc_b));

    const uint256 mined_hash_a = GetTestBlockHash(11);
    const uint256 mined_hash_b = GetTestBlockHash(12);
    constexpr int mined_height = 1;

    {
        auto dbTx = evoDb.BeginTransaction();
        WriteMinedCommitment(evoDb, qc_a, mined_hash_a, mined_height);
        dbTx->Commit();
    }
    VerifyMinedCommitmentInstalled(qblockman, qc_a, mined_hash_a);

    CBlockIndex pindex_mined;
    pindex_mined.nHeight = mined_height;
    pindex_mined.pprev = const_cast<CBlockIndex*>(pindex_genesis);
    pindex_mined.phashBlock = &mined_hash_a;

    CBlock block_with_qc = MakeEmptyBlock();
    block_with_qc.vtx.emplace_back(MakeCommitmentTx(qc_a, mined_height));
    const CBlock empty_block = MakeEmptyBlock();

    // Warm the caches against commitment A.
    BOOST_CHECK_EQUAL(CalcQuorumMerkleRoot(empty_block, &pindex_mined, qblockman).ToString(),
                      CalcQuorumMerkleRootForCommitment(qc_a).ToString());

    {
        LOCK(cs_main);
        auto dbTx = evoDb.BeginTransaction();
        BOOST_REQUIRE(qblockman.UndoBlock(block_with_qc, &pindex_mined));
        // Install the replacement branch's commitment while the disconnect transaction is
        // still open, mirroring a reorg that reconnects a different valid commitment.
        WriteMinedCommitment(evoDb, qc_b, mined_hash_b, mined_height);
        dbTx->Commit();
    }

    // No explicit InvalidateCachedQcHashes() here: UndoBlock must have done it.
    BOOST_CHECK_EQUAL(CalcQuorumMerkleRoot(empty_block, &pindex_mined, qblockman).ToString(),
                      CalcQuorumMerkleRootForCommitment(qc_b).ToString());
}

// A block that undoes only null commitments must not disturb the caches: null commitments
// are never written to evoDb, so they can never make the LRU stale.
BOOST_FIXTURE_TEST_CASE(qc_hash_cache_survives_null_commitment_undo, Dip3ActiveSetup)
{
    auto& evoDb = *Assert(m_node.evodb);
    auto& qblockman = *Assert(m_node.llmq_ctx)->quorum_block_processor;
    const auto& params = GetLLMQParams(Consensus::LLMQType::LLMQ_TEST);

    const CBlockIndex* pindex_genesis = GenesisIndex(m_node);
    BOOST_REQUIRE(pindex_genesis != nullptr);
    const uint256 quorum_hash = pindex_genesis->GetBlockHash();

    const CFinalCommitment qc_a = MakeDistinctCommitment(params, quorum_hash, /*salt=*/0x55);
    const uint256 mined_hash_a = GetTestBlockHash(21);
    constexpr int mined_height = 1;

    {
        auto dbTx = evoDb.BeginTransaction();
        WriteMinedCommitment(evoDb, qc_a, mined_hash_a, mined_height);
        dbTx->Commit();
    }
    VerifyMinedCommitmentInstalled(qblockman, qc_a, mined_hash_a);

    CBlockIndex pindex_mined;
    pindex_mined.nHeight = mined_height;
    pindex_mined.pprev = const_cast<CBlockIndex*>(pindex_genesis);
    pindex_mined.phashBlock = &mined_hash_a;

    const CBlock empty_block = MakeEmptyBlock();
    const uint256 expected = CalcQuorumMerkleRootForCommitment(qc_a);
    BOOST_CHECK_EQUAL(CalcQuorumMerkleRoot(empty_block, &pindex_mined, qblockman).ToString(), expected.ToString());

    // Undo a block carrying only a null commitment for the same type.
    CFinalCommitment null_qc;
    null_qc.llmqType = params.type;
    null_qc.quorumHash = quorum_hash;
    null_qc.validMembers.resize(params.size, false);
    null_qc.signers.resize(params.size, false);
    BOOST_REQUIRE(null_qc.IsNull());

    CBlock block_with_null = MakeEmptyBlock();
    block_with_null.vtx.emplace_back(MakeCommitmentTx(null_qc, mined_height));

    {
        LOCK(cs_main);
        auto dbTx = evoDb.BeginTransaction();
        BOOST_REQUIRE(qblockman.UndoBlock(block_with_null, &pindex_mined));
        dbTx->Commit();
    }

    // The mined commitment is untouched, so the result is unchanged either way; this pins
    // that undoing a null commitment does not erase real mined state.
    VerifyMinedCommitmentInstalled(qblockman, qc_a, mined_hash_a);
    BOOST_CHECK_EQUAL(CalcQuorumMerkleRoot(empty_block, &pindex_mined, qblockman).ToString(), expected.ToString());
}

BOOST_AUTO_TEST_SUITE_END()
