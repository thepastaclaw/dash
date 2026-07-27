// Copyright (c) 2018-2025 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_LLMQ_BLOCKPROCESSOR_H
#define BITCOIN_LLMQ_BLOCKPROCESSOR_H

#include <bls/bls.h>
#include <llmq/params.h>
#include <llmq/utils.h>
#include <msg_result.h>
#include <unordered_lru_cache.h>

#include <checkqueue.h>
#include <protocol.h>
#include <saltedhasher.h>
#include <sync.h>

#include <gsl/pointers.h>

#include <map>
#include <optional>
#include <utility>
#include <vector>

class BlockValidationState;
class CBlock;
class CBlockIndex;
class CBLSSignature;
class CChain;
class Chainstate;
class CDataStream;
class CDeterministicMNManager;
class CEvoDB;
class CNode;

extern RecursiveMutex cs_main; // NOLINT(readability-redundant-declaration)

namespace llmq
{
class CFinalCommitment;
class CQuorumSnapshotManager;

using QcHashMap = std::map<Consensus::LLMQType, std::vector<uint256>>;
using QcIndexedHashMap = std::map<Consensus::LLMQType, std::map<int16_t, uint256>>;

class CQuorumBlockProcessor
{
private:
    Chainstate& m_chainstate;
    CDeterministicMNManager& m_dmnman;
    CEvoDB& m_evoDb;
    CQuorumSnapshotManager& m_qsnapman;

    CCheckQueue<utils::BlsCheck> m_bls_queue{4};

    mutable Mutex minableCommitmentsCs;
    std::map<std::pair<Consensus::LLMQType, uint256>, uint256> minableCommitmentsByQuorum GUARDED_BY(minableCommitmentsCs);
    std::map<uint256, CFinalCommitment> minableCommitments GUARDED_BY(minableCommitmentsCs);

    mutable std::map<Consensus::LLMQType, Uint256LruHashMap<bool>> mapHasMinedCommitmentCache GUARDED_BY(minableCommitmentsCs);

    // Caches backing GetCachedQcHashes(), used by CalcCbTxMerkleRootQuorums.
    //
    // m_qc_hashes_lru maps a quorum *base* block hash to the hash of the commitment mined
    // for it. That key does not identify the branch the commitment was mined on: two valid
    // branches can mine different CFinalCommitments for the same base. evoDb is rolled back
    // on disconnect, but this LRU is not, so it must be dropped explicitly whenever mined
    // commitment state is undone -- otherwise CalcCbTxMerkleRootQuorums recomputes the old
    // branch's merkle root and rejects a valid replacement with bad-cbtx-quorummerkleroot.
    //
    // m_quorums_cached/m_qcHashes_cached/m_qcIndexedHashes_cached memoize the whole result
    // keyed by the active base-block list. That key does change across the reorg, so this
    // layer is not the source of the staleness; it is cleared alongside the LRU only because
    // it is derived from it.
    mutable Mutex m_qc_hashes_cache_mutex;
    mutable std::map<Consensus::LLMQType, Uint256LruHashMap<std::pair<uint256, int16_t>>> m_qc_hashes_lru
        GUARDED_BY(m_qc_hashes_cache_mutex);
    mutable std::map<Consensus::LLMQType, std::vector<const CBlockIndex*>> m_quorums_cached
        GUARDED_BY(m_qc_hashes_cache_mutex);
    mutable QcHashMap m_qcHashes_cached GUARDED_BY(m_qc_hashes_cache_mutex);
    mutable QcIndexedHashMap m_qcIndexedHashes_cached GUARDED_BY(m_qc_hashes_cache_mutex);

public:
    CQuorumBlockProcessor() = delete;
    CQuorumBlockProcessor(const CQuorumBlockProcessor&) = delete;
    CQuorumBlockProcessor& operator=(const CQuorumBlockProcessor&) = delete;
    explicit CQuorumBlockProcessor(Chainstate& chainstate, CDeterministicMNManager& dmnman, CEvoDB& evoDb,
                                   CQuorumSnapshotManager& qsnapman, int8_t bls_threads);
    ~CQuorumBlockProcessor();

    [[nodiscard]] MessageProcessingResult ProcessMessage(const CNode& peer, std::string_view msg_type, CDataStream& vRecv)
        EXCLUSIVE_LOCKS_REQUIRED(!minableCommitmentsCs);

    bool ProcessBlock(const CBlock& block, gsl::not_null<const CBlockIndex*> pindex, BlockValidationState& state,
                      bool fJustCheck, bool fBLSChecks) EXCLUSIVE_LOCKS_REQUIRED(::cs_main, !minableCommitmentsCs);
    bool UndoBlock(const CBlock& block, gsl::not_null<const CBlockIndex*> pindex)
        EXCLUSIVE_LOCKS_REQUIRED(::cs_main, !minableCommitmentsCs, !m_qc_hashes_cache_mutex);

    //! Commitment hashes for all mined-and-active quorums as of `pindexPrev`, memoized.
    //! Returns nullopt if a commitment referenced by the active base-block list is missing.
    std::optional<std::pair<QcHashMap, QcIndexedHashMap>> GetCachedQcHashes(const CBlockIndex* pindexPrev) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_qc_hashes_cache_mutex);

    //! Drop the caches behind GetCachedQcHashes(). Required whenever mined commitment data
    //! can change for an unchanged quorum base block (disconnect/reorg).
    void InvalidateCachedQcHashes() EXCLUSIVE_LOCKS_REQUIRED(!m_qc_hashes_cache_mutex);

    //! it returns hash of commitment if it should be relay, otherwise nullopt
    std::optional<CInv> AddMineableCommitment(const CFinalCommitment& fqc) EXCLUSIVE_LOCKS_REQUIRED(!minableCommitmentsCs);
    bool HasMineableCommitment(const uint256& hash) const EXCLUSIVE_LOCKS_REQUIRED(!minableCommitmentsCs);
    bool GetMineableCommitmentByHash(const uint256& commitmentHash, CFinalCommitment& ret) const
        EXCLUSIVE_LOCKS_REQUIRED(!minableCommitmentsCs);
    std::optional<std::vector<CFinalCommitment>> GetMineableCommitments(const Consensus::LLMQParams& llmqParams,
                                                                        int nHeight) const
        EXCLUSIVE_LOCKS_REQUIRED(::cs_main, !minableCommitmentsCs);
    bool GetMineableCommitmentsTx(const Consensus::LLMQParams& llmqParams, int nHeight, std::vector<CTransactionRef>& ret) const
        EXCLUSIVE_LOCKS_REQUIRED(::cs_main, !minableCommitmentsCs);
    bool HasMinedCommitment(Consensus::LLMQType llmqType, const uint256& quorumHash) const
        EXCLUSIVE_LOCKS_REQUIRED(!minableCommitmentsCs);
    std::pair<CFinalCommitment, uint256> GetMinedCommitment(Consensus::LLMQType llmqType, const uint256& quorumHash) const;

    std::vector<const CBlockIndex*> GetMinedCommitmentsUntilBlock(Consensus::LLMQType llmqType, gsl::not_null<const CBlockIndex*> pindex, size_t maxCount) const;
    std::map<Consensus::LLMQType, std::vector<const CBlockIndex*>> GetMinedAndActiveCommitmentsUntilBlock(gsl::not_null<const CBlockIndex*> pindex) const;

    std::vector<const CBlockIndex*> GetMinedCommitmentsIndexedUntilBlock(Consensus::LLMQType llmqType, const CBlockIndex* pindex, size_t maxCount) const;
    std::vector<const CBlockIndex*> GetLastMinedCommitmentsPerQuorumIndexUntilBlock(Consensus::LLMQType llmqType,
                                                                                    const CBlockIndex* pindex,
                                                                                    size_t cycle) const;
    std::optional<const CBlockIndex*> GetLastMinedCommitmentsByQuorumIndexUntilBlock(Consensus::LLMQType llmqType, const CBlockIndex* pindex, int quorumIndex, size_t cycle) const;
private:
    static bool GetCommitmentsFromBlock(const CBlock& block, gsl::not_null<const CBlockIndex*> pindex, std::multimap<Consensus::LLMQType, CFinalCommitment>& ret, BlockValidationState& state) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
    bool ProcessCommitment(int nHeight, const uint256& blockHash, const CFinalCommitment& qc, BlockValidationState& state,
                           bool fJustCheck) EXCLUSIVE_LOCKS_REQUIRED(::cs_main, !minableCommitmentsCs);
    size_t GetNumCommitmentsRequired(const Consensus::LLMQParams& llmqParams, int nHeight) const
        EXCLUSIVE_LOCKS_REQUIRED(::cs_main, !minableCommitmentsCs);
    static uint256 GetQuorumBlockHash(const Consensus::LLMQParams& llmqParams, const CChain& active_chain, int nHeight, int quorumIndex) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
};
} // namespace llmq

#endif // BITCOIN_LLMQ_BLOCKPROCESSOR_H
