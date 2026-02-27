// Copyright (c) 2026-present The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <coinjoin/coinjoin.h>
#include <coinjoin/common.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <streams.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <util/time.h>

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <vector>

namespace {

void initialize_coinjoin_state_machine() { SelectParams(CBaseChainParams::REGTEST); }

// ──────────────────────────────────────────────────────────────────────
// Test subclass that exposes the protected state machine internals of
// CCoinJoinBaseSession and CCoinJoinBaseManager without requiring the
// heavy dependency chain of CCoinJoinServer (CConnman, ChainstateManager,
// CDeterministicMNManager, CActiveMasternodeManager, etc.).
// ──────────────────────────────────────────────────────────────────────
class TestCoinJoinSession : public CCoinJoinBaseSession, public CCoinJoinBaseManager
{
public:
    // ── State manipulation ──────────────────────────────────────────
    void SetState(PoolState state) { nState = state; nTimeLastSuccessfulStep = GetTime(); }
    PoolState GetState() const { return static_cast<PoolState>(nState.load()); }
    void SetSessionID(int id) { nSessionID = id; }
    int GetSessionID() const { return nSessionID; }
    void SetSessionDenom(int denom) { nSessionDenom = denom; }
    int GetSessionDenom() const { return nSessionDenom; }

    // ── Collateral tracking (simulates vecSessionCollaterals) ───────
    std::vector<CTransactionRef> vecSessionCollaterals;

    // ── Simulate CreateNewSession (server.cpp:~L364) ────────────────
    bool SimulateCreateNewSession(int denom)
    {
        if (nSessionID != 0) return false;
        if (nState != POOL_STATE_IDLE) return false;
        if (!CoinJoin::IsValidDenomination(denom)) return false;

        nSessionID = GetRand<int>(999999) + 1;
        nSessionDenom = denom;
        SetState(POOL_STATE_QUEUE);
        return true;
    }

    // ── Simulate AddUserToExistingSession (server.cpp:~L399) ────────
    bool SimulateAddUser(int denom, CTransactionRef collateral)
    {
        if (nSessionID == 0) return false;
        if (nState != POOL_STATE_QUEUE) return false;
        if (denom != nSessionDenom) return false;
        if (static_cast<int>(vecSessionCollaterals.size()) >= CoinJoin::GetMaxPoolParticipants()) return false;

        vecSessionCollaterals.push_back(std::move(collateral));
        return true;
    }

    // ── Simulate IsSessionReady (server.cpp:~L415) ──────────────────
    bool IsSessionReady() const
    {
        if (nState == POOL_STATE_QUEUE) {
            return static_cast<int>(vecSessionCollaterals.size()) >= CoinJoin::GetMaxPoolParticipants();
        }
        if (nState == POOL_STATE_ACCEPTING_ENTRIES) {
            return true;
        }
        return false;
    }

    // ── Simulate CheckForCompleteQueue (server.cpp:~L244) ───────────
    void SimulateCheckForCompleteQueue()
    {
        if (nState == POOL_STATE_QUEUE && IsSessionReady()) {
            SetState(POOL_STATE_ACCEPTING_ENTRIES);
        }
    }

    // ── Simulate AddEntry without UTXO validation (server.cpp:~L290) ─
    bool SimulateAddEntry(const CCoinJoinEntry& entry, PoolMessage& nMessageIDRet)
    {
        LOCK(cs_coinjoin);

        if (vecEntries.size() >= vecSessionCollaterals.size()) {
            nMessageIDRet = ERR_ENTRIES_FULL;
            return false;
        }

        if (entry.vecTxDSIn.size() > COINJOIN_ENTRY_MAX_SIZE) {
            nMessageIDRet = ERR_MAXIMUM;
            return false;
        }

        // Check for duplicate inputs across existing entries
        for (const auto& existing : vecEntries) {
            for (const auto& txin : entry.vecTxDSIn) {
                for (const auto& existing_in : existing.vecTxDSIn) {
                    if (existing_in.prevout == txin.prevout) {
                        nMessageIDRet = ERR_ALREADY_HAVE;
                        return false;
                    }
                }
            }
        }

        vecEntries.push_back(entry);
        nMessageIDRet = MSG_ENTRIES_ADDED;
        return true;
    }

    // ── Simulate CreateFinalTransaction (server.cpp:~L200) ──────────
    void SimulateCreateFinalTransaction()
    {
        LOCK(cs_coinjoin);
        CMutableTransaction txNew;

        for (const auto& entry : vecEntries) {
            for (const auto& txout : entry.vecTxOut) {
                txNew.vout.push_back(txout);
            }
            for (const auto& txdsin : entry.vecTxDSIn) {
                txNew.vin.push_back(txdsin);
            }
        }

        sort(txNew.vin.begin(), txNew.vin.end(), CompareInputBIP69());
        sort(txNew.vout.begin(), txNew.vout.end(), CompareOutputBIP69());

        finalMutableTransaction = txNew;
        nState = POOL_STATE_SIGNING;
        nTimeLastSuccessfulStep = GetTime();
    }

    // ── Simulate CheckPool (server.cpp:~L180) ───────────────────────
    void SimulateCheckPool()
    {
        if (nState == POOL_STATE_ACCEPTING_ENTRIES &&
            vecEntries.size() == vecSessionCollaterals.size() &&
            !vecEntries.empty()) {
            SimulateCreateFinalTransaction();
            return;
        }

        if (nState == POOL_STATE_SIGNING && IsSignaturesComplete()) {
            // Would normally CommitFinalTransaction — just verify state is consistent
            LOCK(cs_coinjoin);
            (void)CTransaction(finalMutableTransaction);
            return;
        }
    }

    // ── AddScriptSig to final tx + entries ──────────────────────────
    bool SimulateAddScriptSig(const CTxIn& txinNew)
    {
        LOCK(cs_coinjoin);

        // Check for duplicate scriptsig
        for (const auto& entry : vecEntries) {
            for (const auto& txdsin : entry.vecTxDSIn) {
                if (txdsin.scriptSig == txinNew.scriptSig && !txinNew.scriptSig.empty()) {
                    return false;
                }
            }
        }

        // Update final transaction
        for (auto& txin : finalMutableTransaction.vin) {
            if (txin.prevout == txinNew.prevout && txin.nSequence == txinNew.nSequence) {
                txin.scriptSig = txinNew.scriptSig;
            }
        }

        // Mark in entries
        for (auto& entry : vecEntries) {
            if (entry.AddScriptSig(txinNew)) return true;
        }

        return false;
    }

    // ── Check if all inputs are signed ──────────────────────────────
    bool IsSignaturesComplete() const
    {
        AssertLockHeld(cs_coinjoin);
        for (const auto& entry : vecEntries) {
            for (const auto& txdsin : entry.vecTxDSIn) {
                if (!txdsin.fHasSig) return false;
            }
        }
        return true;
    }

    // ── Accessors ───────────────────────────────────────────────────
    size_t GetEntryCount() const { LOCK(cs_coinjoin); return vecEntries.size(); }
    size_t GetFinalTxVinSize() const { LOCK(cs_coinjoin); return finalMutableTransaction.vin.size(); }
    size_t GetFinalTxVoutSize() const { LOCK(cs_coinjoin); return finalMutableTransaction.vout.size(); }

    // ── Reset ───────────────────────────────────────────────────────
    void Reset()
    {
        LOCK(cs_coinjoin);
        CCoinJoinBaseSession::SetNull();
        vecSessionCollaterals.clear();
        CCoinJoinBaseManager::SetNull();
    }
};

// ── Helpers ─────────────────────────────────────────────────────────

static CScript MakeP2PKHScript(FuzzedDataProvider& fdp)
{
    std::vector<unsigned char> hash(20, 0);
    auto bytes = fdp.ConsumeBytes<uint8_t>(20);
    if (bytes.size() == 20) {
        memcpy(hash.data(), bytes.data(), 20);
    }
    return CScript() << OP_DUP << OP_HASH160 << hash << OP_EQUALVERIFY << OP_CHECKSIG;
}

static COutPoint MakeOutPoint(FuzzedDataProvider& fdp)
{
    uint256 hash;
    auto bytes = fdp.ConsumeBytes<uint8_t>(32);
    if (bytes.size() == 32) {
        memcpy(hash.begin(), bytes.data(), 32);
    }
    return COutPoint(hash, fdp.ConsumeIntegral<uint32_t>());
}

static constexpr std::array<int, 5> VALID_DENOMS = {1, 2, 4, 8, 16};

static int PickValidDenom(FuzzedDataProvider& fdp)
{
    return VALID_DENOMS[fdp.ConsumeIntegralInRange<size_t>(0, 4)];
}

static CTransactionRef MakeTrivialCollateral(FuzzedDataProvider& fdp)
{
    CMutableTransaction mtx;
    mtx.vin.push_back(CTxIn(MakeOutPoint(fdp)));
    mtx.vout.push_back(CTxOut(CoinJoin::GetCollateralAmount(), MakeP2PKHScript(fdp)));
    return MakeTransactionRef(mtx);
}

static CCoinJoinEntry MakeValidEntry(FuzzedDataProvider& fdp, int denom, size_t num_inputs)
{
    CCoinJoinEntry entry;
    const CAmount amount = CoinJoin::DenominationToAmount(denom);
    num_inputs = std::clamp(num_inputs, size_t{1}, size_t{COINJOIN_ENTRY_MAX_SIZE});

    for (size_t i = 0; i < num_inputs; ++i) {
        CTxDSIn dsin;
        dsin.prevout = MakeOutPoint(fdp);
        dsin.nSequence = CTxIn::SEQUENCE_FINAL;
        dsin.prevPubKey = MakeP2PKHScript(fdp);
        entry.vecTxDSIn.push_back(dsin);

        CTxOut txout(amount, MakeP2PKHScript(fdp));
        entry.vecTxOut.push_back(txout);
    }

    entry.txCollateral = MakeTrivialCollateral(fdp);
    return entry;
}

// ── Operation enum for the state machine fuzzer ─────────────────────
enum class FuzzOp : uint8_t {
    CREATE_SESSION = 0,
    ADD_USER,
    CHECK_COMPLETE_QUEUE,
    ADD_ENTRY,
    CHECK_POOL,
    ADD_SCRIPTSIG,
    RESET,
    SET_MOCK_TIME,
    OP_MAX
};

} // namespace

// ═══════════════════════════════════════════════════════════════════════
// Target 1: Full state machine transition fuzzing
//
// Generates a sequence of operations that drive the CoinJoin session
// through its lifecycle: IDLE → QUEUE → ACCEPTING_ENTRIES → SIGNING.
// Uses fuzzed data to choose operations, denominations, entry counts,
// and timing. Verifies no crashes, no UB, and state consistency.
// ═══════════════════════════════════════════════════════════════════════
FUZZ_TARGET(coinjoin_state_transitions, .init = initialize_coinjoin_state_machine)
{
    FuzzedDataProvider fdp(buffer.data(), buffer.size());
    TestCoinJoinSession session;

    // Track inputs we've added so we can generate valid scriptsigs
    std::vector<std::pair<COutPoint, uint32_t>> added_inputs;

    LIMITED_WHILE(fdp.remaining_bytes() > 0, 200)
    {
        const auto op = static_cast<FuzzOp>(fdp.ConsumeIntegralInRange<uint8_t>(0, static_cast<uint8_t>(FuzzOp::OP_MAX) - 1));

        switch (op) {
        case FuzzOp::CREATE_SESSION: {
            const int denom = PickValidDenom(fdp);
            const bool created = session.SimulateCreateNewSession(denom);
            if (created) {
                assert(session.GetState() == POOL_STATE_QUEUE);
                assert(session.GetSessionID() > 0);
                assert(CoinJoin::IsValidDenomination(session.GetSessionDenom()));
                // First user's collateral
                session.vecSessionCollaterals.push_back(MakeTrivialCollateral(fdp));
            }
            break;
        }

        case FuzzOp::ADD_USER: {
            if (session.GetSessionID() == 0) break;
            const int denom = fdp.ConsumeBool() ? session.GetSessionDenom() : PickValidDenom(fdp);
            auto collateral = MakeTrivialCollateral(fdp);
            (void)session.SimulateAddUser(denom, std::move(collateral));
            break;
        }

        case FuzzOp::CHECK_COMPLETE_QUEUE: {
            const PoolState before = session.GetState();
            session.SimulateCheckForCompleteQueue();
            const PoolState after = session.GetState();
            // Can only transition QUEUE → ACCEPTING_ENTRIES
            if (before != POOL_STATE_QUEUE) {
                assert(after == before);
            }
            break;
        }

        case FuzzOp::ADD_ENTRY: {
            if (session.GetState() != POOL_STATE_ACCEPTING_ENTRIES &&
                session.GetState() != POOL_STATE_QUEUE) break;
            if (session.GetSessionDenom() == 0) break;

            const size_t num_inputs = fdp.ConsumeIntegralInRange<size_t>(1, COINJOIN_ENTRY_MAX_SIZE);
            CCoinJoinEntry entry = MakeValidEntry(fdp, session.GetSessionDenom(), num_inputs);

            // Remember the inputs for later scriptsig generation
            for (const auto& txdsin : entry.vecTxDSIn) {
                added_inputs.emplace_back(txdsin.prevout, txdsin.nSequence);
            }

            PoolMessage msg;
            (void)session.SimulateAddEntry(entry, msg);
            // msg must be a valid PoolMessage value
            assert(msg >= MSG_POOL_MIN && msg <= MSG_POOL_MAX);
            break;
        }

        case FuzzOp::CHECK_POOL: {
            session.SimulateCheckPool();
            // State must remain in valid range
            const auto state = session.GetState();
            assert(state >= POOL_STATE_MIN && state <= POOL_STATE_MAX);
            break;
        }

        case FuzzOp::ADD_SCRIPTSIG: {
            if (session.GetState() != POOL_STATE_SIGNING) break;
            if (added_inputs.empty()) break;

            // Pick a random input to "sign"
            const size_t idx = fdp.ConsumeIntegralInRange<size_t>(0, added_inputs.size() - 1);
            CTxIn txin;
            txin.prevout = added_inputs[idx].first;
            txin.nSequence = added_inputs[idx].second;

            // Generate a fuzzed scriptsig
            auto sig_bytes = fdp.ConsumeBytes<uint8_t>(fdp.ConsumeIntegralInRange<size_t>(1, 73));
            txin.scriptSig = CScript(sig_bytes.begin(), sig_bytes.end());

            (void)session.SimulateAddScriptSig(txin);
            break;
        }

        case FuzzOp::RESET: {
            session.Reset();
            added_inputs.clear();
            assert(session.GetState() == POOL_STATE_IDLE);
            assert(session.GetSessionID() == 0);
            assert(session.GetEntryCount() == 0);
            break;
        }

        case FuzzOp::SET_MOCK_TIME: {
            const int64_t t = fdp.ConsumeIntegralInRange<int64_t>(0, 4102444800); // up to 2100
            SetMockTime(t);
            break;
        }

        default:
            break;
        }

        // Invariant: final tx vin/vout sizes are always equal if any entries have been finalized
        if (session.GetState() == POOL_STATE_SIGNING) {
            assert(session.GetFinalTxVinSize() == session.GetFinalTxVoutSize());
        }
    }

    SetMockTime(0);
}

// ═══════════════════════════════════════════════════════════════════════
// Target 2: Queue management fuzzing
//
// Exercises CCoinJoinBaseManager queue operations: push, CheckQueue
// (timeout removal), and GetQueueItemAndTry (mark-tried logic).
// Tests with fuzzed times and queue entries to find edge cases in
// timeout handling and duplicate detection.
// ═══════════════════════════════════════════════════════════════════════
class TestBaseManager : public CCoinJoinBaseManager
{
public:
    void PushQueue(const CCoinJoinQueue& q)
    {
        LOCK(cs_vecqueue);
        vecCoinJoinQueue.push_back(q);
    }

    size_t QueueSize() const
    {
        LOCK(cs_vecqueue);
        return vecCoinJoinQueue.size();
    }

    void CallCheckQueue() { CheckQueue(); }
};

FUZZ_TARGET(coinjoin_queue_fuzz, .init = initialize_coinjoin_state_machine)
{
    FuzzedDataProvider fdp(buffer.data(), buffer.size());
    TestBaseManager manager;

    LIMITED_WHILE(fdp.remaining_bytes() > 0, 100)
    {
        const auto action = fdp.ConsumeIntegralInRange<uint8_t>(0, 4);

        switch (action) {
        case 0: {
            // Push a queue entry
            CCoinJoinQueue q;
            q.nDenom = fdp.ConsumeBool() ? PickValidDenom(fdp) : fdp.ConsumeIntegral<int>();
            q.masternodeOutpoint = MakeOutPoint(fdp);
            q.m_protxHash = uint256::ONE;
            q.nTime = fdp.ConsumeIntegral<int64_t>();
            q.fReady = fdp.ConsumeBool();
            manager.PushQueue(q);
            break;
        }
        case 1: {
            // CheckQueue — removes timed-out entries
            const size_t before = manager.QueueSize();
            manager.CallCheckQueue();
            // Queue can only shrink or stay the same
            assert(manager.QueueSize() <= before);
            break;
        }
        case 2: {
            // GetQueueItemAndTry — marks one item as tried
            CCoinJoinQueue picked;
            (void)manager.GetQueueItemAndTry(picked);
            break;
        }
        case 3: {
            // HasQueue — lookup by hash
            CCoinJoinQueue q;
            q.nDenom = PickValidDenom(fdp);
            q.m_protxHash = uint256::ONE;
            q.nTime = fdp.ConsumeIntegral<int64_t>();
            (void)manager.HasQueue(q.GetHash());
            break;
        }
        case 4: {
            // Set mock time to stress timeout logic
            const int64_t t = fdp.ConsumeIntegralInRange<int64_t>(0, 4102444800);
            SetMockTime(t);
            break;
        }
        }
    }

    SetMockTime(0);
}

// ═══════════════════════════════════════════════════════════════════════
// Target 3: Full protocol flow simulation
//
// Simulates a complete CoinJoin mixing round from session creation
// through signing, using structured fuzzed data. This drives the state
// machine through the entire happy path while fuzzing the entry details,
// number of participants, and scriptsig contents.
// ═══════════════════════════════════════════════════════════════════════
FUZZ_TARGET(coinjoin_protocol_flow, .init = initialize_coinjoin_state_machine)
{
    FuzzedDataProvider fdp(buffer.data(), buffer.size());

    if (fdp.remaining_bytes() < 20) return;

    TestCoinJoinSession session;

    // ── Phase 1: Create session ─────────────────────────────────────
    const int denom = PickValidDenom(fdp);
    if (!session.SimulateCreateNewSession(denom)) return;

    // Add the creator's collateral
    session.vecSessionCollaterals.push_back(MakeTrivialCollateral(fdp));

    // ── Phase 2: Add participants ───────────────────────────────────
    const int num_participants = fdp.ConsumeIntegralInRange<int>(
        CoinJoin::GetMinPoolParticipants(),
        CoinJoin::GetMaxPoolParticipants());

    // We already have 1 (the creator), add the rest
    for (int i = 1; i < num_participants; ++i) {
        auto collateral = MakeTrivialCollateral(fdp);
        session.SimulateAddUser(denom, std::move(collateral));
    }

    // ── Phase 3: Transition to ACCEPTING_ENTRIES ────────────────────
    session.SimulateCheckForCompleteQueue();
    if (session.GetState() != POOL_STATE_ACCEPTING_ENTRIES) return;

    // ── Phase 4: Submit entries from each participant ────────────────
    const size_t inputs_per_entry = fdp.ConsumeIntegralInRange<size_t>(1, COINJOIN_ENTRY_MAX_SIZE);
    std::vector<CCoinJoinEntry> submitted_entries;

    for (int i = 0; i < num_participants; ++i) {
        if (fdp.remaining_bytes() < 50) break;

        CCoinJoinEntry entry = MakeValidEntry(fdp, denom, inputs_per_entry);
        PoolMessage msg;
        if (session.SimulateAddEntry(entry, msg)) {
            submitted_entries.push_back(entry);
        }
    }

    if (submitted_entries.empty()) return;

    // ── Phase 5: Check pool → should create final tx ────────────────
    session.SimulateCheckPool();

    // If we added enough entries to match collaterals, we should be signing now
    if (session.GetState() != POOL_STATE_SIGNING) return;

    // Verify final tx structure
    assert(session.GetFinalTxVinSize() == session.GetFinalTxVoutSize());
    assert(session.GetFinalTxVinSize() > 0);

    // ── Phase 6: Sign inputs ────────────────────────────────────────
    // Collect all the inputs from submitted entries and sign them
    for (const auto& entry : submitted_entries) {
        for (const auto& txdsin : entry.vecTxDSIn) {
            CTxIn txin;
            txin.prevout = txdsin.prevout;
            txin.nSequence = txdsin.nSequence;

            // Generate a fuzzed scriptsig
            auto sig_bytes = fdp.ConsumeBytes<uint8_t>(fdp.ConsumeIntegralInRange<size_t>(1, 73));
            if (sig_bytes.empty()) sig_bytes.push_back(0x01);
            txin.scriptSig = CScript(sig_bytes.begin(), sig_bytes.end());

            (void)session.SimulateAddScriptSig(txin);
        }
    }

    // ── Phase 7: Final check ────────────────────────────────────────
    session.SimulateCheckPool();

    // State should still be valid
    const auto final_state = session.GetState();
    assert(final_state >= POOL_STATE_MIN && final_state <= POOL_STATE_MAX);
}

// ═══════════════════════════════════════════════════════════════════════
// Target 4: Entry scriptsig matching with multiple entries
//
// Builds a multi-entry session and then fuzzes the scriptsig matching
// logic that the server uses when processing DSSIGNFINALTX messages.
// Tests edge cases in prevout matching, duplicate detection, and the
// fHasSig flag management.
// ═══════════════════════════════════════════════════════════════════════
FUZZ_TARGET(coinjoin_multi_entry_scriptsig, .init = initialize_coinjoin_state_machine)
{
    FuzzedDataProvider fdp(buffer.data(), buffer.size());

    if (fdp.remaining_bytes() < 100) return;

    TestCoinJoinSession session;

    // Set up a session in SIGNING state with multiple entries
    const int denom = PickValidDenom(fdp);
    session.SimulateCreateNewSession(denom);

    const int num_entries = fdp.ConsumeIntegralInRange<int>(2, 5);
    for (int i = 0; i < num_entries; ++i) {
        session.vecSessionCollaterals.push_back(MakeTrivialCollateral(fdp));
    }

    session.SimulateCheckForCompleteQueue();
    if (session.GetState() != POOL_STATE_ACCEPTING_ENTRIES) return;

    // Add entries
    std::vector<std::pair<COutPoint, uint32_t>> all_inputs;
    for (int i = 0; i < num_entries; ++i) {
        if (fdp.remaining_bytes() < 50) break;

        const size_t num_inputs = fdp.ConsumeIntegralInRange<size_t>(1, 3);
        CCoinJoinEntry entry = MakeValidEntry(fdp, denom, num_inputs);

        for (const auto& dsin : entry.vecTxDSIn) {
            all_inputs.emplace_back(dsin.prevout, dsin.nSequence);
        }

        PoolMessage msg;
        (void)session.SimulateAddEntry(entry, msg);
    }

    if (session.GetEntryCount() < 2) return;

    // Create final transaction
    session.SimulateCreateFinalTransaction();
    assert(session.GetState() == POOL_STATE_SIGNING);

    // Now fuzz scriptsig submissions — mix valid inputs with random ones
    LIMITED_WHILE(fdp.remaining_bytes() > 0, 100)
    {
        CTxIn txin;

        if (fdp.ConsumeBool() && !all_inputs.empty()) {
            // Use a real input from the session
            const size_t idx = fdp.ConsumeIntegralInRange<size_t>(0, all_inputs.size() - 1);
            txin.prevout = all_inputs[idx].first;
            txin.nSequence = all_inputs[idx].second;
        } else {
            // Use a completely random input
            txin.prevout = MakeOutPoint(fdp);
            txin.nSequence = fdp.ConsumeIntegral<uint32_t>();
        }

        auto sig_bytes = fdp.ConsumeBytes<uint8_t>(fdp.ConsumeIntegralInRange<size_t>(0, 200));
        txin.scriptSig = CScript(sig_bytes.begin(), sig_bytes.end());

        (void)session.SimulateAddScriptSig(txin);
    }

    // Check pool after all scriptsigs — must not crash
    session.SimulateCheckPool();
}

// ═══════════════════════════════════════════════════════════════════════
// Target 5: IsValidStructure with structured generation
//
// Generates CCoinJoinBroadcastTx with incrementally corrupted fields
// to find edge cases in the structural validation. Starts from valid
// structures and mutates individual fields.
// ═══════════════════════════════════════════════════════════════════════
FUZZ_TARGET(coinjoin_broadcasttx_structure, .init = initialize_coinjoin_state_machine)
{
    FuzzedDataProvider fdp(buffer.data(), buffer.size());

    if (fdp.remaining_bytes() < 20) return;

    // Build a base valid broadcast tx
    CCoinJoinBroadcastTx dstx;
    CMutableTransaction mtx;

    const int num_participants = fdp.ConsumeIntegralInRange<int>(
        CoinJoin::GetMinPoolParticipants(),
        CoinJoin::GetMaxPoolParticipants());
    const int denom = PickValidDenom(fdp);
    const CAmount amount = CoinJoin::DenominationToAmount(denom);

    const size_t inputs_per = fdp.ConsumeIntegralInRange<size_t>(1, COINJOIN_ENTRY_MAX_SIZE);
    const size_t total_io = static_cast<size_t>(num_participants) * inputs_per;

    for (size_t i = 0; i < total_io; ++i) {
        if (fdp.remaining_bytes() < 30) break;
        mtx.vin.push_back(CTxIn(MakeOutPoint(fdp)));
        mtx.vout.push_back(CTxOut(amount, MakeP2PKHScript(fdp)));
    }

    dstx.tx = MakeTransactionRef(mtx);
    dstx.m_protxHash = uint256::ONE;
    dstx.masternodeOutpoint = MakeOutPoint(fdp);

    // The base should be valid (if we generated enough I/O)
    const bool base_valid = dstx.IsValidStructure();

    // Now mutate and test
    LIMITED_WHILE(fdp.remaining_bytes() > 0, 50)
    {
        CCoinJoinBroadcastTx mutated = dstx;
        CMutableTransaction mtx_copy(*dstx.tx);

        const auto mutation = fdp.ConsumeIntegralInRange<uint8_t>(0, 6);
        switch (mutation) {
        case 0:
            // Null both identifiers
            mutated.m_protxHash = uint256{};
            mutated.masternodeOutpoint.SetNull();
            assert(!mutated.IsValidStructure());
            break;
        case 1:
            // Add extra input (vin/vout mismatch)
            mtx_copy.vin.push_back(CTxIn(MakeOutPoint(fdp)));
            mutated.tx = MakeTransactionRef(mtx_copy);
            assert(!mutated.IsValidStructure());
            break;
        case 2:
            // Add extra output (vin/vout mismatch)
            mtx_copy.vout.push_back(CTxOut(amount, MakeP2PKHScript(fdp)));
            mutated.tx = MakeTransactionRef(mtx_copy);
            assert(!mutated.IsValidStructure());
            break;
        case 3:
            // Non-denominated amount in output
            if (!mtx_copy.vout.empty()) {
                mtx_copy.vout[0].nValue = 42;
                mutated.tx = MakeTransactionRef(mtx_copy);
                assert(!mutated.IsValidStructure());
            }
            break;
        case 4:
            // Non-P2PKH script in output
            if (!mtx_copy.vout.empty()) {
                mtx_copy.vout[0].scriptPubKey = CScript() << OP_RETURN << std::vector<unsigned char>{'x'};
                mutated.tx = MakeTransactionRef(mtx_copy);
                assert(!mutated.IsValidStructure());
            }
            break;
        case 5:
            // Clear all inputs (below minimum)
            mtx_copy.vin.clear();
            mtx_copy.vout.clear();
            mutated.tx = MakeTransactionRef(mtx_copy);
            assert(!mutated.IsValidStructure());
            break;
        case 6:
            // Exercise with random modifications
            if (!mtx_copy.vout.empty()) {
                const size_t idx = fdp.ConsumeIntegralInRange<size_t>(0, mtx_copy.vout.size() - 1);
                mtx_copy.vout[idx].nValue = fdp.ConsumeIntegral<CAmount>();
                mutated.tx = MakeTransactionRef(mtx_copy);
            }
            (void)mutated.IsValidStructure();
            break;
        }
    }

    // Always exercise with the base tx — must not crash
    (void)base_valid;
}
