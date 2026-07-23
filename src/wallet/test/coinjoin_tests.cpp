// Copyright (c) 2020-2025 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/util/setup_common.h>

#include <coinjoin/client.h>
#include <coinjoin/coinjoin.h>
#include <coinjoin/options.h>
#include <coinjoin/util.h>
#include <coinjoin/walletman.h>
#include <consensus/amount.h>
#include <evo/deterministicmns.h>
#include <interfaces/coinjoin.h>
#include <masternode/sync.h>
#include <net.h>
#include <node/context.h>
#include <policy/settings.h>
#include <protocol.h>
#include <streams.h>
#include <util/system.h>
#include <util/translation.h>
#include <validation.h>
#include <wallet/context.h>
#include <wallet/spend.h>
#include <wallet/wallet.h>

#include <boost/test/unit_test.hpp>

#include <atomic>
#include <chrono>
#include <future>
#include <thread>

struct CoinJoinClientManagerTest {
    static void AddSession(CCoinJoinClientManager& clientman, CDeterministicMNCPtr dmn, int session_id)
    {
        LOCK(clientman.cs_deqsessions);
        auto& session{clientman.deqSessions.emplace_back(clientman.m_wallet, clientman, clientman.m_dmnman,
                                                         clientman.m_mn_metaman, clientman.m_mn_sync, clientman.m_isman)};
        session.mixingMasternode = std::move(dmn);
        session.nSessionID = session_id;
    }
};

namespace wallet {
BOOST_FIXTURE_TEST_SUITE(coinjoin_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(coinjoin_options_tests)
{
    gArgs.ForceSetArg("-enablecoinjoin", "0");
    const auto loader{interfaces::MakeCoinJoinLoader(m_node)};

    BOOST_CHECK_EQUAL(CCoinJoinClientOptions::GetSessions(), DEFAULT_COINJOIN_SESSIONS);
    BOOST_CHECK_EQUAL(CCoinJoinClientOptions::GetRounds(), DEFAULT_COINJOIN_ROUNDS);
    BOOST_CHECK_EQUAL(CCoinJoinClientOptions::GetRandomRounds(), COINJOIN_RANDOM_ROUNDS);
    BOOST_CHECK_EQUAL(CCoinJoinClientOptions::GetAmount(), DEFAULT_COINJOIN_AMOUNT);
    BOOST_CHECK_EQUAL(CCoinJoinClientOptions::GetDenomsGoal(), DEFAULT_COINJOIN_DENOMS_GOAL);
    BOOST_CHECK_EQUAL(CCoinJoinClientOptions::GetDenomsHardCap(), DEFAULT_COINJOIN_DENOMS_HARDCAP);

    BOOST_CHECK_EQUAL(CCoinJoinClientOptions::IsEnabled(), false);
    BOOST_CHECK_EQUAL(CCoinJoinClientOptions::IsMultiSessionEnabled(), DEFAULT_COINJOIN_MULTISESSION);

    CCoinJoinClientOptions::SetEnabled(true);
    BOOST_CHECK_EQUAL(CCoinJoinClientOptions::IsEnabled(), true);
    CCoinJoinClientOptions::SetEnabled(false);
    BOOST_CHECK_EQUAL(CCoinJoinClientOptions::IsEnabled(), false);

    CCoinJoinClientOptions::SetMultiSessionEnabled(!DEFAULT_COINJOIN_MULTISESSION);
    BOOST_CHECK_EQUAL(CCoinJoinClientOptions::IsMultiSessionEnabled(), !DEFAULT_COINJOIN_MULTISESSION);
    CCoinJoinClientOptions::SetMultiSessionEnabled(DEFAULT_COINJOIN_MULTISESSION);
    BOOST_CHECK_EQUAL(CCoinJoinClientOptions::IsMultiSessionEnabled(), DEFAULT_COINJOIN_MULTISESSION);

    CCoinJoinClientOptions::SetRounds(DEFAULT_COINJOIN_ROUNDS + 10);
    BOOST_CHECK_EQUAL(CCoinJoinClientOptions::GetRounds(), DEFAULT_COINJOIN_ROUNDS + 10);
    CCoinJoinClientOptions::SetAmount(DEFAULT_COINJOIN_AMOUNT + 50);
    BOOST_CHECK_EQUAL(CCoinJoinClientOptions::GetAmount(), DEFAULT_COINJOIN_AMOUNT + 50);
}

BOOST_AUTO_TEST_CASE(coinjoin_collateral_tests)
{
    // Good collateral values
    static_assert(CoinJoin::IsCollateralAmount(0.00010000 * COIN));
    static_assert(CoinJoin::IsCollateralAmount(0.00012345 * COIN));
    static_assert(CoinJoin::IsCollateralAmount(0.00032123 * COIN));
    static_assert(CoinJoin::IsCollateralAmount(0.00019000 * COIN));

    // Bad collateral values
    static_assert(!CoinJoin::IsCollateralAmount(0.00009999 * COIN));
    static_assert(!CoinJoin::IsCollateralAmount(0.00040001 * COIN));
    static_assert(!CoinJoin::IsCollateralAmount(0.00100000 * COIN));
    static_assert(!CoinJoin::IsCollateralAmount(0.00100001 * COIN));
}

BOOST_AUTO_TEST_CASE(coinjoin_pending_dsa_request_tests)
{
    CPendingDsaRequest dsa_request;
    BOOST_CHECK(dsa_request.GetProTxHash() == uint256());
    BOOST_CHECK(dsa_request.GetDSA() == CCoinJoinAccept());
    BOOST_CHECK_EQUAL(dsa_request.IsExpired(), true);
    CPendingDsaRequest dsa_request_2;
    BOOST_CHECK(dsa_request == dsa_request_2);
    CCoinJoinAccept cja;
    cja.nDenom = 4;
    uint256 proTxHash{uint256::ONE};
    CPendingDsaRequest custom_request(proTxHash, cja);
    BOOST_CHECK(custom_request.GetProTxHash() == proTxHash);
    BOOST_CHECK(custom_request.GetDSA() == cja);
    BOOST_CHECK_EQUAL(custom_request.IsExpired(), false);
    SetMockTime(GetTime() + 15);
    BOOST_CHECK_EQUAL(custom_request.IsExpired(), false);
    SetMockTime(GetTime() + 1);
    BOOST_CHECK_EQUAL(custom_request.IsExpired(), true);

    BOOST_CHECK(dsa_request != custom_request);
    BOOST_CHECK(!(dsa_request == custom_request));
    BOOST_CHECK(!dsa_request);
    BOOST_CHECK(custom_request);
}

BOOST_AUTO_TEST_CASE(coinjoin_dstxin_tests)
{
    CTxDSIn txin;
    BOOST_CHECK(txin.prevPubKey == CScript());
    BOOST_CHECK_EQUAL(txin.fHasSig, false);
    BOOST_CHECK_EQUAL(txin.nRounds, -10);
    CTxDSIn custom_txin(txin, CScript(4), -9);
    BOOST_CHECK(custom_txin.prevPubKey == CScript(4));
    BOOST_CHECK_EQUAL(custom_txin.fHasSig, false);
    BOOST_CHECK_EQUAL(custom_txin.nRounds, -9);
}

BOOST_AUTO_TEST_CASE(coinjoin_status_update_tests)
{
    CCoinJoinStatusUpdate cjsu;
    BOOST_CHECK_EQUAL(cjsu.nSessionID, 0);
    BOOST_CHECK_EQUAL(cjsu.nState, POOL_STATE_IDLE);
    BOOST_CHECK_EQUAL(cjsu.nEntriesCount, 0);
    BOOST_CHECK_EQUAL(cjsu.nStatusUpdate, STATUS_ACCEPTED);
    BOOST_CHECK_EQUAL(cjsu.nMessageID, MSG_NOERR);
    CCoinJoinStatusUpdate custom_cjsu(1, POOL_STATE_QUEUE, 1, STATUS_REJECTED, ERR_QUEUE_FULL);
    BOOST_CHECK_EQUAL(custom_cjsu.nSessionID, 1);
    BOOST_CHECK_EQUAL(custom_cjsu.nState, POOL_STATE_QUEUE);
    BOOST_CHECK_EQUAL(custom_cjsu.nEntriesCount, 1);
    BOOST_CHECK_EQUAL(custom_cjsu.nStatusUpdate, STATUS_REJECTED);
    BOOST_CHECK_EQUAL(custom_cjsu.nMessageID, ERR_QUEUE_FULL);
}

BOOST_AUTO_TEST_CASE(coinjoin_accept_tests)
{
    CCoinJoinAccept cja;
    BOOST_CHECK_EQUAL(cja.nDenom, 0);
    BOOST_CHECK_EQUAL(cja.txCollateral.GetHash(), CMutableTransaction().GetHash());
    // CMutableTransaction custom_cmt()
}

class CTransactionBuilderTestSetup : public TestChain100Setup
{
public:
    CTransactionBuilderTestSetup() :
        wallet{std::make_unique<CWallet>(m_node.chain.get(), m_node.coinjoin_loader.get(), "", m_args, CreateMockWalletDatabase())}
    {
        context.args = &m_args;
        context.chain = m_node.chain.get();
        context.coinjoin_loader = m_node.coinjoin_loader.get();
        CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));
        wallet->SetupLegacyScriptPubKeyMan();
        wallet->LoadWallet();
        AddWallet(context, wallet);
        {
            LOCK2(wallet->cs_wallet, ::cs_main);
            wallet->GetLegacyScriptPubKeyMan()->AddKeyPubKey(coinbaseKey, coinbaseKey.GetPubKey());
            wallet->SetLastBlockProcessed(m_node.chainman->ActiveChain().Height(), m_node.chainman->ActiveChain().Tip()->GetBlockHash());
        }
        WalletRescanReserver reserver(*wallet);
        reserver.reserve();
        CWallet::ScanResult result = wallet->ScanForWalletTransactions(/*start_block=*/wallet->chain().getBlockHash(0),
                                                                       /*start_height=*/0, /*max_height=*/{}, reserver,
                                                                       /*fUpdate=*/true, /*save_progress=*/false);
        BOOST_CHECK_EQUAL(result.status, CWallet::ScanResult::SUCCESS);
    }

    ~CTransactionBuilderTestSetup()
    {
        RemoveWallet(context, wallet, /*load_on_start=*/std::nullopt);
    }

    WalletContext context;
    const std::shared_ptr<CWallet> wallet;

    CWalletTx& AddTxToChain(uint256 nTxHash)
    {
        decltype(wallet->mapWallet)::iterator it;
        CMutableTransaction blocktx;
        {
            LOCK(wallet->cs_wallet);
            it = wallet->mapWallet.find(nTxHash);
            BOOST_REQUIRE(it != wallet->mapWallet.end());
            blocktx = CMutableTransaction(*it->second.tx);
        }
        CreateAndProcessBlock({blocktx}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));
        LOCK2(wallet->cs_wallet, ::cs_main);
        wallet->SetLastBlockProcessed(m_node.chainman->ActiveChain().Height(), m_node.chainman->ActiveChain().Tip()->GetBlockHash());
        it->second.m_state = TxStateConfirmed{m_node.chainman->ActiveChain().Tip()->GetBlockHash(), m_node.chainman->ActiveChain().Height(), /*index=*/1};
        return it->second;
    }
    CompactTallyItem GetTallyItem(const std::vector<CAmount>& vecAmounts)
    {
        CompactTallyItem tallyItem;
        ReserveDestination reserveDest(wallet.get());
        int nChangePosRet{RANDOM_CHANGE_POSITION};
        CCoinControl coinControl;
        coinControl.m_feerate = CFeeRate(1000);
        {
            LOCK(wallet->cs_wallet);
            auto dest_opt = reserveDest.GetReservedDestination(false);
            BOOST_REQUIRE(dest_opt);
            tallyItem.txdest = *dest_opt;
        }
        for (CAmount nAmount : vecAmounts) {
            CTransactionRef tx;
            {
                auto res = CreateTransaction(*wallet, {{GetScriptForDestination(tallyItem.txdest), nAmount, false}}, nChangePosRet, coinControl);
                BOOST_REQUIRE(res);
                tx = res->tx;
                nChangePosRet = res->change_pos;
            }
            {
                LOCK2(wallet->cs_wallet, ::cs_main);
                wallet->CommitTransaction(tx, {}, {});
            }
            AddTxToChain(tx->GetHash());
            for (uint32_t n = 0; n < tx->vout.size(); ++n) {
                if (nChangePosRet != RANDOM_CHANGE_POSITION && int(n) == nChangePosRet) {
                    // Skip the change output to only return the requested coins
                    continue;
                }
                tallyItem.outpoints.emplace_back(COutPoint{tx->GetHash(), n});
                tallyItem.nAmount += tx->vout[n].nValue;
            }
        }
        BOOST_REQUIRE_EQUAL(tallyItem.outpoints.size(), vecAmounts.size());
        reserveDest.KeepDestination();
        return tallyItem;
    }
};

BOOST_FIXTURE_TEST_CASE(coinjoin_manager_start_stop_tests, CTransactionBuilderTestSetup)
{
    BOOST_CHECK(m_node.cj_walletman->doForClient("", [](auto& cj_man) {
        BOOST_CHECK_EQUAL(cj_man.isMixing(), false);
        BOOST_CHECK_EQUAL(cj_man.startMixing(), true);
        BOOST_CHECK_EQUAL(cj_man.isMixing(), true);
        BOOST_CHECK_EQUAL(cj_man.startMixing(), false);
        cj_man.stopMixing();
        BOOST_CHECK_EQUAL(cj_man.isMixing(), false);
    }));
}

BOOST_FIXTURE_TEST_CASE(coinjoin_completion_waits_for_wallet_callbacks, CTransactionBuilderTestSetup)
{
    struct ProcessingResult {
        bool queue_blocked{false};
        bool processing_started{false};
        bool completed_before_unblock{false};
        bool completed_after_unblock{false};
        bool callback_processed_before_unblock{false};
        bool callback_processed_after_unblock{false};
        std::exception_ptr error;
    };

    auto process_completion = [&](CNode& peer, int session_id) {
        ProcessingResult result;
        std::promise<void> unblock_queue;
        const std::shared_future<void> unblock_future{unblock_queue.get_future()};
        auto queue_blocked{std::make_shared<std::promise<void>>()};
        auto queue_blocked_future{queue_blocked->get_future()};
        CallFunctionInValidationInterfaceQueue([queue_blocked, unblock_future] {
            queue_blocked->set_value();
            unblock_future.wait();
        });
        result.queue_blocked = queue_blocked_future.wait_for(std::chrono::seconds{5}) == std::future_status::ready;
        if (!result.queue_blocked) {
            unblock_queue.set_value();
            return result;
        }

        std::atomic<bool> preceding_callback_processed{false};
        CallFunctionInValidationInterfaceQueue([&preceding_callback_processed] { preceding_callback_processed = true; });

        std::promise<void> processing_started;
        auto processing_started_future{processing_started.get_future()};
        std::promise<void> processing_done;
        auto processing_done_future{processing_done.get_future()};
        std::thread processing_thread{[&] {
            processing_started.set_value();
            try {
                CDataStream stream{SER_NETWORK, PROTOCOL_VERSION};
                stream << session_id << MSG_SUCCESS;
                m_node.cj_walletman->processMessage(peer, m_node.chainman->ActiveChainstate(), *m_node.connman,
                                                    *m_node.mempool, NetMsgType::DSCOMPLETE, stream);
            } catch (...) {
                result.error = std::current_exception();
            }
            processing_done.set_value();
        }};
        struct Cleanup {
            std::promise<void>& unblock_queue;
            std::thread& processing_thread;
            bool unblocked{false};

            void Unblock()
            {
                if (unblocked) return;
                unblock_queue.set_value();
                unblocked = true;
            }
            ~Cleanup()
            {
                Unblock();
                if (processing_thread.joinable()) processing_thread.join();
            }
        } cleanup{unblock_queue, processing_thread};

        result.processing_started = processing_started_future.wait_for(std::chrono::seconds{5}) ==
                                    std::future_status::ready;
        if (result.processing_started) {
            result.completed_before_unblock = processing_done_future.wait_for(std::chrono::milliseconds{100}) ==
                                              std::future_status::ready;
        }
        result.callback_processed_before_unblock = preceding_callback_processed;
        cleanup.Unblock();
        result.completed_after_unblock = processing_done_future.wait_for(std::chrono::seconds{5}) ==
                                         std::future_status::ready;
        if (processing_thread.joinable()) processing_thread.join();
        SyncWithValidationInterfaceQueue();
        result.callback_processed_after_unblock = preceding_callback_processed;
        return result;
    };

    auto check_processing_error = [](const std::exception_ptr& error) {
        if (!error) return;
        try {
            std::rethrow_exception(error);
        } catch (const std::exception& e) {
            BOOST_ERROR(e.what());
        } catch (...) {
            BOOST_ERROR("Unknown DSCOMPLETE processing exception");
        }
    };

    struct OptionsCleanup {
        const bool enabled{CCoinJoinClientOptions::IsEnabled()};
        ~OptionsCleanup() { CCoinJoinClientOptions::SetEnabled(enabled); }
    } options_cleanup;
    CCoinJoinClientOptions::SetEnabled(true);
    struct MasternodeSyncCleanup {
        CMasternodeSync& sync;
        const bool was_synced{sync.IsBlockchainSynced()};
        ~MasternodeSyncCleanup()
        {
            if (!was_synced) sync.Reset(/*fForce=*/true, /*fNotifyReset=*/false);
        }
    } masternode_sync_cleanup{*m_node.mn_sync};
    if (!m_node.mn_sync->IsBlockchainSynced()) m_node.mn_sync->SwitchToNextAsset();

    auto make_peer = [](uint32_t address) {
        in_addr peer_in_addr{};
        peer_in_addr.s_addr = htonl(address);
        auto peer{std::make_unique<CNode>(/*id=*/0,
                                          /*sock=*/nullptr,
                                          /*addrIn=*/CAddress{CService{peer_in_addr, 8333}, NODE_NETWORK},
                                          /*nKeyedNetGroupIn=*/0,
                                          /*nLocalHostNonceIn=*/0,
                                          /*addrBindIn=*/CAddress{},
                                          /*addrNameIn=*/std::string{},
                                          /*conn_type_in=*/ConnectionType::INBOUND,
                                          /*inbound_onion=*/false)};
        peer->nVersion = PROTOCOL_VERSION;
        peer->SetCommonVersion(PROTOCOL_VERSION);
        return peer;
    };

    constexpr int session_id{1};
    auto dmn_state{std::make_shared<CDeterministicMNState>()};
    dmn_state->netInfo = NetInfoInterface::MakeNetInfo(
        ProTxVersion::GetMax(/*is_basic_scheme_active=*/true, /*is_extended_addr=*/false));
    BOOST_REQUIRE_EQUAL(dmn_state->netInfo->AddEntry(NetInfoPurpose::CORE_P2P, "127.0.0.1:8333"), NetInfoStatus::Success);
    auto dmn{std::make_shared<CDeterministicMN>(/*internalId=*/0)};
    dmn->pdmnState = dmn_state;
    BOOST_REQUIRE(m_node.cj_walletman->doForClient("", [&](auto& clientman) {
        CoinJoinClientManagerTest::AddSession(clientman, dmn, session_id);
    }));

    auto expected_peer{make_peer(0x7f000001)};
    auto unrelated_peer{make_peer(0x7f000002)};
    unrelated_peer->m_masternode_connection = true;

    const auto unrelated_result{process_completion(*unrelated_peer, session_id)};
    BOOST_CHECK(unrelated_result.queue_blocked);
    BOOST_CHECK(unrelated_result.processing_started);
    BOOST_CHECK(unrelated_result.completed_before_unblock);
    BOOST_CHECK(!unrelated_result.callback_processed_before_unblock);
    BOOST_CHECK(unrelated_result.completed_after_unblock);
    BOOST_CHECK(unrelated_result.callback_processed_after_unblock);
    check_processing_error(unrelated_result.error);

    const auto wrong_session_result{process_completion(*expected_peer, session_id + 1)};
    BOOST_CHECK(wrong_session_result.queue_blocked);
    BOOST_CHECK(wrong_session_result.processing_started);
    BOOST_CHECK(wrong_session_result.completed_before_unblock);
    BOOST_CHECK(!wrong_session_result.callback_processed_before_unblock);
    BOOST_CHECK(wrong_session_result.completed_after_unblock);
    BOOST_CHECK(wrong_session_result.callback_processed_after_unblock);
    check_processing_error(wrong_session_result.error);

    const auto completion_result{process_completion(*expected_peer, session_id)};
    BOOST_CHECK(completion_result.queue_blocked);
    BOOST_CHECK(completion_result.processing_started);
    BOOST_CHECK(!completion_result.completed_before_unblock);
    BOOST_CHECK(!completion_result.callback_processed_before_unblock);
    BOOST_CHECK(completion_result.completed_after_unblock);
    BOOST_CHECK(completion_result.callback_processed_after_unblock);
    check_processing_error(completion_result.error);
}

// End-to-end check that NewKeyPool() stops mixing
BOOST_FIXTURE_TEST_CASE(coinjoin_newkeypool_stops_mixing_tests, CTransactionBuilderTestSetup)
{
    BOOST_CHECK(m_node.cj_walletman->doForClient("", [](auto& cj_man) {
        BOOST_REQUIRE(cj_man.startMixing());
        BOOST_CHECK_EQUAL(cj_man.isMixing(), true);
    }));
    {
        LOCK(wallet->cs_wallet);
        BOOST_REQUIRE(wallet->GetLegacyScriptPubKeyMan()->NewKeyPool());
    }
    BOOST_CHECK(m_node.cj_walletman->doForClient("", [](auto& cj_man) {
        BOOST_CHECK_EQUAL(cj_man.isMixing(), false);
    }));
}

BOOST_FIXTURE_TEST_CASE(CTransactionBuilderTest, CTransactionBuilderTestSetup)
{
    // NOTE: Mock wallet version is FEATURE_BASE which means that it uses uncompressed pubkeys
    // (65 bytes instead of 33 bytes) and we use Low R signatures, so CTxIn size is 179 bytes.
    // Each output is 34 bytes, vin and vout compact sizes are 1 byte each.
    // Therefore base size (i.e. for a tx with 1 input, 0 outputs) is expected to be
    // 4(n32bitVersion) + 1(vin size) + 179(vin[0]) + 1(vout size) + 4(nLockTime) = 189 bytes.

    minRelayTxFee = CFeeRate(DEFAULT_MIN_RELAY_TX_FEE);
    // Tests with single outpoint tallyItem
    {
        CompactTallyItem tallyItem = GetTallyItem({4999});
        CTransactionBuilder txBuilder(*wallet, tallyItem);

        BOOST_CHECK_EQUAL(txBuilder.CountOutputs(), 0);
        BOOST_CHECK_EQUAL(txBuilder.GetAmountInitial(), tallyItem.nAmount);
        BOOST_CHECK_EQUAL(txBuilder.GetAmountLeft(), 4810);         // 4999 - 189

        BOOST_CHECK(txBuilder.CouldAddOutput(4776));                // 4810 - 34
        BOOST_CHECK(!txBuilder.CouldAddOutput(4777));

        BOOST_CHECK(txBuilder.CouldAddOutput(0));
        BOOST_CHECK(!txBuilder.CouldAddOutput(-1));

        BOOST_CHECK(txBuilder.CouldAddOutputs({1000, 1000, 2708})); // (4810 - 34 * 3) split in 3 outputs
        BOOST_CHECK(!txBuilder.CouldAddOutputs({1000, 1000, 2709}));

        BOOST_CHECK_EQUAL(txBuilder.AddOutput(4999), nullptr);
        BOOST_CHECK_EQUAL(txBuilder.AddOutput(-1), nullptr);

        CTransactionBuilderOutput* output = txBuilder.AddOutput();
        BOOST_CHECK(output->UpdateAmount(txBuilder.GetAmountLeft()));
        BOOST_CHECK(output->UpdateAmount(1));
        BOOST_CHECK(output->UpdateAmount(output->GetAmount() + txBuilder.GetAmountLeft()));
        BOOST_CHECK(!output->UpdateAmount(output->GetAmount() + 1));
        BOOST_CHECK(!output->UpdateAmount(0));
        BOOST_CHECK(!output->UpdateAmount(-1));
        BOOST_CHECK_EQUAL(txBuilder.CountOutputs(), 1);

        bilingual_str strResult;
        BOOST_REQUIRE(txBuilder.Commit(strResult));
        CWalletTx& wtx = AddTxToChain(uint256S(strResult.original));
        BOOST_CHECK_EQUAL(wtx.tx->vout.size(), txBuilder.CountOutputs()); // should have no change output
        BOOST_CHECK_EQUAL(wtx.tx->vout[0].nValue, output->GetAmount());
        BOOST_CHECK(wtx.tx->vout[0].scriptPubKey == output->GetScript());
    }
    // Tests with multiple outpoint tallyItem
    {
        CompactTallyItem tallyItem = GetTallyItem({10000, 20000, 30000, 40000, 50000});
        CTransactionBuilder txBuilder(*wallet, tallyItem);
        std::vector<CTransactionBuilderOutput*> vecOutputs;
        bilingual_str strResult;

        auto output = txBuilder.AddOutput(100);
        BOOST_CHECK(output != nullptr);
        BOOST_CHECK(!txBuilder.Commit(strResult));

        if (output != nullptr) {
            output->UpdateAmount(1000);
            vecOutputs.push_back(output);
        }
        while (vecOutputs.size() < 100) {
            output = txBuilder.AddOutput(1000 + vecOutputs.size());
            if (output == nullptr) {
                break;
            }
            vecOutputs.push_back(output);
        }
        BOOST_CHECK_EQUAL(vecOutputs.size(), 100);
        BOOST_CHECK_EQUAL(txBuilder.CountOutputs(), vecOutputs.size());
        BOOST_REQUIRE(txBuilder.Commit(strResult));
        CWalletTx& wtx = AddTxToChain(uint256S(strResult.original));
        BOOST_CHECK_EQUAL(wtx.tx->vout.size(), txBuilder.CountOutputs() + 1); // should have change output
        for (const auto& out : wtx.tx->vout) {
            auto it = std::find_if(vecOutputs.begin(), vecOutputs.end(), [&](CTransactionBuilderOutput* output) -> bool {
                return output->GetAmount() == out.nValue && output->GetScript() == out.scriptPubKey;
            });
            if (it != vecOutputs.end()) {
                vecOutputs.erase(it);
            } else {
                // change output
                BOOST_CHECK_EQUAL(txBuilder.GetAmountLeft() - 34, out.nValue);
            }
        }
        BOOST_CHECK(vecOutputs.size() == 0);
    }
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
