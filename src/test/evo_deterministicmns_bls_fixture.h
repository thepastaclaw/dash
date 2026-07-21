// Copyright (c) 2026 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef DASH_TEST_EVO_DETERMINISTICMNS_BLS_FIXTURE_H
#define DASH_TEST_EVO_DETERMINISTICMNS_BLS_FIXTURE_H

// Included from evo_deterministicmns_tests.cpp after its transaction helpers.

struct BLSMigrationTest {
    struct MN {
        uint256 hash;
        CKey owner;
        CBLSSecretKey op;
    };
    TestChainSetup& setup;
    ChainstateManager& chainman;
    CDeterministicMNManager& dmnman;
    SimpleUTXOMap utxos{BuildSimpleUtxoMap(setup.m_coinbase_txns)};
    const CScript coinbase_pk{GetScriptForRawPubKey(setup.coinbaseKey.GetPubKey())};
    int port{19000};
    explicit BLSMigrationTest(TestChainSetup& setup) :
        setup(setup),
        chainman(*Assert(setup.m_node.chainman)),
        dmnman(*Assert(setup.m_node.dmnman))
    {
    }
    const CBlockIndex* Tip() const { return WITH_LOCK(::cs_main, return chainman.ActiveChain().Tip()); }
    bool V24Active() const { return DeploymentActiveAfter(Tip(), chainman, Consensus::DEPLOYMENT_V24); }
    bool V19Active() const { return DeploymentActiveAfter(Tip(), chainman.GetConsensus(), Consensus::DEPLOYMENT_V19); }
    void Block(std::vector<CMutableTransaction> txs = {})
    {
        setup.CreateAndProcessBlock(txs, coinbase_pk);
        dmnman.UpdatedBlockTip(Tip());
    }
    void MineV19()
    {
        while (!V19Active())
            Block();
    }
    void MineV24()
    {
        for (int i = 0; i < 2000 && !V24Active(); ++i)
            Block();
        BOOST_REQUIRE(V24Active());
    }
    CBLSSecretKey Key() const
    {
        CBLSSecretKey key;
        key.MakeNewKey();
        return key;
    }
    MN Reg(uint16_t version, const CBLSPublicKey* supplied = nullptr)
    {
        MN mn;
        auto tx = CreateProRegTx(chainman, utxos, port++, GenerateRandomAddress(), setup.coinbaseKey, mn.owner, mn.op,
                                 version, supplied);
        mn.hash = tx.GetHash();
        Block({tx});
        return mn;
    }
    CMutableTransaction ProReg(const CBLSPublicKey& op, uint16_t version)
    {
        CKey owner;
        CBLSSecretKey unused;
        return CreateProRegTx(chainman, utxos, port++, GenerateRandomAddress(), setup.coinbaseKey, owner, unused,
                              version, &op);
    }
    CMutableTransaction UpReg(const MN& mn, const CBLSPublicKey& op, uint16_t version, CAmount fee = 0)
    {
        return CreateProUpRegTx(chainman, utxos, mn.hash, mn.owner, op, mn.owner.GetPubKey().GetID(),
                                GenerateRandomAddress(), setup.coinbaseKey, version, fee);
    }
    CMutableTransaction UpServ(const MN& mn, uint16_t version)
    {
        return CreateProUpServTx(chainman, utxos, mn.hash, mn.op, port++, CScript(), setup.coinbaseKey, version);
    }
    void Check(const CMutableTransaction& tx, bool expected, const std::string& reason = {})
    {
        TxValidationState state;
        bool ok{false};
        LOCK(cs_main);
        if (tx.nType == TRANSACTION_PROVIDER_REGISTER)
            ok = CheckProRegTx(CTransaction(tx), Tip(), dmnman, chainman.ActiveChainstate().CoinsTip(), chainman, state,
                               true);
        else if (tx.nType == TRANSACTION_PROVIDER_UPDATE_REGISTRAR)
            ok = CheckProUpRegTx(CTransaction(tx), Tip(), dmnman, chainman.ActiveChainstate().CoinsTip(), chainman,
                                 state, true);
        else
            ok = CheckProUpServTx(CTransaction(tx), Tip(), dmnman, chainman, state, true);
        BOOST_REQUIRE_MESSAGE(ok == expected, "unexpected result: " << state.GetRejectReason());
        if (!reason.empty()) BOOST_CHECK_EQUAL(state.GetRejectReason(), reason);
    }
    CDeterministicMNList Reload(const CDeterministicMNList& live)
    {
        live.ForEachMN(false, [&](const CDeterministicMN& dmn) {
            BOOST_CHECK(dmn.pdmnState->pubKeyOperator == CBLSLazyPublicKey() ||
                        dmn.pdmnState->pubKeyOperator.IsLegacy() == (dmn.pdmnState->nVersion == ProTxVersion::LegacyBLS));
        });
        CDataStream ds(SER_DISK, CLIENT_VERSION);
        ds << live;
        CDeterministicMNList reloaded;
        ds >> reloaded;
        BOOST_CHECK(live.IsEqual(reloaded));
        return reloaded;
    }
    void State(const CDeterministicMNList& list, const MN& mn, uint16_t version, const CBLSPublicKey& key, bool banned)
    {
        const auto dmn = list.GetMN(mn.hash);
        BOOST_REQUIRE(dmn);
        BOOST_CHECK_EQUAL(dmn->pdmnState->nVersion, version);
        BOOST_CHECK_EQUAL(dmn->pdmnState->pubKeyOperator.IsLegacy(), version == ProTxVersion::LegacyBLS);
        BOOST_CHECK(dmn->pdmnState->pubKeyOperator.Get() == key);
        BOOST_CHECK_EQUAL(dmn->pdmnState->IsBanned(), banned);
    }
    bool Rebuild(const std::vector<CMutableTransaction>& txs, BlockValidationState& state, CDeterministicMNList& list)
    {
        CBlock block;
        block.vtx.push_back(MakeTransactionRef(CMutableTransaction{}));
        for (const auto& tx : txs)
            block.vtx.push_back(MakeTransactionRef(tx));
        bool ok{false};
        std::string thrown;
        {
            LOCK(cs_main);
            try {
                ok = Assert(setup.m_node.chain_helper)
                         ->special_tx->RebuildListFromBlock(block, Tip(), dmnman.GetListAtChainTip(),
                                                            chainman.ActiveChainstate().CoinsTip(), false, state, list);
            } catch (const std::exception& e) {
                thrown = e.what();
            }
        }
        BOOST_REQUIRE_MESSAGE(thrown.empty(), "RebuildListFromBlock threw: " << thrown);
        return ok;
    }
    void Mempool(const CMutableTransaction& tx, bool expected, const std::string& reason = {})
    {
        LOCK(cs_main);
        const auto result = chainman.ProcessTransaction(MakeTransactionRef(tx));
        BOOST_REQUIRE_EQUAL(result.m_result_type == MempoolAcceptResult::ResultType::VALID, expected);
        if (!reason.empty()) BOOST_CHECK_EQUAL(result.m_state.GetRejectReason(), reason);
    }
    bool TemplateHas(const uint256& hash)
    {
        auto& mempool = *Assert(setup.m_node.mempool);
        auto block = node::BlockAssembler{chainman.ActiveChainstate(), setup.m_node, &mempool}.CreateNewBlock(coinbase_pk);
        BOOST_REQUIRE(block);
        return std::any_of(block->block.vtx.begin(), block->block.vtx.end(),
                           [&](const auto& tx) { return tx->GetHash() == hash; });
    }
};

#endif // DASH_TEST_EVO_DETERMINISTICMNS_BLS_FIXTURE_H
