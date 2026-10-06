#!/usr/bin/env python3
# Copyright (c) 2023 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.messages import (
    CInv,
    MSG_DSTX,
    MSG_TX,
    msg_inv,
    msg_notfound,
    msg_tx,
)
from test_framework.p2p import (
    GETDATA_TX_INTERVAL,
    NONPREF_PEER_TX_DELAY,
    OVERLOADED_PEER_OBJECT_DELAY,
    p2p_lock,
    P2PTxInvStore,
)
from test_framework.util import (
    assert_equal,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.wallet import (
    MiniWallet,
    MiniWalletMode,
)

# Time to bump forward (using bump_mocktime) before waiting for the node to send getdata(tx) in
# response to an inv(tx), in seconds. This delay includes all possible delays + 1, so it should only
# be used when the value of the delay is not interesting. If we want to test that the node waits x
# seconds for one peer and y seconds for another, use specific values instead.
TXREQUEST_TIME_SKIP = NONPREF_PEER_TX_DELAY + OVERLOADED_PEER_OBJECT_DELAY + 1

def cleanup(func):
    # Time to fastfoward (using bump_mocktime) in between subtests to ensure they do not interfere
    # with one another, in seconds. Equal to 12 hours, which is enough to expire anything that may
    # exist (though nothing should since state should be cleared) in p2p data structures.
    LONG_TIME_SKIP = 12 * 60 * 60

    def wrapper(self):
        try:
            func(self)
        finally:
            # Clear mempool
            self.generate(self.nodes[0], 1)
            self.nodes[0].disconnect_p2ps()
            # update_schedulers=False because the mockscheduler RPC refuses jumps larger than an
            # hour; like upstream's node.bumpmocktime() this only needs to move the node's clock.
            self.bump_mocktime(LONG_TIME_SKIP, update_schedulers=False)
    return wrapper

class PeerTxRelayer(P2PTxInvStore):
    """A P2PTxInvStore that also remembers all of the getdata and tx messages it receives."""
    def __init__(self):
        super().__init__()
        self._tx_received = []
        self._getdata_received = []

    @property
    def tx_received(self):
        with p2p_lock:
            return self._tx_received

    @property
    def getdata_received(self):
        with p2p_lock:
            return self._getdata_received

    def on_tx(self, message):
        self._tx_received.append(message)

    def on_getdata(self, message):
        self._getdata_received.append(message)

    def wait_for_parent_requests(self, txids):
        """Wait for requests for missing parents by txid as MSG_DSTX. Requires that the getdata
        message match these txids exactly; all txids must be requested and no additional requests
        are allowed."""
        def test_function():
            last_getdata = self.last_message.get('getdata')
            if not last_getdata:
                return False
            return len(last_getdata.inv) == len(txids) and all([item.type == MSG_DSTX and item.hash in txids for item in last_getdata.inv])
        self.wait_until(test_function, timeout=10)

    def assert_never_requested(self, txhash):
        """Check that the node has never sent us a getdata for this hash (int type)"""
        for getdata in self.getdata_received:
            for request in getdata.inv:
                assert request.hash != txhash

class OrphanHandlingTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        # Dash enables -txindex by default, which would make AlreadyHave() return true for any
        # parent that is already in a block (the node can serve it from the index), so confirmed
        # parents would never be requested. Turn it off to exercise the orphan parent fetching
        # logic the same way upstream does.
        self.extra_args = [["-txindex=0"]]

    def create_parent_and_child(self):
        """Create package with 1 parent and 1 child, normal fees (no cpfp)."""
        parent = self.wallet.create_self_transfer()
        child = self.wallet.create_self_transfer(utxo_to_spend=parent['new_utxo'])
        return child["txid"], child["tx"], parent["tx"]

    def relay_transaction(self, peer, tx):
        """Relay transaction using MSG_TX"""
        txid = int(tx.rehash(), 16)
        peer.send_and_ping(msg_inv([CInv(t=MSG_TX, h=txid)]))
        self.bump_mocktime(TXREQUEST_TIME_SKIP)
        peer.wait_for_getdata([txid])
        peer.send_and_ping(msg_tx(tx))

    @cleanup
    def test_orphan_rejected_parents(self):
        node = self.nodes[0]
        peer1 = node.add_p2p_connection(PeerTxRelayer())
        peer2 = node.add_p2p_connection(PeerTxRelayer())

        self.log.info("Test orphan handling when a parent is known to be invalid")
        parent_low_fee = self.wallet_p2pk.create_self_transfer(fee_rate=0)
        parent_other = self.wallet_p2pk.create_self_transfer()
        child = self.wallet_p2pk.create_self_transfer_multi(
            utxos_to_spend=[parent_other["new_utxo"], parent_low_fee["new_utxo"]])

        # Relay the parent. It should be rejected because it pays 0 fees.
        self.relay_transaction(peer1, parent_low_fee["tx"])
        assert parent_low_fee["txid"] not in node.getrawmempool()

        # Relay the child. It should not be accepted because it has missing inputs.
        # Its parent should not be requested because its txid has been added to the rejection filter.
        with node.assert_debug_log(['not keeping orphan with rejected parents {}'.format(child["txid"])]):
            self.relay_transaction(peer2, child["tx"])
        assert child["txid"] not in node.getrawmempool()

        # No parents are requested.
        self.bump_mocktime(GETDATA_TX_INTERVAL)
        peer1.assert_never_requested(int(parent_other["txid"], 16))
        peer2.assert_never_requested(int(parent_other["txid"], 16))
        peer2.assert_never_requested(int(parent_low_fee["txid"], 16))

    @cleanup
    def test_orphan_multiple_parents(self):
        node = self.nodes[0]
        peer = node.add_p2p_connection(PeerTxRelayer())

        self.log.info("Test orphan parent requests with a mixture of confirmed, in-mempool and missing parents")
        # This UTXO confirmed a long time ago.
        utxo_conf_old = self.wallet.send_self_transfer(from_node=node)["new_utxo"]
        txid_conf_old = utxo_conf_old["txid"]
        self.generate(self.wallet, 10)

        # Create a fake reorg to trigger BlockDisconnected, which resets the rolling bloom filter.
        # The alternative is to mine thousands of transactions to push it out of the filter.
        last_block = node.getbestblockhash()
        node.invalidateblock(last_block)
        node.preciousblock(last_block)
        node.syncwithvalidationinterfacequeue()

        # This UTXO confirmed recently.
        utxo_conf_recent = self.wallet.send_self_transfer(from_node=node)["new_utxo"]
        self.generate(node, 1)

        # This UTXO is unconfirmed and in the mempool.
        assert_equal(len(node.getrawmempool()), 0)
        mempool_tx = self.wallet.send_self_transfer(from_node=node)
        utxo_unconf_mempool = mempool_tx["new_utxo"]

        # This UTXO is unconfirmed and missing.
        missing_tx = self.wallet.create_self_transfer()
        utxo_unconf_missing = missing_tx["new_utxo"]
        assert missing_tx["txid"] not in node.getrawmempool()

        orphan = self.wallet.create_self_transfer_multi(utxos_to_spend=[utxo_conf_old,
            utxo_conf_recent, utxo_unconf_mempool, utxo_unconf_missing])

        self.relay_transaction(peer, orphan["tx"])
        self.bump_mocktime(NONPREF_PEER_TX_DELAY)
        peer.sync_with_ping()
        assert_equal(len(peer.last_message["getdata"].inv), 2)
        peer.wait_for_parent_requests([int(txid_conf_old, 16), int(missing_tx["txid"], 16)])

        # Even though the peer would send a notfound for the "old" confirmed transaction, the node
        # doesn't give up on the orphan. Once all of the missing parents are received, it should be
        # submitted to mempool.
        peer.send_message(msg_notfound(vec=[CInv(MSG_DSTX, int(txid_conf_old, 16))]))
        peer.send_and_ping(msg_tx(missing_tx["tx"]))
        peer.sync_with_ping()
        assert_equal(node.getmempoolentry(orphan["txid"])["ancestorcount"], 3)

    @cleanup
    def test_orphans_overlapping_parents(self):
        node = self.nodes[0]
        # In the process of relaying inflight_parent_AB
        peer_txrequest = node.add_p2p_connection(PeerTxRelayer())
        # Sends the orphans
        peer_orphans = node.add_p2p_connection(PeerTxRelayer())

        confirmed_utxos = [self.wallet_p2pk.get_utxo() for _ in range(4)]
        assert all([utxo["confirmations"] > 0 for utxo in confirmed_utxos])
        self.log.info("Test handling of multiple orphans with missing parents that are already being requested")
        # Parent of child_A only
        missing_parent_A = self.wallet_p2pk.create_self_transfer(utxo_to_spend=confirmed_utxos[0])
        # Parents of child_A and child_B
        missing_parent_AB = self.wallet_p2pk.create_self_transfer(utxo_to_spend=confirmed_utxos[1])
        inflight_parent_AB = self.wallet_p2pk.create_self_transfer(utxo_to_spend=confirmed_utxos[2])
        # Parent of child_B only
        missing_parent_B = self.wallet_p2pk.create_self_transfer(utxo_to_spend=confirmed_utxos[3])
        child_A = self.wallet_p2pk.create_self_transfer_multi(
            utxos_to_spend=[missing_parent_A["new_utxo"], missing_parent_AB["new_utxo"], inflight_parent_AB["new_utxo"]]
        )
        child_B = self.wallet_p2pk.create_self_transfer_multi(
            utxos_to_spend=[missing_parent_B["new_utxo"], missing_parent_AB["new_utxo"], inflight_parent_AB["new_utxo"]]
        )

        # The in-flight announcement needs to be a MSG_DSTX one for the node to recognize that the
        # missing input and the in-flight request for inflight_parent_AB are the same request: the
        # request tracker keys announcements on the full inv, and orphan parents are always fetched
        # as MSG_DSTX so that a parent which turns out to be a mixing tx keeps its DSTX metadata.
        peer_txrequest.send_and_ping(msg_inv([CInv(t=MSG_DSTX, h=int(inflight_parent_AB["txid"], 16))]))
        self.bump_mocktime(NONPREF_PEER_TX_DELAY)
        peer_txrequest.wait_for_getdata([int(inflight_parent_AB["txid"], 16)])

        self.log.info("Test that the node does not request a parent if it has an in-flight txrequest")
        # Relay orphan child_A
        self.relay_transaction(peer_orphans, child_A["tx"])
        self.bump_mocktime(NONPREF_PEER_TX_DELAY)
        # There are 3 missing parents. missing_parent_A and missing_parent_AB should be requested.
        # But inflight_parent_AB should not, because there is already an in-flight request for it.
        peer_orphans.wait_for_parent_requests([int(missing_parent_A["txid"], 16), int(missing_parent_AB["txid"], 16)])

        self.log.info("Test that the node does not request a parent if it has an in-flight orphan parent request")
        # Relay orphan child_B
        self.relay_transaction(peer_orphans, child_B["tx"])
        self.bump_mocktime(NONPREF_PEER_TX_DELAY)
        # Only missing_parent_B should be requested. Not inflight_parent_AB or missing_parent_AB
        # because they are already being requested from peer_txrequest and peer_orphans respectively.
        peer_orphans.wait_for_parent_requests([int(missing_parent_B["txid"], 16)])
        peer_orphans.assert_never_requested(int(inflight_parent_AB["txid"], 16))

    @cleanup
    def test_orphan_of_orphan(self):
        node = self.nodes[0]
        peer = node.add_p2p_connection(PeerTxRelayer())

        self.log.info("Test handling of an orphan with a parent who is another orphan")
        missing_grandparent = self.wallet_p2pk.create_self_transfer()
        missing_parent_orphan = self.wallet_p2pk.create_self_transfer(utxo_to_spend=missing_grandparent["new_utxo"])
        missing_parent = self.wallet_p2pk.create_self_transfer()
        orphan = self.wallet_p2pk.create_self_transfer_multi(utxos_to_spend=[missing_parent["new_utxo"], missing_parent_orphan["new_utxo"]])

        # The node should put missing_parent_orphan into the orphanage and request missing_grandparent
        self.relay_transaction(peer, missing_parent_orphan["tx"])
        self.bump_mocktime(NONPREF_PEER_TX_DELAY)
        peer.wait_for_parent_requests([int(missing_grandparent["txid"], 16)])

        # The node should put the orphan into the orphanage and request missing_parent, skipping
        # missing_parent_orphan because it already has it in the orphanage.
        self.relay_transaction(peer, orphan["tx"])
        self.bump_mocktime(NONPREF_PEER_TX_DELAY)
        peer.wait_for_parent_requests([int(missing_parent["txid"], 16)])

    @cleanup
    def test_orphan_inherit_rejection(self):
        node = self.nodes[0]
        peer1 = node.add_p2p_connection(PeerTxRelayer())
        peer2 = node.add_p2p_connection(PeerTxRelayer())
        peer3 = node.add_p2p_connection(PeerTxRelayer())

        self.log.info("Test that an orphan with rejected parents, along with any descendants, cannot be retried")
        parent_low_fee = self.wallet_p2pk.create_self_transfer(fee_rate=0)
        child = self.wallet.create_self_transfer(utxo_to_spend=parent_low_fee["new_utxo"])
        grandchild = self.wallet.create_self_transfer(utxo_to_spend=child["new_utxo"])

        # Relay the parent. It should be rejected because it pays 0 fees.
        self.relay_transaction(peer1, parent_low_fee["tx"])

        # Relay the child. It should be rejected for having missing parents, and this rejection is
        # cached by txid.
        with node.assert_debug_log(['not keeping orphan with rejected parents {}'.format(child["txid"])]):
            self.relay_transaction(peer1, child["tx"])
        assert_equal(0, len(node.getrawmempool()))
        peer1.assert_never_requested(parent_low_fee["txid"])

        # Grandchild should also not be kept in orphanage because its parent has been rejected.
        with node.assert_debug_log(['not keeping orphan with rejected parents {}'.format(grandchild["txid"])]):
            self.relay_transaction(peer2, grandchild["tx"])
        assert_equal(0, len(node.getrawmempool()))
        peer2.assert_never_requested(child["txid"])

        # The child should never be requested, even if announced again.
        peer3.send_and_ping(msg_inv([CInv(t=MSG_TX, h=int(child["txid"], 16))]))
        self.bump_mocktime(TXREQUEST_TIME_SKIP)
        peer3.assert_never_requested(child["txid"])

    def run_test(self):
        self.wallet_p2pk = MiniWallet(self.nodes[0], mode=MiniWalletMode.RAW_P2PK)
        self.generate(self.wallet_p2pk, 10)
        self.wallet = MiniWallet(self.nodes[0])
        self.generate(self.wallet, 160)
        self.test_orphan_rejected_parents()
        self.test_orphan_multiple_parents()
        self.test_orphans_overlapping_parents()
        self.test_orphan_of_orphan()
        self.test_orphan_inherit_rejection()


if __name__ == '__main__':
    OrphanHandlingTest().main()
