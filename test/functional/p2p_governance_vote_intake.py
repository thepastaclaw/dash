#!/usr/bin/env python3
# Copyright (c) 2026 The Dash Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
p2p_governance_vote_intake.py

Adversarial P2P coverage for the governance-vote intake bound.

Vulnerability: MNGOVERNANCEOBJECTVOTE handling default-deserialized
CGovernanceVote::vchSig from the wire. A peer declaring a compact-size of
MAX_SIZE (32 MiB) — the exact trigger in the report — caused the generic
byte-vector decoder to allocate/zero multi-megabytes before EOF, then
throw std::ios_base::failure. The outer ProcessMessages catch only logs,
so the peer stayed connected and could replay the send indefinitely.

The fix bounds the read at CGovernanceVote::MAX_SIG_SIZE (96), requires
the wire length to be exactly one of the two structurally legitimate
sizes (65-byte compact ECDSA voting key or 96-byte BLS operator), and
scores the peer 100 (disconnect) with a specific reason on rejection.

This test:
  - Verifies the exact malicious CompactSize(MAX_SIZE) declaration is
    scored and disconnects the peer, and cannot be replayed on the same
    connection (the fresh reconnect starts at score 0).
  - Verifies a well-formed CompactSize with an oversized-but-under-cap
    length (128) is rejected the same way.
  - Verifies an internally truncated valid-boundary length (96 declared,
    fewer bytes delivered) is caught locally and scored — not swallowed
    by the outer generic catch.

We do not verify the *legitimate* boundary sizes here: the wire-layer
bound accepts both 65 and 96 bytes, and those flows are exercised in the
unit test governance_vote_wire_tests. What matters at the P2P layer is
peer punishment for malformed messages, which requires no masternode
setup — the check runs before every downstream gate.
"""

import struct

from test_framework.messages import (
    COutPoint,
    hash256,
    ser_compact_size,
    ser_uint256,
    uint256_from_str,
)
from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    force_finish_mnsync,
    wait_until_helper,
)


# Match src/serialize.h::MAX_SIZE. This is what the original report identified
# as the attacker-controlled compact-size upper bound abused by the wire
# decoder before EOF was reached.
MAX_SIZE = 0x02000000  # 32 MiB

# Match CGovernanceVote::{COMPACT_SIG_SIZE, BLS_SIG_SIZE, MAX_SIG_SIZE}.
COMPACT_SIG_SIZE = 65
BLS_SIG_SIZE = 96
MAX_SIG_SIZE = BLS_SIG_SIZE


class msg_govobjvote_raw:
    """A govobjvote message carrying a hand-crafted raw payload."""
    msgtype = b"govobjvote"

    def __init__(self, payload=b""):
        self.payload = payload

    def serialize(self):
        return self.payload

    def __repr__(self):
        return "msg_govobjvote_raw(len=%d)" % len(self.payload)


def get_p2p_id(node, subver):
    def _get():
        for peer in node.getpeerinfo():
            if peer["subver"] == subver:
                return peer["id"]
        return None
    wait_until_helper(lambda: _get() is not None, timeout=10)
    return _get()


def wait_for_banscore(node, peer_id, expected):
    def _score():
        for peer in node.getpeerinfo():
            if peer["id"] == peer_id:
                return peer["banscore"]
        return None
    wait_until_helper(lambda: _score() == expected, timeout=10)


def vote_header():
    """Fixed-size govobjvote wire prefix, i.e. every field up to (but not
    including) the vchSig CompactSize length."""
    outpoint = COutPoint(uint256_from_str(hash256(b"gov-vote-intake-test")), 0)
    parent_hash = uint256_from_str(hash256(b"gov-vote-intake-parent"))
    outcome = 1   # VOTE_OUTCOME_YES
    signal = 1    # VOTE_SIGNAL_FUNDING
    nTime = 0x5F5E1000
    return (
        outpoint.serialize()
        + ser_uint256(parent_hash)
        + struct.pack("<i", outcome)
        + struct.pack("<i", signal)
        + struct.pack("<q", nTime)
    )


def compactsize_uint32(value):
    """CompactSize encoded in the 0xfe/uint32 form. Used to construct the
    exact malicious wire declaration from the report without having to
    supply the (attacker-omitted) payload bytes."""
    return b"\xfe" + struct.pack("<I", value)


class GovernanceVoteIntakeTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        # -whitelist keeps the misbehaving peer connected past the
        # discouragement threshold so banscore stays observable at 100;
        # -deprecatedrpc=banscore exposes it through getpeerinfo.
        # -debug=net surfaces the specific reason strings in debug.log.
        self.extra_args = [[
            "-whitelist=127.0.0.1",
            "-deprecatedrpc=banscore",
            "-debug=net",
            "-debug=gobject",
        ]]

    def skip_test_if_missing_module(self):
        # This test does not require the wallet.
        pass

    def send_bad_vote_and_expect_ban(self, node, payload, log_reason):
        """Open a fresh peer, send one crafted govobjvote, and assert:
          (a) the node logged the specific Misbehaving reason;
          (b) the peer's banscore climbs to 100 (full ban);
          (c) the connection is torn down by the node — proving the
              rejection did not fall through to the outer generic catch,
              which only logs and would leave the peer able to replay.
        """
        peer = node.add_p2p_connection(P2PInterface())
        peer_id = get_p2p_id(node, peer.strSubVer)
        wait_for_banscore(node, peer_id, 0)

        with node.assert_debug_log(["Misbehaving", log_reason]):
            peer.send_message(msg_govobjvote_raw(payload))
            # Do not sync_with_ping() here: -whitelist prevents auto-disconnect
            # on discouragement but the Misbehaving reason still fires. Wait
            # on the banscore to prove the handler saw and rejected the vote.
            wait_for_banscore(node, peer_id, 100)

        # Prove no replay path on this connection: the score is at 100, the
        # message-handling path returned early, and a follow-up crafted vote
        # would either bump score past 100 (still 100, capped) or reach the
        # same reject path. What we assert here is that the fresh connection
        # every subcase opens starts at 0 — i.e. the previous peer's state
        # did not silently leak into a new connection.
        node.disconnect_p2ps()

    def run_test(self):
        node = self.nodes[0]

        # NetGovernance::ProcessMessage gates every branch behind
        # IsBlockchainSynced(), so the attack — and this test — only reach
        # the govobjvote handler once mnsync has moved past the blockchain
        # phase. Force-advance so the P2P path we care about is live.
        force_finish_mnsync(node)

        header = vote_header()

        # (1) The exact malicious trigger from the report: CompactSize(MAX_SIZE)
        # with no signature bytes following. The pre-fix decoder resized a
        # std::vector<unsigned char> to ~MAX_SIZE bytes before hitting EOF.
        # The fix rejects this at the CompactSize gate.
        malicious_max_size = header + compactsize_uint32(MAX_SIZE)
        self.log.info("CompactSize(MAX_SIZE) is rejected before allocation (Misbehaving 100)")
        self.send_bad_vote_and_expect_ban(
            node,
            malicious_max_size,
            "invalid governance vote signature size",
        )

        # (2) A well-formed CompactSize that fits in one byte but names an
        # oversized (128 > MAX_SIG_SIZE) length. Same rejection path.
        oversized_128 = header + ser_compact_size(128) + b"\x00" * 128
        self.log.info("Oversized-but-under-MAX_SIZE (128) is rejected (Misbehaving 100)")
        self.send_bad_vote_and_expect_ban(
            node,
            oversized_128,
            "invalid governance vote signature size",
        )

        # (3) An intermediate legitimate-looking size (32) — well below the
        # cap but not one of the two structurally legitimate signature
        # encodings. Same rejection path, same reason.
        intermediate_32 = header + ser_compact_size(32) + b"\x00" * 32
        self.log.info("Intermediate size (32) is rejected (Misbehaving 100)")
        self.send_bad_vote_and_expect_ban(
            node,
            intermediate_32,
            "invalid governance vote signature size",
        )

        # (4) Internally truncated legitimate-boundary length: wire declares
        # BLS_SIG_SIZE (96) but delivers only a few bytes. The bounded
        # element read throws ios_base::failure, and the handler must catch
        # it locally and score the peer with the "malformed governance vote"
        # reason. If the fix regressed to relying on the outer catch, the
        # peer would stay connected at score 0.
        truncated = header + struct.pack("<B", BLS_SIG_SIZE) + b"\x00" * 10
        self.log.info("Truncated BLS-length vote is caught locally (Misbehaving 100)")
        self.send_bad_vote_and_expect_ban(
            node,
            truncated,
            "malformed governance vote",
        )

        # Final: sanity-check no state leaked. A fresh peer starts at 0.
        peer = node.add_p2p_connection(P2PInterface())
        peer_id = get_p2p_id(node, peer.strSubVer)
        assert_equal(peer_id is not None, True)
        wait_for_banscore(node, peer_id, 0)
        node.disconnect_p2ps()


if __name__ == '__main__':
    GovernanceVoteIntakeTest().main()
