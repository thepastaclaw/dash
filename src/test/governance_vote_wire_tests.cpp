// Copyright (c) 2026 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <governance/vote.h>
#include <primitives/transaction.h>
#include <serialize.h>
#include <streams.h>
#include <uint256.h>
#include <version.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <ios>
#include <limits>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(governance_vote_wire_tests, BasicTestingSetup)

namespace {
// Serialize the fixed-size prefix of a CGovernanceVote wire encoding: exactly
// the field layout SERIALIZE_METHODS writes before the signature vector.
void WriteVoteHeader(CDataStream& ss)
{
    const COutPoint outpoint{uint256::ONE, 0};
    const uint256 parent_hash{uint256::ONE};
    const int outcome = 1; // VOTE_OUTCOME_YES
    const int signal = 1;  // VOTE_SIGNAL_FUNDING (voting-key signed)
    const int64_t time = 1'700'000'000;
    ss << outpoint << parent_hash << outcome << signal << time;
}

// Build a well-formed wire vote with a signature of arbitrary length. Uses the
// default operator<< so the CompactSize prefix matches the payload byte count.
CDataStream MakeVoteWire(size_t sig_len)
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    WriteVoteHeader(ss);
    ss << std::vector<unsigned char>(sig_len, 0xAA);
    return ss;
}
} // namespace

// The exact malicious trigger. A peer declaring CompactSize(MAX_SIZE) for the
// signature vector would drive the generic byte-vector unserializer to resize
// a std::vector<unsigned char> to ~32 MiB (and 5 MiB in the original report)
// before EOF was reached, letting one peer repeatedly force multi-megabyte
// allocations on the message-handling thread. UnserializeFromNet must reject
// this at the CompactSize gate — no allocation, no element read.
BOOST_AUTO_TEST_CASE(rejects_compactsize_max_size_before_allocation)
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    WriteVoteHeader(ss);
    // Hand-encode CompactSize(MAX_SIZE) — the exact value in the report — then
    // deliberately do NOT append any signature bytes. If the bound check ever
    // regressed, we would either allocate ~32 MiB or throw ios_base::failure
    // trying to read the missing bytes; either is a bug this test catches.
    ss << uint8_t{0xfe};
    ss << static_cast<uint32_t>(MAX_SIZE);

    CGovernanceVote vote;
    BOOST_CHECK(!vote.UnserializeFromNet(ss));
}

// Same, but with the uint64 CompactSize form. Proves the check compares in
// uint64 (via UnserializeVectorWithMaxSize) rather than a narrowed size_t.
BOOST_AUTO_TEST_CASE(rejects_compactsize_uint64_form)
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    WriteVoteHeader(ss);
    ss << uint8_t{0xff};
    ss << uint64_t{0x100000000ULL + CGovernanceVote::BLS_SIG_SIZE};

    CGovernanceVote vote;
    BOOST_CHECK(!vote.UnserializeFromNet(ss));
}

// A well-formed CompactSize that names a wire size just above BLS (97) must
// also be rejected — the primitive checks against MAX_SIG_SIZE, so the wire
// gate itself refuses to allocate.
BOOST_AUTO_TEST_CASE(rejects_oversized_but_under_max_size)
{
    // MAX_SIG_SIZE = BLS = 96. 128 is above the cap but well under MAX_SIZE.
    CDataStream ss = MakeVoteWire(128);
    CGovernanceVote vote;
    BOOST_CHECK(!vote.UnserializeFromNet(ss));
}

// Sizes between 1 and BLS that are neither compact-ECDSA (65) nor BLS (96) are
// structurally illegitimate — no legitimate voting flow produces them — and
// must be rejected at the wire layer.
BOOST_AUTO_TEST_CASE(rejects_other_intermediate_sizes)
{
    for (size_t bad : {size_t{0}, size_t{1}, size_t{32}, size_t{64}, size_t{66}, size_t{95}}) {
        CDataStream ss = MakeVoteWire(bad);
        CGovernanceVote vote;
        BOOST_CHECK_MESSAGE(!vote.UnserializeFromNet(ss),
                            "signature size " << bad << " should be rejected");
    }
}

// Requirement 3: internally-truncated vectors — the wire declares a valid
// size but does not deliver enough bytes — must not fall through to the outer
// ProcessMessages catch as an unhandled exception; the caller relies on
// std::ios_base::failure being catchable at this layer. Both boundary sizes
// share the underlying element decoder, so testing one is sufficient.
BOOST_AUTO_TEST_CASE(truncated_signature_throws_ios_failure)
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    WriteVoteHeader(ss);
    // Declare a 96-byte signature but only supply 10 bytes.
    ss << uint8_t{static_cast<uint8_t>(CGovernanceVote::BLS_SIG_SIZE)};
    const std::vector<unsigned char> partial(10, 0xBB);
    ss.write(MakeByteSpan(partial));

    CGovernanceVote vote;
    BOOST_CHECK_THROW([[maybe_unused]] const bool ok = vote.UnserializeFromNet(ss),
                      std::ios_base::failure);
}

// Wire compatibility for the two legitimate boundary sizes: 65-byte compact
// ECDSA (proposal FUNDING via voting key) and 96-byte BLS (operator key).
// UnserializeFromNet must accept both and match what operator>> would produce.
BOOST_AUTO_TEST_CASE(accepts_65_byte_compact_signature)
{
    CDataStream ss_a = MakeVoteWire(CGovernanceVote::COMPACT_SIG_SIZE);
    CDataStream ss_b = MakeVoteWire(CGovernanceVote::COMPACT_SIG_SIZE);

    CGovernanceVote via_net;
    BOOST_REQUIRE(via_net.UnserializeFromNet(ss_a));
    BOOST_CHECK_EQUAL(ss_a.size(), 0U);

    CGovernanceVote via_operator;
    ss_b >> via_operator;

    // Same hash means every wire-relevant field matched exactly.
    BOOST_CHECK_EQUAL(via_net.GetHash().ToString(), via_operator.GetHash().ToString());
}

BOOST_AUTO_TEST_CASE(accepts_96_byte_bls_signature)
{
    CDataStream ss_a = MakeVoteWire(CGovernanceVote::BLS_SIG_SIZE);
    CDataStream ss_b = MakeVoteWire(CGovernanceVote::BLS_SIG_SIZE);

    CGovernanceVote via_net;
    BOOST_REQUIRE(via_net.UnserializeFromNet(ss_a));
    BOOST_CHECK_EQUAL(ss_a.size(), 0U);

    CGovernanceVote via_operator;
    ss_b >> via_operator;

    BOOST_CHECK_EQUAL(via_net.GetHash().ToString(), via_operator.GetHash().ToString());
}

// The SER_GETHASH flag path (used by CGovernanceVote::GetSignatureHash) must
// not be affected by the wire cap. This is a smoke test that GetSignatureHash
// still succeeds on a well-formed vote parsed via the bounded reader.
BOOST_AUTO_TEST_CASE(ser_gethash_unchanged)
{
    CDataStream ss = MakeVoteWire(CGovernanceVote::BLS_SIG_SIZE);
    CGovernanceVote vote;
    BOOST_REQUIRE(vote.UnserializeFromNet(ss));
    BOOST_CHECK(vote.GetSignatureHash() != uint256{});
}

BOOST_AUTO_TEST_SUITE_END()
