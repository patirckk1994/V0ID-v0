#include "round_receipt.hpp"

#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using v0id::fhe::CryptoProfileId;
using v0id::fhe::EvaluatorSessionId;
using v0id::fhe::PublicMachineShape;
using v0id::integrity::RoundLink;
using v0id::integrity::RoundReceipt;
using v0id::integrity::RoundReceiptContext;
using v0id::integrity::verify_round_receipt;

struct TestRunner {
    int passed{};
    int failed{};

    void expect(bool condition, const std::string& name, const std::string& reason) {
        if (condition) {
            ++passed;
            std::cout << "[PASS] " << name << '\n';
        } else {
            ++failed;
            std::cerr << "[FAIL] " << name << ": " << reason << '\n';
        }
    }
};

EvaluatorSessionId session_id(std::uint8_t bias = 0) {
    EvaluatorSessionId id{};
    for (std::size_t i = 0; i < id.size(); ++i)
        id[i] = static_cast<std::uint8_t>(i + 1 + bias);
    return id;
}

CryptoProfileId demo_profile() {
    return CryptoProfileId{
        "openfhe-binfhe",
        "STD128Q",
        "v0id-remote-machine-v3",
        "toy-fingerprint32-v1+quine-sha3-512-client-v1",
        "v0id-series-kmac-v1",
        1,
    };
}

RoundReceiptContext demo_context(const std::string& job_id, std::uint64_t rounds = 4) {
    RoundReceiptContext context;
    context.session_id = session_id();
    context.shape = PublicMachineShape{4, 8, rounds, 4};
    context.profile = demo_profile();
    context.job_id = job_id;
    context.epoch = 1;
    return context;
}

// Stand-in for "serialize this round's ciphertext bytes and hash them". The
// audit only ever sees post-serialization bytes, so a plain tagged digest is
// an honest substitute for a real BinFHE ciphertext blob in a fast, FHE-free
// unit test; malicious_evaluator_harness.cpp exercises the real thing.
RoundLink synthetic_witness(const std::string& tag, std::uint64_t round) {
    std::vector<std::uint8_t> bytes(tag.begin(), tag.end());
    bytes.push_back(static_cast<std::uint8_t>(round));
    return v0id::integrity::sha3_512_bytes(bytes);
}

std::vector<RoundLink> honest_witnesses(const std::string& tag, std::uint64_t rounds) {
    std::vector<RoundLink> out;
    out.reserve(rounds);
    for (std::uint64_t r = 1; r <= rounds; ++r)
        out.push_back(synthetic_witness(tag, r));
    return out;
}

} // namespace

int main() try {
    TestRunner tests;

    // --- Positive control: a genuinely honest 4-round receipt verifies. ---
    const auto context_a = demo_context("job-A");
    const auto witnesses_a = honest_witnesses("job-A", 4);
    RoundReceipt receipt_a{context_a, witnesses_a};
    const auto verdict_a = verify_round_receipt(context_a, receipt_a, witnesses_a.back());
    tests.expect(verdict_a.ok, "honest 4-round receipt verifies", verdict_a.reason);

    const auto verdict_a_again = verify_round_receipt(context_a, receipt_a, witnesses_a.back());
    tests.expect(verdict_a.receipt_id == verdict_a_again.receipt_id,
                 "receipt_id is deterministic for identical input",
                 "same receipt produced different receipt_id across calls");

    auto reordered = witnesses_a;
    std::swap(reordered[0], reordered[1]);
    const auto verdict_reordered = verify_round_receipt(
        context_a, RoundReceipt{context_a, reordered}, reordered.back());
    tests.expect(verdict_a.receipt_id != verdict_reordered.receipt_id,
                 "reordering interior witnesses changes receipt_id",
                 "receipt_id did not depend on witness order (documented as diagnostic-only, "
                 "but it should still be order-sensitive)");

    // --- SKIP: fewer links than the declared round budget. ---
    std::vector<RoundLink> two_of_four(witnesses_a.begin(), witnesses_a.begin() + 2);
    const auto verdict_skip_count = verify_round_receipt(
        context_a, RoundReceipt{context_a, two_of_four}, two_of_four.back());
    tests.expect(!verdict_skip_count.ok,
                 "SKIP: receipt with 2 links against a 4-round budget is rejected",
                 "short receipt was incorrectly accepted");
    tests.expect(verdict_skip_count.reason.find("skipped rounds") != std::string::npos,
                 "SKIP: rejection reason names the round-count mismatch",
                 "reason was: " + verdict_skip_count.reason);

    // --- SKIP (the concrete 2/4 bug): evaluator only computes 2 real rounds
    // and resends the unchanged post-round-2 ciphertext state to pad out
    // rounds 3 and 4. This is exactly what malicious_evaluator_harness.cpp's
    // "skip_half" strategy does once translated into round-witness digests:
    // the reused ciphertext object serializes to the same bytes every time.
    auto skip_and_resend = witnesses_a;
    skip_and_resend[2] = witnesses_a[1]; // round 3 "witness" == round 2's (no real step ran)
    skip_and_resend[3] = witnesses_a[1]; // round 4 "witness" == round 2's
    const auto verdict_skip_resend = verify_round_receipt(
        context_a, RoundReceipt{context_a, skip_and_resend}, skip_and_resend.back());
    tests.expect(!verdict_skip_resend.ok,
                 "SKIP: skip-and-resend-identical-ciphertext receipt is rejected",
                 "duplicate per-round witnesses were incorrectly accepted");
    tests.expect(verdict_skip_resend.reason.find("identical per-round witness") != std::string::npos,
                 "SKIP: rejection reason names the duplicate witness",
                 "reason was: " + verdict_skip_resend.reason);

    // --- REPLAY: a fully self-consistent receipt built for job A is
    // presented as the answer to a differently-identified job B. ---
    const auto context_b = demo_context("job-B");
    const auto verdict_replay = verify_round_receipt(
        context_b, RoundReceipt{context_a, witnesses_a}, witnesses_a.back());
    tests.expect(!verdict_replay.ok,
                 "REPLAY: job-A receipt rejected when verified against job-B's context",
                 "cross-job replay was incorrectly accepted");
    tests.expect(verdict_replay.reason.find("does not match the requested job") != std::string::npos,
                 "REPLAY: rejection reason names the context mismatch",
                 "reason was: " + verdict_replay.reason);

    // REPLAY variant: only the session id differs (same job_id/epoch/profile/
    // shape), modeling a stale-session evaluator answering under someone
    // else's cached session.
    auto context_stale_session = context_a;
    context_stale_session.session_id = session_id(9);
    const auto verdict_stale_session = verify_round_receipt(
        context_stale_session, RoundReceipt{context_a, witnesses_a}, witnesses_a.back());
    tests.expect(!verdict_stale_session.ok,
                 "REPLAY: stale/foreign session id alone is rejected",
                 "session substitution was incorrectly accepted");

    // --- SPLICE: mix a genuine receipt's round links with another job's
    // actual final output. ---
    const auto context_c = demo_context("job-C");
    const auto witnesses_c = honest_witnesses("job-C", 4);
    const auto verdict_splice_result = verify_round_receipt(
        context_a, RoundReceipt{context_a, witnesses_a}, witnesses_c.back());
    tests.expect(!verdict_splice_result.ok,
                 "SPLICE: job-A receipt against job-C's actual final output is rejected",
                 "spliced final-result mismatch was incorrectly accepted");
    tests.expect(verdict_splice_result.reason.find("does not match the actual returned") !=
                     std::string::npos,
                 "SPLICE: rejection reason names the final-witness mismatch",
                 "reason was: " + verdict_splice_result.reason);

    // SPLICE variant: interior rounds borrowed from job C, final round
    // genuinely from job A. This documents a real, stated limitation: the
    // audit does not independently validate interior rounds, only that they
    // are present, distinct and correctly counted, plus that the final round
    // matches the actual output. It is intentionally not sold as closing
    // interior-round splicing.
    auto spliced_interior = witnesses_a;
    spliced_interior[1] = witnesses_c[1];
    const auto verdict_splice_interior = verify_round_receipt(
        context_a, RoundReceipt{context_a, spliced_interior}, spliced_interior.back());
    tests.expect(verdict_splice_interior.ok,
                 "SPLICE (documented gap): interior-round splice is NOT caught by this audit",
                 "interior splice was unexpectedly rejected; update round_receipt.hpp's "
                 "documented limitations if this now fails soundly");

    // --- Boundary: a 1-round job is the minimal well-formed case. ---
    const auto context_one = demo_context("job-D", 1);
    const auto witnesses_one = honest_witnesses("job-D", 1);
    const auto verdict_one = verify_round_receipt(
        context_one, RoundReceipt{context_one, witnesses_one}, witnesses_one.back());
    tests.expect(verdict_one.ok, "1-round receipt verifies", verdict_one.reason);

    std::cout << "\nV0ID round-receipt audit tests: "
              << tests.passed << " passed, " << tests.failed << " failed\n";
    std::cout << "NOTE: this proves the audit rejects skip/replay/final-result-splice under\n"
                 "the tested strategies; it does NOT prove soundness against an adaptive\n"
                 "evaluator that pays for cheap ciphertext re-randomization instead of the\n"
                 "real per-round circuit, and it does NOT catch interior-round splicing.\n"
                 "See round_receipt.hpp for the exact claim boundary.\n";
    return tests.failed == 0 ? 0 : 1;
} catch (const std::exception& e) {
    std::cerr << "V0ID round-receipt audit tests fatal error: " << e.what() << '\n';
    return 2;
}
