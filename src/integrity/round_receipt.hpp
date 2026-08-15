#pragma once

#include "quine_hash.hpp"
#include "remote_machine_codec.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace v0id::integrity {

// A 64-byte SHA3-512 chain link/digest. This reuses QuineDigest512's width;
// it is a distinct concept (execution-order commitment, not a job-image
// commitment) but there is no reason to invent a second digest type for it.
using RoundLink = QuineDigest512;

// Public, evaluator-visible identity a round receipt is bound to. Every field
// already exists in the RMJ3/RMR3 job interface; this struct adds no new
// secret material, only a place to bind them together for the receipt.
//
// job_id/epoch are included deliberately. The existing RMR3 result already
// echoes session_id/shape/profile and the client already requires exact
// matches for those (see remote_machine_demo.cpp). It does NOT currently bind
// job_id/epoch into the *result* payload at all -- only the transport
// envelope echoes them, and a permissive dispatcher can set that from the
// request without deriving it from the computed answer. A "replay evaluator"
// that answers a fresh job with an old cached accepted result is exactly the
// gap that leaves open. Binding job_id/epoch here closes it for any verifier
// that checks receipt.context against its own trusted request context.
struct RoundReceiptContext {
    v0id::fhe::EvaluatorSessionId session_id{};
    v0id::fhe::PublicMachineShape shape{};
    v0id::fhe::CryptoProfileId profile{};
    std::string job_id;
    std::uint64_t epoch{};
};

bool round_receipt_context_equal(const RoundReceiptContext& a,
                                 const RoundReceiptContext& b);

// Chain seed. Binds the exact round budget (context.shape.rounds) and the
// full job/session/profile identity that every link in the chain is folded
// under.
RoundLink round_receipt_seed(const RoundReceiptContext& context);

// Fold one round's post-step witness onto the running chain. round_index is
// 1-based. This is a plain SHA3-512 hash chain -- the same "standardized
// primitive, canonical length-delimited encoding" style QuineHash512 already
// uses, not a new construction that needs its own cryptanalysis.
RoundLink fold_round_link(const RoundLink& previous,
                          std::uint64_t round_index,
                          const RoundLink& round_witness_digest);

// Digest of one round's evaluator-visible post-step ciphertext state. This is
// computed over already-serialized ciphertext bytes with SHA3-512, a public
// operation: no new FHE gates, no secret key. BinFHE gate evaluation
// re-randomizes ciphertext encodings, so two genuinely independent step()
// calls are not expected to serialize to identical bytes even when the
// underlying plaintext happens to reach a fixed point.
RoundLink round_state_digest(const v0id::fhe::ByteBlob& serialized_state,
                             const v0id::fhe::ByteBlob& serialized_head,
                             const v0id::fhe::ByteBlob& serialized_tape);

// One evaluator's claimed execution-order receipt for a job: one witness
// digest per requested round, in round order.
struct RoundReceipt {
    RoundReceiptContext context;
    std::vector<RoundLink> witness_digests;
};

struct RoundReceiptVerdict {
    bool ok{};
    std::string reason;
    // Informational chain summary: the seed folded through every supplied
    // witness in order. Reordering interior digests changes this value even
    // though it does not by itself fail verify_round_receipt today; a future
    // stronger binding (e.g. embedding this into QuineHash512) could compare
    // it against an independently derived value and close interior-round
    // splicing too. Until something does that comparison, treat receipt_id
    // as diagnostic, not as a security boundary.
    RoundLink receipt_id{};
};

// Verification is O(rounds) SHA3-512 calls over already-serialized,
// already-evaluator-visible bytes: no OpenFHE bootstrapped gate evaluation,
// no secret key. This is many orders of magnitude cheaper than recomputing
// even one requested round -- a verifier that had to redo the FHE computation
// to check it would have gained nothing over just distrusting the evaluator
// outright. See malicious_evaluator_harness.cpp for a measured comparison.
//
// What this DOES detect (see round_receipt_tests.cpp and the malicious
// evaluator harness for the concrete cases):
//   - fewer witnesses than the declared round budget ("skip and stop"),
//   - a receipt whose context (session/job/epoch/profile/round-budget) does
//     not match what the verifier actually requested ("replay",
//     "substitution"),
//   - a receipt whose final witness does not match the actual returned
//     machine state ("splice" of a receipt onto someone else's result, or
//     vice versa),
//   - the specific "skip and resend the unchanged ciphertext" strategy that
//     the malicious evaluator harness shows defeats the final-output and
//     legacy-fingerprint checks alone (caught by duplicate-witness
//     detection).
//
// What this does NOT detect, and must not be described as detecting:
//   - an evaluator that pays for a cheap ciphertext re-randomization (a
//     handful of ordinary gate evaluations) instead of running the real
//     per-round transition circuit, producing genuinely distinct, genuinely
//     matching witnesses without doing the requested work. Closing that
//     requires binding the witness to the transition circuit itself (a
//     soundness property of a real verifiable-computation system), not
//     merely to "some ciphertext changed." This remains the open problem
//     described in ROADMAP.md section 5.
//   - reordering of interior (non-final) round witnesses relative to their
//     claimed round index, unless a caller separately checks receipt_id
//     against an independently derived value.
//   - anything about a network peer's identity/authentication; this audits
//     one already-received job/result pair, it is not a transport or peer
//     authentication mechanism.
RoundReceiptVerdict verify_round_receipt(
    const RoundReceiptContext& expected,
    const RoundReceipt& receipt,
    const RoundLink& actual_final_state_digest);

} // namespace v0id::integrity
