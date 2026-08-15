#include "round_receipt.hpp"

#include <set>
#include <stdexcept>

namespace v0id::integrity {
namespace {

void append_u64(std::vector<std::uint8_t>& out, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8)
        out.push_back(static_cast<std::uint8_t>((value >> shift) & 0xffu));
}

void append_string(std::vector<std::uint8_t>& out, const std::string& value) {
    append_u64(out, static_cast<std::uint64_t>(value.size()));
    out.insert(out.end(), value.begin(), value.end());
}

void append_blob(std::vector<std::uint8_t>& out,
                 const std::uint8_t* data,
                 std::size_t size) {
    append_u64(out, static_cast<std::uint64_t>(size));
    if (size != 0)
        out.insert(out.end(), data, data + size);
}

void append_profile(std::vector<std::uint8_t>& out,
                    const v0id::fhe::CryptoProfileId& profile) {
    append_string(out, profile.primitive_id);
    append_string(out, profile.parameter_set);
    append_string(out, profile.machine_protocol);
    append_string(out, profile.integrity_profile);
    append_string(out, profile.series_generator_id);
    append_u64(out, profile.series_generator_version);
}

void append_shape(std::vector<std::uint8_t>& out,
                  const v0id::fhe::PublicMachineShape& shape) {
    append_u64(out, shape.states);
    append_u64(out, shape.tape_cells);
    append_u64(out, shape.rounds);
    append_u64(out, shape.integrity_slots);
}

bool same_shape(const v0id::fhe::PublicMachineShape& a,
                const v0id::fhe::PublicMachineShape& b) {
    return a.states == b.states &&
           a.tape_cells == b.tape_cells &&
           a.rounds == b.rounds &&
           a.integrity_slots == b.integrity_slots;
}

} // namespace

bool round_receipt_context_equal(const RoundReceiptContext& a,
                                 const RoundReceiptContext& b) {
    return a.session_id == b.session_id &&
           same_shape(a.shape, b.shape) &&
           a.profile == b.profile &&
           a.job_id == b.job_id &&
           a.epoch == b.epoch;
}

RoundLink round_receipt_seed(const RoundReceiptContext& context) {
    if (context.job_id.empty())
        throw std::runtime_error("round receipt requires a job id");

    std::vector<std::uint8_t> canonical;
    append_string(canonical, "V0ID-ROUND-RECEIPT-SEED-v1");
    append_blob(canonical, context.session_id.data(), context.session_id.size());
    append_shape(canonical, context.shape);
    append_profile(canonical, context.profile);
    append_string(canonical, context.job_id);
    append_u64(canonical, context.epoch);
    return sha3_512_bytes(canonical);
}

RoundLink fold_round_link(const RoundLink& previous,
                          std::uint64_t round_index,
                          const RoundLink& round_witness_digest) {
    std::vector<std::uint8_t> canonical;
    append_string(canonical, "V0ID-ROUND-RECEIPT-LINK-v1");
    append_blob(canonical, previous.data(), previous.size());
    append_u64(canonical, round_index);
    append_blob(canonical, round_witness_digest.data(), round_witness_digest.size());
    return sha3_512_bytes(canonical);
}

RoundLink round_state_digest(const v0id::fhe::ByteBlob& serialized_state,
                             const v0id::fhe::ByteBlob& serialized_head,
                             const v0id::fhe::ByteBlob& serialized_tape) {
    std::vector<std::uint8_t> canonical;
    append_string(canonical, "V0ID-ROUND-STATE-DIGEST-v1");
    append_blob(canonical, serialized_state.data(), serialized_state.size());
    append_blob(canonical, serialized_head.data(), serialized_head.size());
    append_blob(canonical, serialized_tape.data(), serialized_tape.size());
    return sha3_512_bytes(canonical);
}

RoundReceiptVerdict verify_round_receipt(
    const RoundReceiptContext& expected,
    const RoundReceipt& receipt,
    const RoundLink& actual_final_state_digest) {

    RoundReceiptVerdict verdict;

    if (!round_receipt_context_equal(expected, receipt.context)) {
        verdict.reason =
            "round receipt context does not match the requested job "
            "(session/job/epoch/profile/round-budget substitution or replay)";
        return verdict;
    }

    if (receipt.witness_digests.size() != expected.shape.rounds) {
        verdict.reason =
            "round receipt link count (" +
            std::to_string(receipt.witness_digests.size()) +
            ") does not match the requested round budget (" +
            std::to_string(expected.shape.rounds) +
            "); evaluator skipped rounds";
        return verdict;
    }

    if (receipt.witness_digests.empty()) {
        verdict.reason = "round receipt requires at least one round";
        return verdict;
    }

    std::set<std::string> seen;
    for (std::size_t i = 0; i < receipt.witness_digests.size(); ++i) {
        const auto& digest = receipt.witness_digests[i];
        const std::string key(reinterpret_cast<const char*>(digest.data()), digest.size());
        if (!seen.insert(key).second) {
            verdict.reason =
                "round receipt reuses an identical per-round witness at round " +
                std::to_string(i + 1) +
                " (round did not change from an earlier round; likely a skipped "
                "or resent round)";
            return verdict;
        }
    }

    if (receipt.witness_digests.back() != actual_final_state_digest) {
        verdict.reason =
            "round receipt final witness does not match the actual returned "
            "machine state (result spliced from a different execution)";
        return verdict;
    }

    RoundLink link = round_receipt_seed(expected);
    for (std::size_t i = 0; i < receipt.witness_digests.size(); ++i)
        link = fold_round_link(link, i + 1, receipt.witness_digests[i]);

    verdict.ok = true;
    verdict.reason = "round receipt verified";
    verdict.receipt_id = link;
    return verdict;
}

} // namespace v0id::integrity
