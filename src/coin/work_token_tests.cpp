#include "work_token.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using v0id::coin::ContractVisibility;
using v0id::coin::Digest512;
using v0id::coin::PayoutAxis;
using v0id::coin::TokenFlavor;
using v0id::coin::WorkEvent;

struct Runner {
    int passed{};
    int failed{};

    void check(bool ok, const std::string& name) {
        if (ok) {
            ++passed;
            std::cout << "[PASS] " << name << '\n';
        } else {
            ++failed;
            std::cerr << "[FAIL] " << name << '\n';
        }
    }
};

Digest512 digest(std::uint8_t seed) {
    Digest512 out{};
    for (std::size_t i = 0; i < out.size(); ++i)
        out[i] = static_cast<std::uint8_t>(seed + i * 13u);
    return out;
}

WorkEvent hybrid_event() {
    WorkEvent e;
    e.visibility = ContractVisibility::hidden_semantics;
    e.mining_work = 1200;
    e.compute_complexity = 4800;
    e.mining_class = "pow-class-v1";
    e.compute_class = "v0id-binfhe-work-v1";
    e.subject_binding = digest(0x11);
    e.evidence_binding = digest(0x22);
    e.mining_binding = digest(0x33);
    e.execution_binding = digest(0x44);
    e.series_stack_binding = digest(0x55);
    return e;
}

bool throws_combo(const WorkEvent& event, PayoutAxis axis) {
    try {
        (void)v0id::coin::derive_payout_primitive(
            event, axis, TokenFlavor::combo);
        return false;
    } catch (const std::runtime_error&) {
        return true;
    }
}

} // namespace

int main() try {
    Runner r;

    const auto hybrid = hybrid_event();
    const auto event_id = v0id::coin::work_event_id512(hybrid);
    r.check(event_id == v0id::coin::work_event_id512(hybrid),
            "hybrid work-event identity is deterministic");

    const auto branches = v0id::coin::derive_available_payout_branches(hybrid);
    r.check(branches.size() == 6,
            "hybrid mining+compute event exposes full 2x3 payout tree");

    r.check(std::all_of(branches.begin(), branches.end(),
                        [&](const auto& p) { return p.work_event_id == event_id; }),
            "all payout leaves share one underlying work-event identity");

    r.check(v0id::coin::payout_symbol(PayoutAxis::mining, TokenFlavor::independent) == "V0ID-MI" &&
            v0id::coin::payout_symbol(PayoutAxis::mining, TokenFlavor::invariant) == "V0ID-MV" &&
            v0id::coin::payout_symbol(PayoutAxis::mining, TokenFlavor::combo) == "V0ID-MC" &&
            v0id::coin::payout_symbol(PayoutAxis::compute, TokenFlavor::independent) == "V0ID-CI" &&
            v0id::coin::payout_symbol(PayoutAxis::compute, TokenFlavor::invariant) == "V0ID-CV" &&
            v0id::coin::payout_symbol(PayoutAxis::compute, TokenFlavor::combo) == "V0ID-CC",
            "six payout primitives have stable mining/compute symbols");

    const auto compute_independent = v0id::coin::denomination_id512(
        hybrid, PayoutAxis::compute, TokenFlavor::independent);
    const auto compute_invariant = v0id::coin::denomination_id512(
        hybrid, PayoutAxis::compute, TokenFlavor::invariant);
    const auto compute_combo = v0id::coin::denomination_id512(
        hybrid, PayoutAxis::compute, TokenFlavor::combo);

    auto changed = hybrid;
    changed.execution_binding[0] ^= 1u;
    r.check(v0id::coin::denomination_id512(
                changed, PayoutAxis::compute, TokenFlavor::independent) != compute_independent,
            "compute independent denomination binds exact module/TM execution identity");
    r.check(v0id::coin::denomination_id512(
                changed, PayoutAxis::compute, TokenFlavor::invariant) == compute_invariant,
            "compute invariant denomination ignores exact module/TM identity");
    r.check(v0id::coin::denomination_id512(
                changed, PayoutAxis::compute, TokenFlavor::combo) != compute_combo,
            "compute combo denomination binds exact compute identity");

    const auto mining_independent = v0id::coin::denomination_id512(
        hybrid, PayoutAxis::mining, TokenFlavor::independent);
    const auto mining_invariant = v0id::coin::denomination_id512(
        hybrid, PayoutAxis::mining, TokenFlavor::invariant);
    const auto mining_combo = v0id::coin::denomination_id512(
        hybrid, PayoutAxis::mining, TokenFlavor::combo);

    changed = hybrid;
    changed.mining_binding[0] ^= 1u;
    r.check(v0id::coin::denomination_id512(
                changed, PayoutAxis::mining, TokenFlavor::independent) != mining_independent,
            "mining independent denomination binds exact PoW algorithm/profile identity");
    r.check(v0id::coin::denomination_id512(
                changed, PayoutAxis::mining, TokenFlavor::invariant) == mining_invariant,
            "mining invariant denomination ignores exact mining algorithm identity");
    r.check(v0id::coin::denomination_id512(
                changed, PayoutAxis::mining, TokenFlavor::combo) != mining_combo,
            "mining combo denomination binds exact mining identity");

    r.check(mining_combo != compute_combo,
            "mining-combo and compute-combo remain distinct payout classes");

    auto pure_mining = hybrid;
    pure_mining.compute_complexity = 0;
    pure_mining.compute_class.clear();
    pure_mining.execution_binding.fill(0);
    pure_mining.series_stack_binding.fill(0);
    pure_mining.visibility = ContractVisibility::not_applicable;
    const auto mining_branches = v0id::coin::derive_available_payout_branches(pure_mining);
    r.check(mining_branches.size() == 2,
            "pure mining event exposes independent+invariant leaves only");
    r.check(throws_combo(pure_mining, PayoutAxis::mining),
            "pure mining event cannot mint a fake hybrid combo leaf");

    auto pure_compute = hybrid;
    pure_compute.mining_work = 0;
    pure_compute.mining_class.clear();
    pure_compute.mining_binding.fill(0);
    const auto compute_branches = v0id::coin::derive_available_payout_branches(pure_compute);
    r.check(compute_branches.size() == 2,
            "pure compute event exposes independent+invariant leaves only");
    r.check(throws_combo(pure_compute, PayoutAxis::compute),
            "pure compute event cannot mint a fake hybrid combo leaf");

    changed = hybrid;
    ++changed.mining_work;
    r.check(v0id::coin::work_event_id512(changed) != event_id,
            "mining work amount changes underlying event identity");

    changed = hybrid;
    ++changed.compute_complexity;
    r.check(v0id::coin::work_event_id512(changed) != event_id,
            "compute complexity changes underlying event identity");

    changed = hybrid;
    changed.visibility = ContractVisibility::public_semantics;
    r.check(v0id::coin::work_event_id512(changed) != event_id,
            "public/hidden contract visibility changes work-event identity");

    bool empty_rejected = false;
    try {
        WorkEvent empty;
        (void)v0id::coin::work_event_id512(empty);
    } catch (const std::runtime_error&) {
        empty_rejected = true;
    }
    r.check(empty_rejected,
            "zero-work event fails closed");

    std::cout << "\nV0ID hybrid work-token wrapper tests: "
              << r.passed << " passed, " << r.failed << " failed\n"
              << "NOTE: six payout primitives are classifications over one accepted work event. "
                 "This layer defines no issuance multiplier or mining/compute exchange rate.\n";
    return r.failed == 0 ? 0 : 1;
} catch (const std::exception& e) {
    std::cerr << "V0ID work-token test fatal error: " << e.what() << '\n';
    return 1;
}
