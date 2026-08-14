#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace v0id::coin {

using Digest512 = std::array<std::uint8_t, 64>;

// The payout axis is a view over one accepted hybrid-capable work event. Mining
// and useful compute are deliberately NOT mutually exclusive event types.
enum class PayoutAxis : std::uint8_t {
    mining = 1,
    compute = 2,
};

// Orthogonal to mining/compute and token flavor.
enum class ContractVisibility : std::uint8_t {
    not_applicable = 0,
    public_semantics = 1,
    hidden_semantics = 2,
};

// For each axis the wrapper can expose three payout primitives:
//
// independent : preserves the exact algorithm/module execution identity.
// invariant   : common denomination within the corresponding work class.
// combo       : binds BOTH mining and compute classes/identities. A combo leaf
//               therefore exists only for a genuinely hybrid event.
enum class TokenFlavor : std::uint8_t {
    independent = 1,
    invariant = 2,
    combo = 3,
};

// One accepted work event may contain conventional mining work, useful compute,
// or both. This wrapper carries already-accepted evidence; it does not define
// PoW validity, useful-compute soundness, difficulty, issuance, fees, exchange
// rates, or a conversion formula between mining work and compute complexity.
struct WorkEvent {
    std::string protocol_id{"v0id-work-event-v1"};
    ContractVisibility visibility{ContractVisibility::not_applicable};

    std::uint64_t mining_work{};
    std::uint64_t compute_complexity{};
    std::string mining_class;
    std::string compute_class;

    // Current block/job/challenge or equivalent subject and the proof/result the
    // future verifier accepted.
    Digest512 subject_binding{};
    Digest512 evidence_binding{};

    // Exact mining algorithm/profile identity, e.g. a canonical commitment to
    // the PoW algorithm and parameters. May be zero when mining_work == 0.
    Digest512 mining_binding{};

    // Exact compute identity. For synchronized modules use the canonical shared
    // module-set digest. For built-in/default stacks or user Turing machines use
    // a canonical SHA3-512 identity of that executable/profile. May be zero when
    // compute_complexity == 0.
    Digest512 execution_binding{};

    // Optional series-first whole-stack context binding for useful computation.
    Digest512 series_stack_binding{};
};

struct PayoutPrimitive {
    std::string protocol_id{"v0id-payout-primitive-v1"};
    PayoutAxis axis{PayoutAxis::compute};
    TokenFlavor flavor{TokenFlavor::invariant};

    // All payout leaves derived from one accepted event share work_event_id.
    // Consensus can therefore enforce whatever issuance policy it chooses
    // without confusing six representations with six unrelated work events.
    Digest512 work_event_id{};
    Digest512 denomination_id{};
    Digest512 payout_id{};

    // Keep both quantities explicit. In particular, combo tokens do NOT hide a
    // made-up exchange rate between mining security work and compute complexity.
    std::uint64_t mining_work{};
    std::uint64_t compute_complexity{};
    std::string mining_class;
    std::string compute_class;
    Digest512 mining_binding{};
    Digest512 execution_binding{};
};

// Canonical SHA3-512 identities. OpenSSL supplies SHA3; no custom hash primitive
// is introduced by the coin wrapper.
Digest512 work_event_id512(const WorkEvent& event);
Digest512 denomination_id512(const WorkEvent& event,
                             PayoutAxis axis,
                             TokenFlavor flavor);
PayoutPrimitive derive_payout_primitive(const WorkEvent& event,
                                        PayoutAxis axis,
                                        TokenFlavor flavor);

// Returns every semantically valid leaf. Pure mining/compute events get their
// independent+invariant leaves. A hybrid event can expose the full 2 x 3 tree:
// MI/MV/MC and CI/CV/CC. Combo leaves require both work components to be nonzero.
std::vector<PayoutPrimitive> derive_available_payout_branches(
    const WorkEvent& event);

std::string payout_symbol(PayoutAxis axis, TokenFlavor flavor);
std::string to_string(PayoutAxis axis);
std::string to_string(TokenFlavor flavor);
std::string digest_hex(const Digest512& digest);

} // namespace v0id::coin
