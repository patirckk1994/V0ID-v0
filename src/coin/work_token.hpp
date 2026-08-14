#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace v0id::coin {

using Digest512 = std::array<std::uint8_t, 64>;

// First payout dimension: where accepted work came from.
enum class WorkSource : std::uint8_t {
    mining_pow = 1,
    useful_compute = 2,
};

// Orthogonal to work source and token flavor.
enum class ContractVisibility : std::uint8_t {
    not_applicable = 0,
    public_semantics = 1,
    hidden_semantics = 2,
};

// Second payout dimension. The names intentionally follow the architecture
// discussion rather than pretending these are already consensus assets.
//
// independent : preserves exact execution/module/algorithm identity.
// invariant   : common denomination for the same normalized work class.
// combo       : binds both the exact identity and invariant denomination.
enum class TokenFlavor : std::uint8_t {
    independent = 1,
    invariant = 2,
    combo = 3,
};

// One accepted unit/event of work. This is only a wrapper around evidence that a
// future verifier/consensus layer has already accepted. It does not define PoW
// validity, useful-compute soundness, difficulty, issuance, fees or exchange
// rates.
struct WorkEvent {
    std::string protocol_id{"v0id-work-event-v1"};
    WorkSource source{WorkSource::useful_compute};
    ContractVisibility visibility{ContractVisibility::hidden_semantics};

    // Integer normalized units; calibration is deliberately external.
    std::uint64_t normalized_work{};
    std::string work_class;

    // Current block/job/challenge or equivalent subject.
    Digest512 subject_binding{};

    // Accepted proof/certificate/result commitment. This wrapper does not claim
    // that the evidence itself is sound; that remains the verifier's job.
    Digest512 evidence_binding{};

    // Exact execution identity. For synchronized modules use the canonical
    // shared module-set digest. For built-in/default stacks or user Turing
    // machines use a canonical SHA3-512 identity of that executable/profile.
    // Plain PoW may leave this zero when no module/algorithm identity applies.
    Digest512 execution_binding{};

    // Optional binding to the series-first whole-stack context. Useful-compute
    // claims should normally populate it. Generic mining may leave it zero.
    Digest512 series_stack_binding{};
};

struct PayoutPrimitive {
    std::string protocol_id{"v0id-payout-primitive-v1"};
    WorkSource source{WorkSource::useful_compute};
    TokenFlavor flavor{TokenFlavor::invariant};

    // All payout leaves derived from one accepted event share work_event_id.
    // This lets a future ledger prevent accidental double-accounting even when
    // it exposes multiple representations or parallel reward classes.
    Digest512 work_event_id{};

    // Identifies the fungibility class. Independent and combo denominations bind
    // execution identity; invariant intentionally does not.
    Digest512 denomination_id{};

    // Unique identity of this event/flavor leaf.
    Digest512 payout_id{};

    std::uint64_t normalized_work{};
    std::string work_class;
    Digest512 execution_binding{};
};

// Canonical SHA3-512 identities. OpenSSL supplies SHA3; no custom hash primitive
// is introduced by the coin wrapper.
Digest512 work_event_id512(const WorkEvent& event);
Digest512 denomination_id512(const WorkEvent& event, TokenFlavor flavor);
PayoutPrimitive derive_payout_primitive(const WorkEvent& event,
                                        TokenFlavor flavor);

// Returns the three leaves for this event's source. Across both possible sources
// the protocol therefore forms the 2 x 3 mining/compute x I/V/C tree. This is a
// classification tree, not an issuance policy.
std::array<PayoutPrimitive, 3> derive_payout_branches(const WorkEvent& event);

std::string payout_symbol(WorkSource source, TokenFlavor flavor);
std::string to_string(WorkSource source);
std::string to_string(TokenFlavor flavor);
std::string digest_hex(const Digest512& digest);

} // namespace v0id::coin
