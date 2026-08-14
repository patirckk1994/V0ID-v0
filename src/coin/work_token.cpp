#include "work_token.hpp"

#include <openssl/evp.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace v0id::coin {
namespace {

void append_u64(std::vector<std::uint8_t>& out, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8)
        out.push_back(static_cast<std::uint8_t>((value >> shift) & 0xffu));
}

void append_blob(std::vector<std::uint8_t>& out,
                 const std::uint8_t* data,
                 std::size_t size) {
    append_u64(out, static_cast<std::uint64_t>(size));
    if (size != 0)
        out.insert(out.end(), data, data + size);
}

void append_string(std::vector<std::uint8_t>& out, std::string_view value) {
    append_blob(out,
                reinterpret_cast<const std::uint8_t*>(value.data()),
                value.size());
}

bool all_zero(const Digest512& digest) {
    return std::all_of(digest.begin(), digest.end(),
                       [](std::uint8_t b) { return b == 0; });
}

Digest512 sha3_512(const std::vector<std::uint8_t>& bytes) {
    EVP_MD* md = EVP_MD_fetch(nullptr, "SHA3-512", nullptr);
    if (!md)
        throw std::runtime_error("OpenSSL SHA3-512 unavailable for work-token wrapper");
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        EVP_MD_free(md);
        throw std::runtime_error("EVP_MD_CTX_new failed");
    }

    Digest512 out{};
    unsigned int written = 0;
    const bool ok =
        EVP_DigestInit_ex2(ctx, md, nullptr) == 1 &&
        EVP_DigestUpdate(ctx, bytes.data(), bytes.size()) == 1 &&
        EVP_DigestFinal_ex(ctx, out.data(), &written) == 1;
    EVP_MD_CTX_free(ctx);
    EVP_MD_free(md);

    if (!ok || written != out.size())
        throw std::runtime_error("OpenSSL SHA3-512 work-token digest failed");
    return out;
}

void append_digest(std::vector<std::uint8_t>& out, const Digest512& digest) {
    append_blob(out, digest.data(), digest.size());
}

void validate_event(const WorkEvent& event) {
    if (event.protocol_id != "v0id-work-event-v1")
        throw std::runtime_error("unsupported V0ID work-event protocol");
    if (event.mining_work == 0 && event.compute_complexity == 0)
        throw std::runtime_error("work event contains no mining or compute work");
    if (event.work_class.empty()) {
        // Kept below as source-specific classes; this branch intentionally does
        // not exist. The comment prevents future accidental reintroduction of a
        // single class that would collapse mining and compute semantics.
    }
    if (all_zero(event.subject_binding) || all_zero(event.evidence_binding))
        throw std::runtime_error("work event requires subject/evidence bindings");

    if (event.mining_work != 0) {
        if (event.mining_class.empty())
            throw std::runtime_error("mining work requires mining class");
        if (all_zero(event.mining_binding))
            throw std::runtime_error("mining work requires mining algorithm/profile binding");
    }

    if (event.compute_complexity != 0) {
        if (event.compute_class.empty())
            throw std::runtime_error("compute work requires compute class");
        if (all_zero(event.execution_binding))
            throw std::runtime_error("compute work requires execution binding");
        if (event.visibility == ContractVisibility::not_applicable)
            throw std::runtime_error("compute work requires public/hidden visibility classification");
    }
}

void validate_leaf(const WorkEvent& event,
                   PayoutAxis axis,
                   TokenFlavor flavor) {
    validate_event(event);
    if (axis == PayoutAxis::mining && event.mining_work == 0)
        throw std::runtime_error("mining payout requested for event with no mining work");
    if (axis == PayoutAxis::compute && event.compute_complexity == 0)
        throw std::runtime_error("compute payout requested for event with no compute work");
    if (flavor == TokenFlavor::combo &&
        (event.mining_work == 0 || event.compute_complexity == 0))
        throw std::runtime_error("combo payout requires a hybrid mining+compute event");
}

} // namespace

Digest512 work_event_id512(const WorkEvent& event) {
    validate_event(event);

    std::vector<std::uint8_t> canonical;
    append_string(canonical, "V0ID-WORK-EVENT-ID-v1");
    append_string(canonical, event.protocol_id);
    canonical.push_back(static_cast<std::uint8_t>(event.visibility));
    append_u64(canonical, event.mining_work);
    append_u64(canonical, event.compute_complexity);
    append_string(canonical, event.mining_class);
    append_string(canonical, event.compute_class);
    append_digest(canonical, event.subject_binding);
    append_digest(canonical, event.evidence_binding);
    append_digest(canonical, event.mining_binding);
    append_digest(canonical, event.execution_binding);
    append_digest(canonical, event.series_stack_binding);
    return sha3_512(canonical);
}

Digest512 denomination_id512(const WorkEvent& event,
                             PayoutAxis axis,
                             TokenFlavor flavor) {
    validate_leaf(event, axis, flavor);

    std::vector<std::uint8_t> canonical;
    append_string(canonical, "V0ID-PAYOUT-DENOMINATION-v1");
    canonical.push_back(static_cast<std::uint8_t>(axis));
    canonical.push_back(static_cast<std::uint8_t>(flavor));

    if (flavor == TokenFlavor::independent) {
        if (axis == PayoutAxis::mining) {
            append_string(canonical, event.mining_class);
            append_digest(canonical, event.mining_binding);
        } else {
            append_string(canonical, event.compute_class);
            append_digest(canonical, event.execution_binding);
        }
    } else if (flavor == TokenFlavor::invariant) {
        if (axis == PayoutAxis::mining)
            append_string(canonical, event.mining_class);
        else
            append_string(canonical, event.compute_class);
    } else if (flavor == TokenFlavor::combo) {
        // Combo deliberately carries both identities/classes while keeping the
        // axis label. MC and CC can therefore have distinct market/payout policy
        // without inventing a conversion rate inside the cryptographic wrapper.
        append_string(canonical, event.mining_class);
        append_string(canonical, event.compute_class);
        append_digest(canonical, event.mining_binding);
        append_digest(canonical, event.execution_binding);
    } else {
        throw std::runtime_error("unknown payout token flavor");
    }

    return sha3_512(canonical);
}

PayoutPrimitive derive_payout_primitive(const WorkEvent& event,
                                        PayoutAxis axis,
                                        TokenFlavor flavor) {
    validate_leaf(event, axis, flavor);

    PayoutPrimitive out;
    out.axis = axis;
    out.flavor = flavor;
    out.work_event_id = work_event_id512(event);
    out.denomination_id = denomination_id512(event, axis, flavor);
    out.mining_work = event.mining_work;
    out.compute_complexity = event.compute_complexity;
    out.mining_class = event.mining_class;
    out.compute_class = event.compute_class;
    out.mining_binding = event.mining_binding;
    out.execution_binding = event.execution_binding;

    std::vector<std::uint8_t> canonical;
    append_string(canonical, "V0ID-PAYOUT-ID-v1");
    append_digest(canonical, out.work_event_id);
    append_digest(canonical, out.denomination_id);
    canonical.push_back(static_cast<std::uint8_t>(axis));
    canonical.push_back(static_cast<std::uint8_t>(flavor));
    out.payout_id = sha3_512(canonical);
    return out;
}

std::vector<PayoutPrimitive> derive_available_payout_branches(
    const WorkEvent& event) {
    validate_event(event);

    std::vector<PayoutPrimitive> out;
    out.reserve(6);

    if (event.mining_work != 0) {
        out.push_back(derive_payout_primitive(
            event, PayoutAxis::mining, TokenFlavor::independent));
        out.push_back(derive_payout_primitive(
            event, PayoutAxis::mining, TokenFlavor::invariant));
        if (event.compute_complexity != 0)
            out.push_back(derive_payout_primitive(
                event, PayoutAxis::mining, TokenFlavor::combo));
    }

    if (event.compute_complexity != 0) {
        out.push_back(derive_payout_primitive(
            event, PayoutAxis::compute, TokenFlavor::independent));
        out.push_back(derive_payout_primitive(
            event, PayoutAxis::compute, TokenFlavor::invariant));
        if (event.mining_work != 0)
            out.push_back(derive_payout_primitive(
                event, PayoutAxis::compute, TokenFlavor::combo));
    }

    return out;
}

std::string payout_symbol(PayoutAxis axis, TokenFlavor flavor) {
    const char a = axis == PayoutAxis::mining ? 'M' : 'C';
    char f = '?';
    switch (flavor) {
        case TokenFlavor::independent: f = 'I'; break;
        case TokenFlavor::invariant: f = 'V'; break;
        case TokenFlavor::combo: f = 'C'; break;
    }
    if (f == '?')
        throw std::runtime_error("unknown payout token flavor");
    return std::string("V0ID-") + a + f;
}

std::string to_string(PayoutAxis axis) {
    switch (axis) {
        case PayoutAxis::mining: return "MINING";
        case PayoutAxis::compute: return "COMPUTE";
    }
    return "UNKNOWN_AXIS";
}

std::string to_string(TokenFlavor flavor) {
    switch (flavor) {
        case TokenFlavor::independent: return "INDEPENDENT";
        case TokenFlavor::invariant: return "INVARIANT";
        case TokenFlavor::combo: return "COMBO";
    }
    return "UNKNOWN_FLAVOR";
}

std::string digest_hex(const Digest512& digest) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (const auto b : digest)
        oss << std::setw(2) << static_cast<unsigned>(b);
    return oss.str();
}

} // namespace v0id::coin
