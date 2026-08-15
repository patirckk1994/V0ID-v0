#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

namespace v0id::fhe {

using ByteBlob = std::vector<std::uint8_t>;
using EvaluatorSessionId = std::array<std::uint8_t, 32>;

struct PublicMachineShape {
    std::uint64_t states{};
    std::uint64_t tape_cells{};
    std::uint64_t rounds{};

    // Reserved public capacity for future execution-bound integrity material.
    // Zero is valid. RMJ4/RMR4 carry no ToyFingerprint candidate bank.
    std::uint64_t integrity_slots{};
};

struct CryptoProfileId {
    std::string primitive_id;
    std::string parameter_set;
    std::string machine_protocol;
    std::string integrity_profile;
    std::string series_generator_id;
    std::uint64_t series_generator_version{};

    bool operator==(const CryptoProfileId&) const = default;
};

struct EvaluatorSessionBundle {
    EvaluatorSessionId session_id{};
    std::string primitive_id;
    std::string parameter_set;
    ByteBlob context;
    ByteBlob refresh_key;
    ByteBlob switching_key;
};

// RMJ4 contains only evaluator-visible encrypted machine state. The obsolete
// ToyFingerprint nonce/initial-state/mask fields were removed rather than kept
// as dummy wire baggage.
struct RemoteMachineBundle {
    EvaluatorSessionId session_id{};
    PublicMachineShape shape;
    CryptoProfileId profile;

    ByteBlob encrypted_zero;
    std::vector<ByteBlob> program_bits;
    std::vector<ByteBlob> state_bits;
    std::vector<ByteBlob> head_bits;
    std::vector<ByteBlob> tape_bits;
};

struct RemoteMachineResult {
    EvaluatorSessionId session_id{};
    PublicMachineShape shape;
    CryptoProfileId profile;
    std::vector<ByteBlob> state_bits;
    std::vector<ByteBlob> head_bits;
    std::vector<ByteBlob> tape_bits;
};

namespace remote_detail {

inline constexpr std::array<std::uint8_t, 8> SESSION_MAGIC{
    'V','0','I','D','R','M','S','3'};
inline constexpr std::array<std::uint8_t, 8> JOB_MAGIC{
    'V','0','I','D','R','M','J','4'};
inline constexpr std::array<std::uint8_t, 8> RESULT_MAGIC{
    'V','0','I','D','R','M','R','4'};

inline constexpr std::uint64_t MAX_STATES = 128;
inline constexpr std::uint64_t MAX_TAPE_CELLS = 65536;
inline constexpr std::uint64_t MAX_ROUNDS = 1000000;
inline constexpr std::uint64_t MAX_INTEGRITY_SLOTS = 1024;
inline constexpr std::uint64_t MAX_PROFILE_FIELD_BYTES = 96;
inline constexpr std::uint64_t MAX_BLOB_BYTES = 512ull * 1024ull * 1024ull;
inline constexpr std::uint64_t MAX_WIRE_BYTES = 2ull * 1024ull * 1024ull * 1024ull;

inline void validate_shape(const PublicMachineShape& shape) {
    if (shape.states == 0 || shape.states > MAX_STATES)
        throw std::runtime_error("remote machine state count outside limit");
    if (shape.tape_cells == 0 || shape.tape_cells > MAX_TAPE_CELLS)
        throw std::runtime_error("remote machine tape size outside limit");
    if (shape.rounds > MAX_ROUNDS)
        throw std::runtime_error("remote machine round budget outside limit");
    if (shape.integrity_slots > MAX_INTEGRITY_SLOTS)
        throw std::runtime_error("remote machine integrity slot capacity outside limit");
}

inline void validate_profile_field(const std::string& value, const char* what) {
    if (value.empty())
        throw std::runtime_error(std::string(what) + " must not be empty");
    if (value.size() > MAX_PROFILE_FIELD_BYTES)
        throw std::runtime_error(std::string(what) + " exceeds protocol limit");
}

inline void validate_profile(const CryptoProfileId& profile) {
    validate_profile_field(profile.primitive_id, "primitive id");
    validate_profile_field(profile.parameter_set, "parameter set");
    validate_profile_field(profile.machine_protocol, "machine protocol");
    validate_profile_field(profile.integrity_profile, "integrity profile");
    validate_profile_field(profile.series_generator_id, "series generator id");
    if (profile.series_generator_version == 0)
        throw std::runtime_error("series generator version must be positive");
}

inline void validate_session_id(const EvaluatorSessionId& session_id) {
    if (std::all_of(session_id.begin(), session_id.end(),
                    [](std::uint8_t b) { return b == 0; }))
        throw std::runtime_error("evaluator session id must not be all zero");
}

inline void validate_session_bundle(const EvaluatorSessionBundle& bundle) {
    validate_session_id(bundle.session_id);
    validate_profile_field(bundle.primitive_id, "evaluator primitive id");
    validate_profile_field(bundle.parameter_set, "evaluator parameter set");
    if (bundle.context.empty())
        throw std::runtime_error("evaluator session context must not be empty");
    if (bundle.refresh_key.empty())
        throw std::runtime_error("evaluator session refresh key must not be empty");
    if (bundle.switching_key.empty())
        throw std::runtime_error("evaluator session switching key must not be empty");
}

inline std::size_t checked_size(std::uint64_t value, const char* what) {
    if (value > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
        throw std::runtime_error(what);
    return static_cast<std::size_t>(value);
}

inline std::size_t program_bit_count(const PublicMachineShape& shape) {
    validate_shape(shape);
    const auto count = shape.states * 2ull * (shape.states + 4ull);
    return checked_size(count, "remote machine program bit count overflow");
}

inline void put_u64(ByteBlob& out, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8)
        out.push_back(static_cast<std::uint8_t>((value >> shift) & 0xffu));
}

inline std::uint64_t get_u64(const std::uint8_t*& p, const std::uint8_t* end) {
    if (end - p < 8)
        throw std::runtime_error("truncated V0ID remote machine bundle");
    std::uint64_t value = 0;
    for (int i = 0; i < 8; ++i)
        value = (value << 8) | p[i];
    p += 8;
    return value;
}

inline void put_session_id(ByteBlob& out, const EvaluatorSessionId& session_id) {
    validate_session_id(session_id);
    out.insert(out.end(), session_id.begin(), session_id.end());
}

inline EvaluatorSessionId get_session_id(const std::uint8_t*& p,
                                         const std::uint8_t* end) {
    if (end - p < static_cast<std::ptrdiff_t>(EvaluatorSessionId{}.size()))
        throw std::runtime_error("truncated evaluator session id");
    EvaluatorSessionId session_id{};
    std::copy_n(p, session_id.size(), session_id.begin());
    p += session_id.size();
    validate_session_id(session_id);
    return session_id;
}

inline void put_shape(ByteBlob& out, const PublicMachineShape& shape) {
    validate_shape(shape);
    put_u64(out, shape.states);
    put_u64(out, shape.tape_cells);
    put_u64(out, shape.rounds);
    put_u64(out, shape.integrity_slots);
}

inline PublicMachineShape get_shape(const std::uint8_t*& p, const std::uint8_t* end) {
    PublicMachineShape shape;
    shape.states = get_u64(p, end);
    shape.tape_cells = get_u64(p, end);
    shape.rounds = get_u64(p, end);
    shape.integrity_slots = get_u64(p, end);
    validate_shape(shape);
    return shape;
}

inline void put_string(ByteBlob& out, const std::string& value, const char* what) {
    validate_profile_field(value, what);
    put_u64(out, static_cast<std::uint64_t>(value.size()));
    out.insert(out.end(), value.begin(), value.end());
}

inline std::string get_string(const std::uint8_t*& p,
                              const std::uint8_t* end,
                              const char* what) {
    const auto size = get_u64(p, end);
    if (size == 0 || size > MAX_PROFILE_FIELD_BYTES)
        throw std::runtime_error(std::string("invalid ") + what + " length");
    if (size > static_cast<std::uint64_t>(end - p))
        throw std::runtime_error(std::string("truncated ") + what);
    const auto n = checked_size(size, "profile string size overflow");
    std::string out(reinterpret_cast<const char*>(p), n);
    p += n;
    return out;
}

inline void put_profile(ByteBlob& out, const CryptoProfileId& profile) {
    validate_profile(profile);
    put_string(out, profile.primitive_id, "primitive id");
    put_string(out, profile.parameter_set, "parameter set");
    put_string(out, profile.machine_protocol, "machine protocol");
    put_string(out, profile.integrity_profile, "integrity profile");
    put_string(out, profile.series_generator_id, "series generator id");
    put_u64(out, profile.series_generator_version);
}

inline CryptoProfileId get_profile(const std::uint8_t*& p, const std::uint8_t* end) {
    CryptoProfileId profile;
    profile.primitive_id = get_string(p, end, "primitive id");
    profile.parameter_set = get_string(p, end, "parameter set");
    profile.machine_protocol = get_string(p, end, "machine protocol");
    profile.integrity_profile = get_string(p, end, "integrity profile");
    profile.series_generator_id = get_string(p, end, "series generator id");
    profile.series_generator_version = get_u64(p, end);
    validate_profile(profile);
    return profile;
}

inline void append_blob(ByteBlob& out, const ByteBlob& blob) {
    if (blob.size() > MAX_BLOB_BYTES)
        throw std::runtime_error("V0ID remote machine blob exceeds limit");
    put_u64(out, static_cast<std::uint64_t>(blob.size()));
    out.insert(out.end(), blob.begin(), blob.end());
    if (out.size() > MAX_WIRE_BYTES)
        throw std::runtime_error("V0ID remote machine wire payload exceeds limit");
}

inline ByteBlob read_blob(const std::uint8_t*& p, const std::uint8_t* end) {
    const auto size = get_u64(p, end);
    if (size > MAX_BLOB_BYTES)
        throw std::runtime_error("V0ID remote machine blob exceeds limit");
    const auto remaining = static_cast<std::uint64_t>(end - p);
    if (size > remaining)
        throw std::runtime_error("bad V0ID remote machine blob length");
    const auto n = checked_size(size, "V0ID remote machine blob size overflow");
    ByteBlob out(p, p + n);
    p += n;
    return out;
}

inline void require_magic(const std::uint8_t*& p,
                          const std::uint8_t* end,
                          const std::array<std::uint8_t, 8>& magic) {
    for (const auto expected : magic) {
        if (p == end || *p++ != expected)
            throw std::runtime_error("bad V0ID remote machine magic");
    }
}

inline void require_exact_size(std::size_t actual,
                               std::size_t expected,
                               const char* what) {
    if (actual != expected)
        throw std::runtime_error(what);
}

} // namespace remote_detail

inline ByteBlob pack_evaluator_session_bundle(const EvaluatorSessionBundle& bundle) {
    using namespace remote_detail;
    validate_session_bundle(bundle);

    ByteBlob out;
    out.insert(out.end(), SESSION_MAGIC.begin(), SESSION_MAGIC.end());
    put_session_id(out, bundle.session_id);
    put_string(out, bundle.primitive_id, "evaluator primitive id");
    put_string(out, bundle.parameter_set, "evaluator parameter set");
    append_blob(out, bundle.context);
    append_blob(out, bundle.refresh_key);
    append_blob(out, bundle.switching_key);
    return out;
}

inline EvaluatorSessionBundle unpack_evaluator_session_bundle(const ByteBlob& wire) {
    using namespace remote_detail;
    if (wire.size() > MAX_WIRE_BYTES)
        throw std::runtime_error("V0ID evaluator session payload exceeds limit");
    if (wire.size() < SESSION_MAGIC.size() + EvaluatorSessionId{}.size())
        throw std::runtime_error("V0ID evaluator session bundle too short");

    const auto* p = wire.data();
    const auto* end = p + wire.size();
    require_magic(p, end, SESSION_MAGIC);

    EvaluatorSessionBundle bundle;
    bundle.session_id = get_session_id(p, end);
    bundle.primitive_id = get_string(p, end, "evaluator primitive id");
    bundle.parameter_set = get_string(p, end, "evaluator parameter set");
    bundle.context = read_blob(p, end);
    bundle.refresh_key = read_blob(p, end);
    bundle.switching_key = read_blob(p, end);
    validate_session_bundle(bundle);

    if (p != end)
        throw std::runtime_error("trailing bytes in V0ID evaluator session bundle");
    return bundle;
}

inline ByteBlob pack_remote_machine_bundle(const RemoteMachineBundle& bundle) {
    using namespace remote_detail;
    validate_session_id(bundle.session_id);
    validate_shape(bundle.shape);
    validate_profile(bundle.profile);

    require_exact_size(bundle.program_bits.size(), program_bit_count(bundle.shape),
                       "wrong encrypted program bit count");
    require_exact_size(bundle.state_bits.size(),
                       checked_size(bundle.shape.states, "state count overflow"),
                       "wrong encrypted state bit count");
    require_exact_size(bundle.head_bits.size(),
                       checked_size(bundle.shape.tape_cells, "head count overflow"),
                       "wrong encrypted head bit count");
    require_exact_size(bundle.tape_bits.size(),
                       checked_size(bundle.shape.tape_cells, "tape count overflow"),
                       "wrong encrypted tape bit count");

    ByteBlob out;
    out.insert(out.end(), JOB_MAGIC.begin(), JOB_MAGIC.end());
    put_session_id(out, bundle.session_id);
    put_shape(out, bundle.shape);
    put_profile(out, bundle.profile);
    append_blob(out, bundle.encrypted_zero);
    for (const auto& blob : bundle.program_bits) append_blob(out, blob);
    for (const auto& blob : bundle.state_bits) append_blob(out, blob);
    for (const auto& blob : bundle.head_bits) append_blob(out, blob);
    for (const auto& blob : bundle.tape_bits) append_blob(out, blob);
    return out;
}

inline RemoteMachineBundle unpack_remote_machine_bundle(const ByteBlob& wire) {
    using namespace remote_detail;
    if (wire.size() > MAX_WIRE_BYTES)
        throw std::runtime_error("V0ID remote machine wire payload exceeds limit");
    if (wire.size() < JOB_MAGIC.size() + EvaluatorSessionId{}.size() +
                          4 * sizeof(std::uint64_t))
        throw std::runtime_error("V0ID remote machine bundle too short");

    const auto* p = wire.data();
    const auto* end = p + wire.size();
    require_magic(p, end, JOB_MAGIC);

    RemoteMachineBundle bundle;
    bundle.session_id = get_session_id(p, end);
    bundle.shape = get_shape(p, end);
    bundle.profile = get_profile(p, end);
    bundle.encrypted_zero = read_blob(p, end);

    bundle.program_bits.resize(program_bit_count(bundle.shape));
    for (auto& blob : bundle.program_bits) blob = read_blob(p, end);

    bundle.state_bits.resize(checked_size(bundle.shape.states, "state count overflow"));
    for (auto& blob : bundle.state_bits) blob = read_blob(p, end);

    bundle.head_bits.resize(checked_size(bundle.shape.tape_cells, "head count overflow"));
    for (auto& blob : bundle.head_bits) blob = read_blob(p, end);

    bundle.tape_bits.resize(checked_size(bundle.shape.tape_cells, "tape count overflow"));
    for (auto& blob : bundle.tape_bits) blob = read_blob(p, end);

    if (p != end)
        throw std::runtime_error("trailing bytes in V0ID remote machine bundle");
    return bundle;
}

inline ByteBlob pack_remote_machine_result(const RemoteMachineResult& result) {
    using namespace remote_detail;
    validate_session_id(result.session_id);
    validate_shape(result.shape);
    validate_profile(result.profile);
    require_exact_size(result.state_bits.size(),
                       checked_size(result.shape.states, "state count overflow"),
                       "wrong result state bit count");
    require_exact_size(result.head_bits.size(),
                       checked_size(result.shape.tape_cells, "head count overflow"),
                       "wrong result head bit count");
    require_exact_size(result.tape_bits.size(),
                       checked_size(result.shape.tape_cells, "tape count overflow"),
                       "wrong result tape bit count");

    ByteBlob out;
    out.insert(out.end(), RESULT_MAGIC.begin(), RESULT_MAGIC.end());
    put_session_id(out, result.session_id);
    put_shape(out, result.shape);
    put_profile(out, result.profile);
    for (const auto& blob : result.state_bits) append_blob(out, blob);
    for (const auto& blob : result.head_bits) append_blob(out, blob);
    for (const auto& blob : result.tape_bits) append_blob(out, blob);
    return out;
}

inline RemoteMachineResult unpack_remote_machine_result(const ByteBlob& wire) {
    using namespace remote_detail;
    if (wire.size() > MAX_WIRE_BYTES)
        throw std::runtime_error("V0ID remote machine result exceeds limit");
    if (wire.size() < RESULT_MAGIC.size() + EvaluatorSessionId{}.size() +
                          4 * sizeof(std::uint64_t))
        throw std::runtime_error("V0ID remote machine result too short");

    const auto* p = wire.data();
    const auto* end = p + wire.size();
    require_magic(p, end, RESULT_MAGIC);

    RemoteMachineResult result;
    result.session_id = get_session_id(p, end);
    result.shape = get_shape(p, end);
    result.profile = get_profile(p, end);

    result.state_bits.resize(checked_size(result.shape.states, "state count overflow"));
    for (auto& blob : result.state_bits) blob = read_blob(p, end);

    result.head_bits.resize(checked_size(result.shape.tape_cells, "head count overflow"));
    for (auto& blob : result.head_bits) blob = read_blob(p, end);

    result.tape_bits.resize(checked_size(result.shape.tape_cells, "tape count overflow"));
    for (auto& blob : result.tape_bits) blob = read_blob(p, end);

    if (p != end)
        throw std::runtime_error("trailing bytes in V0ID remote machine result");
    return result;
}

} // namespace v0id::fhe
