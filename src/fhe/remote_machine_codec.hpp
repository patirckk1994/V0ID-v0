#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <vector>

namespace v0id::fhe {

using ByteBlob = std::vector<std::uint8_t>;
using DigestBlob32 = std::array<ByteBlob, 32>;

struct PublicMachineShape {
    std::uint64_t states{};
    std::uint64_t tape_cells{};
    std::uint64_t rounds{};
    std::uint64_t integrity_slots{};
};

// Everything in this structure is evaluator-visible. Secret-key material and
// the client MorphManifest are intentionally absent.
struct RemoteMachineBundle {
    PublicMachineShape shape;

    ByteBlob context;
    ByteBlob refresh_key;
    ByteBlob switching_key;

    // One independently encrypted zero used only as an accumulator seed.
    ByteBlob encrypted_zero;

    // Canonical row layout: for each (state, read), next-state one-hot bits,
    // write bit, move-left/stay/right bits.
    std::vector<ByteBlob> program_bits;
    std::vector<ByteBlob> state_bits;
    std::vector<ByteBlob> head_bits;
    std::vector<ByteBlob> tape_bits;

    DigestBlob32 nonce_bits;
    DigestBlob32 fingerprint_initial_state_bits;
    std::vector<DigestBlob32> integrity_mask_bits;
};

struct RemoteMachineResult {
    PublicMachineShape shape;
    std::vector<ByteBlob> state_bits;
    std::vector<ByteBlob> head_bits;
    std::vector<ByteBlob> tape_bits;
    std::vector<DigestBlob32> integrity_candidates;
};

namespace remote_detail {

inline constexpr std::array<std::uint8_t, 8> JOB_MAGIC{
    'V','0','I','D','R','M','J','1'};
inline constexpr std::array<std::uint8_t, 8> RESULT_MAGIC{
    'V','0','I','D','R','M','R','1'};

inline constexpr std::uint64_t MAX_STATES = 128;
inline constexpr std::uint64_t MAX_TAPE_CELLS = 65536;
inline constexpr std::uint64_t MAX_ROUNDS = 1000000;
inline constexpr std::uint64_t MAX_INTEGRITY_SLOTS = 1024;
inline constexpr std::uint64_t MAX_BLOB_BYTES = 512ull * 1024ull * 1024ull;
inline constexpr std::uint64_t MAX_WIRE_BYTES = 2ull * 1024ull * 1024ull * 1024ull;

inline void validate_shape(const PublicMachineShape& shape) {
    if (shape.states == 0 || shape.states > MAX_STATES)
        throw std::runtime_error("remote machine state count outside limit");
    if (shape.tape_cells == 0 || shape.tape_cells > MAX_TAPE_CELLS)
        throw std::runtime_error("remote machine tape size outside limit");
    if (shape.rounds > MAX_ROUNDS)
        throw std::runtime_error("remote machine round budget outside limit");
    if (shape.integrity_slots == 0 || shape.integrity_slots > MAX_INTEGRITY_SLOTS)
        throw std::runtime_error("remote machine integrity slot count outside limit");
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

template <std::size_t N>
inline void append_blob_array(ByteBlob& out, const std::array<ByteBlob, N>& array) {
    for (const auto& blob : array)
        append_blob(out, blob);
}

template <std::size_t N>
inline std::array<ByteBlob, N> read_blob_array(const std::uint8_t*& p,
                                                const std::uint8_t* end) {
    std::array<ByteBlob, N> out;
    for (auto& blob : out)
        blob = read_blob(p, end);
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

inline ByteBlob pack_remote_machine_bundle(const RemoteMachineBundle& bundle) {
    using namespace remote_detail;
    validate_shape(bundle.shape);

    require_exact_size(bundle.program_bits.size(), program_bit_count(bundle.shape),
                       "wrong encrypted program bit count");
    require_exact_size(bundle.state_bits.size(), checked_size(bundle.shape.states, "state count overflow"),
                       "wrong encrypted state bit count");
    require_exact_size(bundle.head_bits.size(), checked_size(bundle.shape.tape_cells, "head count overflow"),
                       "wrong encrypted head bit count");
    require_exact_size(bundle.tape_bits.size(), checked_size(bundle.shape.tape_cells, "tape count overflow"),
                       "wrong encrypted tape bit count");
    require_exact_size(bundle.integrity_mask_bits.size(),
                       checked_size(bundle.shape.integrity_slots, "integrity slot count overflow"),
                       "wrong encrypted integrity mask count");

    ByteBlob out;
    out.insert(out.end(), JOB_MAGIC.begin(), JOB_MAGIC.end());
    put_shape(out, bundle.shape);

    append_blob(out, bundle.context);
    append_blob(out, bundle.refresh_key);
    append_blob(out, bundle.switching_key);
    append_blob(out, bundle.encrypted_zero);

    for (const auto& blob : bundle.program_bits) append_blob(out, blob);
    for (const auto& blob : bundle.state_bits) append_blob(out, blob);
    for (const auto& blob : bundle.head_bits) append_blob(out, blob);
    for (const auto& blob : bundle.tape_bits) append_blob(out, blob);
    append_blob_array(out, bundle.nonce_bits);
    append_blob_array(out, bundle.fingerprint_initial_state_bits);
    for (const auto& mask : bundle.integrity_mask_bits)
        append_blob_array(out, mask);

    return out;
}

inline RemoteMachineBundle unpack_remote_machine_bundle(const ByteBlob& wire) {
    using namespace remote_detail;
    if (wire.size() > MAX_WIRE_BYTES)
        throw std::runtime_error("V0ID remote machine wire payload exceeds limit");
    if (wire.size() < JOB_MAGIC.size() + 4 * sizeof(std::uint64_t))
        throw std::runtime_error("V0ID remote machine bundle too short");

    const auto* p = wire.data();
    const auto* end = p + wire.size();
    require_magic(p, end, JOB_MAGIC);

    RemoteMachineBundle bundle;
    bundle.shape = get_shape(p, end);
    bundle.context = read_blob(p, end);
    bundle.refresh_key = read_blob(p, end);
    bundle.switching_key = read_blob(p, end);
    bundle.encrypted_zero = read_blob(p, end);

    bundle.program_bits.resize(program_bit_count(bundle.shape));
    for (auto& blob : bundle.program_bits) blob = read_blob(p, end);

    bundle.state_bits.resize(checked_size(bundle.shape.states, "state count overflow"));
    for (auto& blob : bundle.state_bits) blob = read_blob(p, end);

    bundle.head_bits.resize(checked_size(bundle.shape.tape_cells, "head count overflow"));
    for (auto& blob : bundle.head_bits) blob = read_blob(p, end);

    bundle.tape_bits.resize(checked_size(bundle.shape.tape_cells, "tape count overflow"));
    for (auto& blob : bundle.tape_bits) blob = read_blob(p, end);

    bundle.nonce_bits = read_blob_array<32>(p, end);
    bundle.fingerprint_initial_state_bits = read_blob_array<32>(p, end);

    bundle.integrity_mask_bits.resize(
        checked_size(bundle.shape.integrity_slots, "integrity slot count overflow"));
    for (auto& mask : bundle.integrity_mask_bits)
        mask = read_blob_array<32>(p, end);

    if (p != end)
        throw std::runtime_error("trailing bytes in V0ID remote machine bundle");
    return bundle;
}

inline ByteBlob pack_remote_machine_result(const RemoteMachineResult& result) {
    using namespace remote_detail;
    validate_shape(result.shape);
    require_exact_size(result.state_bits.size(), checked_size(result.shape.states, "state count overflow"),
                       "wrong result state bit count");
    require_exact_size(result.head_bits.size(), checked_size(result.shape.tape_cells, "head count overflow"),
                       "wrong result head bit count");
    require_exact_size(result.tape_bits.size(), checked_size(result.shape.tape_cells, "tape count overflow"),
                       "wrong result tape bit count");
    require_exact_size(result.integrity_candidates.size(),
                       checked_size(result.shape.integrity_slots, "integrity slot count overflow"),
                       "wrong result integrity candidate count");

    ByteBlob out;
    out.insert(out.end(), RESULT_MAGIC.begin(), RESULT_MAGIC.end());
    put_shape(out, result.shape);
    for (const auto& blob : result.state_bits) append_blob(out, blob);
    for (const auto& blob : result.head_bits) append_blob(out, blob);
    for (const auto& blob : result.tape_bits) append_blob(out, blob);
    for (const auto& candidate : result.integrity_candidates)
        append_blob_array(out, candidate);
    return out;
}

inline RemoteMachineResult unpack_remote_machine_result(const ByteBlob& wire) {
    using namespace remote_detail;
    if (wire.size() > MAX_WIRE_BYTES)
        throw std::runtime_error("V0ID remote machine result exceeds limit");
    if (wire.size() < RESULT_MAGIC.size() + 4 * sizeof(std::uint64_t))
        throw std::runtime_error("V0ID remote machine result too short");

    const auto* p = wire.data();
    const auto* end = p + wire.size();
    require_magic(p, end, RESULT_MAGIC);

    RemoteMachineResult result;
    result.shape = get_shape(p, end);

    result.state_bits.resize(checked_size(result.shape.states, "state count overflow"));
    for (auto& blob : result.state_bits) blob = read_blob(p, end);

    result.head_bits.resize(checked_size(result.shape.tape_cells, "head count overflow"));
    for (auto& blob : result.head_bits) blob = read_blob(p, end);

    result.tape_bits.resize(checked_size(result.shape.tape_cells, "tape count overflow"));
    for (auto& blob : result.tape_bits) blob = read_blob(p, end);

    result.integrity_candidates.resize(
        checked_size(result.shape.integrity_slots, "integrity slot count overflow"));
    for (auto& candidate : result.integrity_candidates)
        candidate = read_blob_array<32>(p, end);

    if (p != end)
        throw std::runtime_error("trailing bytes in V0ID remote machine result");
    return result;
}

} // namespace v0id::fhe
