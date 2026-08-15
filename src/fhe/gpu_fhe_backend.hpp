#pragma once

#include "boolean_program_image.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <vector>

namespace v0id::fhe {

#ifdef V0ID_GPU_FHE_ENABLED
inline constexpr bool kGpuFheCompileRequested = true;
inline constexpr const char* kRequestedFheBackendName = "TFHE-rs CUDA";
inline constexpr const char* kActiveFheBackendName = "TFHE-rs CUDA";
#else
inline constexpr bool kGpuFheCompileRequested = false;
inline constexpr const char* kRequestedFheBackendName = "OpenFHE BinFHE CPU";
inline constexpr const char* kActiveFheBackendName = "OpenFHE BinFHE CPU reference";
#endif

enum class GpuFheProgressStage : std::uint32_t {
    KeyGeneration = 1,
    ClientEncryption = 2,
    Execution = 3,
    OutputSelection = 4,
};

using GpuFheProgressCallback = std::function<void(
    GpuFheProgressStage stage,
    std::size_t current,
    std::size_t total)>;

// Serialized artifacts produced on the trusted client side. client_key_blob is
// private and must never be sent to the evaluator. server_key_blob and
// encrypted_job_blob are the evaluator-facing cloud payloads.
struct TfheCudaPreparedJob {
    std::vector<std::uint8_t> client_key_blob;
    std::vector<std::uint8_t> server_key_blob;
    std::vector<std::uint8_t> encrypted_job_blob;
    std::size_t output_word_count{};
};

// True only in builds linked against the Rust TFHE-rs CUDA sidecar.
bool tfhe_cuda_backend_available();

// Trusted client boundary: key generation plus encryption/serialization of the
// compact Boolean program image and inputs. The returned ClientKey blob remains
// client-only; only server_key_blob + encrypted_job_blob belong on the wire.
TfheCudaPreparedJob prepare_boolean_program_image_tfhe_cuda_client(
    const v0id::integrity::BooleanProgramImage& image,
    const std::vector<std::uint64_t>& input_words,
    GpuFheProgressCallback progress = {});

// Untrusted evaluator boundary: accepts no client key and no plaintext program.
// It deserializes the compressed TFHE server key and encrypted job, executes the
// fixed-path VM under CUDA, and returns only an encrypted serialized result.
std::vector<std::uint8_t> evaluate_boolean_program_image_tfhe_cuda_server(
    const std::vector<std::uint8_t>& server_key_blob,
    const std::vector<std::uint8_t>& encrypted_job_blob,
    GpuFheProgressCallback progress = {});

// Trusted client boundary: decrypt a serialized evaluator result with the
// client-only key blob. expected_output_word_count is public shape metadata and
// prevents accepting a result with a silently different output cardinality.
std::vector<std::uint64_t> decrypt_boolean_program_image_tfhe_cuda_client(
    const std::vector<std::uint8_t>& client_key_blob,
    const std::vector<std::uint8_t>& encrypted_result_blob,
    std::size_t expected_output_word_count);

// Convenience differential/stress wrapper. It now exercises the exact same
// serialized client -> evaluator -> client seam above in one process. No secret
// key enters evaluate_boolean_program_image_tfhe_cuda_server(). Moving the two
// evaluator-facing blobs over ZeroMQ is therefore a transport step, not a new
// cryptographic execution path.
std::vector<std::uint64_t> evaluate_boolean_program_image_tfhe_cuda(
    const v0id::integrity::BooleanProgramImage& image,
    const std::vector<std::uint64_t>& input_words,
    GpuFheProgressCallback progress = {});

} // namespace v0id::fhe
