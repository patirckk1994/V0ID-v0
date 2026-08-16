#pragma once

#include "boolean_program_image.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <span>
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

inline constexpr std::size_t kTfheCudaInstructionChunkSize = 32;

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

// Trusted-client artifacts. The client key never belongs on the evaluator.
// The server key is installed once per evaluator session; encrypted_init_blob
// contains encrypted inputs/zero/output selectors but no instruction stream.
struct TfheCudaPreparedSession {
    std::vector<std::uint8_t> client_key_blob;
    std::vector<std::uint8_t> server_key_blob;
    std::vector<std::uint8_t> encrypted_init_blob;
    std::size_t instruction_count{};
    std::size_t output_word_count{};
};

bool tfhe_cuda_backend_available();

TfheCudaPreparedSession prepare_boolean_program_image_tfhe_cuda_client(
    const v0id::integrity::BooleanProgramImage& image,
    const std::vector<std::uint64_t>& input_words,
    GpuFheProgressCallback progress = {});

// Encrypt only one contiguous instruction range. start_instruction is bound
// into the encrypted chunk envelope; the evaluator rejects replay, reordering
// and gaps relative to its cached session progress.
std::vector<std::uint8_t> encrypt_boolean_program_chunk_tfhe_cuda_client(
    const std::vector<std::uint8_t>& client_key_blob,
    std::span<const v0id::integrity::BooleanProgramInstruction> instructions,
    std::size_t start_instruction,
    std::size_t total_instruction_count,
    GpuFheProgressCallback progress = {});

// Evaluator-owned cached session. It owns the GPU server key plus encrypted
// registers/inputs between chunks. The handle is process-local and deliberately
// opaque to callers; a network evaluator can map its own session id to this
// object without exposing a ClientKey.
class TfheCudaServerSession final {
public:
    TfheCudaServerSession(
        const std::vector<std::uint8_t>& server_key_blob,
        const std::vector<std::uint8_t>& encrypted_init_blob);
    ~TfheCudaServerSession();

    TfheCudaServerSession(const TfheCudaServerSession&) = delete;
    TfheCudaServerSession& operator=(const TfheCudaServerSession&) = delete;
    TfheCudaServerSession(TfheCudaServerSession&& other) noexcept;
    TfheCudaServerSession& operator=(TfheCudaServerSession&& other) noexcept;

    void evaluate_chunk(
        const std::vector<std::uint8_t>& encrypted_chunk_blob,
        GpuFheProgressCallback progress = {});

    std::vector<std::uint8_t> finish(
        GpuFheProgressCallback progress = {});

private:
    void* handle_{};
};

std::vector<std::uint64_t> decrypt_boolean_program_image_tfhe_cuda_client(
    const std::vector<std::uint8_t>& client_key_blob,
    const std::vector<std::uint8_t>& encrypted_result_blob,
    std::size_t expected_instruction_count,
    std::size_t expected_output_word_count);

// Local differential/stress wrapper around the same streamed seam that a
// future ZeroMQ client/evaluator will use: prepare once, cache server state,
// encrypt/send bounded chunks, finish, decrypt locally.
std::vector<std::uint64_t> evaluate_boolean_program_image_tfhe_cuda(
    const v0id::integrity::BooleanProgramImage& image,
    const std::vector<std::uint64_t>& input_words,
    GpuFheProgressCallback progress = {});

} // namespace v0id::fhe
