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
    InputEncryption = 2,
    Execution = 3,
    OutputSelection = 4,
};

using GpuFheProgressCallback = std::function<void(
    GpuFheProgressStage stage,
    std::size_t current,
    std::size_t total)>;

// True only in builds linked against the Rust TFHE-rs CUDA sidecar.
bool tfhe_cuda_backend_available();

// Local differential/stress harness boundary for the compact private program
// image. The C++ side passes the trusted plaintext image to the Rust sidecar;
// the sidecar encrypts every opcode/register/index/immediate field before the
// CUDA evaluator touches it. Production remote transport will later split key
// generation/encryption from evaluation and serialize the encrypted image.
std::vector<std::uint64_t> evaluate_boolean_program_image_tfhe_cuda(
    const v0id::integrity::BooleanProgramImage& image,
    const std::vector<std::uint64_t>& input_words,
    GpuFheProgressCallback progress = {});

} // namespace v0id::fhe
