#pragma once

namespace v0id::fhe {

// Compile-time hook for a future CUDA/TFHE-rs execution backend.
//
// Define V0ID_GPU_FHE_ENABLED when building to request the GPU path. Until the
// CUDA adapter is implemented, RemoteEncryptedBooleanProgram remains the
// OpenFHE/BinFHE CPU reference evaluator. Keeping the distinction explicit
// prevents a build flag from silently claiming GPU execution that is not wired.
#ifdef V0ID_GPU_FHE_ENABLED
inline constexpr bool kGpuFheCompileRequested = true;
inline constexpr const char* kRequestedFheBackendName = "TFHE-CUDA (adapter pending)";
inline constexpr const char* kActiveFheBackendName = "OpenFHE BinFHE CPU reference";
#else
inline constexpr bool kGpuFheCompileRequested = false;
inline constexpr const char* kRequestedFheBackendName = "OpenFHE BinFHE CPU";
inline constexpr const char* kActiveFheBackendName = "OpenFHE BinFHE CPU reference";
#endif

} // namespace v0id::fhe
