#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace v0id::mathvm {

// ABI v2 is additive: primitive_u64 remains valid and primitive_bytes adds
// bounded byte-buffer providers for hashes, KEM ciphertexts, polynomial blobs,
// and other non-scalar cryptographic values.
inline constexpr std::uint32_t MATHVM_ABI_VERSION = 2;

// Stable numeric tags used by the generic Wasm host imports. They are protocol
// identifiers, not security values. The textual id remains the canonical name
// used in manifests/logging and later capability negotiation.
inline constexpr std::uint64_t PRIMITIVE_ADD_MOD_U64 = 0x0001'0001ull;
inline constexpr std::uint64_t PRIMITIVE_MUL_MOD_U64 = 0x0001'0002ull;
inline constexpr std::uint64_t PRIMITIVE_SHA3_256_BYTES = 0x0002'0001ull;
inline constexpr std::uint64_t PRIMITIVE_ML_KEM_768_ENCAP_BYTES = 0x0003'0301ull;
inline constexpr std::uint64_t PRIMITIVE_TOY_LWE_AFFINE_U64 = 0x7fff'0001ull;

enum class PrimitiveAbi : std::uint8_t {
    u64 = 1,
    bytes = 2,
};

struct PrimitiveDescriptor {
    std::uint64_t tag{};
    std::string id;
    std::uint32_t version{};
    std::uint64_t cost{};
    bool experimental{};
    PrimitiveAbi abi{PrimitiveAbi::u64};
    std::size_t max_input_bytes{};
    std::size_t max_output_bytes{};
};

struct PrimitiveRequirement {
    std::uint64_t tag{};
    std::string id;
    std::uint32_t version{};
};

class PrimitiveProvider {
public:
    virtual ~PrimitiveProvider() = default;
    virtual PrimitiveDescriptor descriptor() const = 0;
};

class U64PrimitiveProvider : public PrimitiveProvider {
public:
    virtual std::uint64_t evaluate_u64(std::uint64_t a,
                                       std::uint64_t b,
                                       std::uint64_t c,
                                       std::uint64_t d) const = 0;
};

class BytePrimitiveProvider : public PrimitiveProvider {
public:
    // Input and output are copied across the Wasm/native boundary and are
    // independently bounded by the descriptor and SandboxLimits. Providers
    // never receive an unchecked Wasm pointer.
    virtual std::vector<std::uint8_t> evaluate_bytes(
        const std::vector<std::uint8_t>& input) const = 0;
};

using U64PrimitiveFunction = std::function<std::uint64_t(
    std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t)>;
using BytePrimitiveFunction = std::function<std::vector<std::uint8_t>(
    const std::vector<std::uint8_t>&)>;

class FunctionalU64Provider final : public U64PrimitiveProvider {
public:
    FunctionalU64Provider(PrimitiveDescriptor descriptor,
                          U64PrimitiveFunction function);

    PrimitiveDescriptor descriptor() const override;
    std::uint64_t evaluate_u64(std::uint64_t a,
                               std::uint64_t b,
                               std::uint64_t c,
                               std::uint64_t d) const override;

private:
    PrimitiveDescriptor descriptor_;
    U64PrimitiveFunction function_;
};

class FunctionalBytesProvider final : public BytePrimitiveProvider {
public:
    FunctionalBytesProvider(PrimitiveDescriptor descriptor,
                            BytePrimitiveFunction function);

    PrimitiveDescriptor descriptor() const override;
    std::vector<std::uint8_t> evaluate_bytes(
        const std::vector<std::uint8_t>& input) const override;

private:
    PrimitiveDescriptor descriptor_;
    BytePrimitiveFunction function_;
};

class PrimitiveRegistry {
public:
    void register_provider(std::shared_ptr<const PrimitiveProvider> provider);

    const PrimitiveProvider& require(std::uint64_t tag,
                                     std::uint32_t version) const;
    const PrimitiveProvider& require(const PrimitiveRequirement& requirement) const;
    const U64PrimitiveProvider& require_u64(std::uint64_t tag,
                                            std::uint32_t version) const;
    const BytePrimitiveProvider& require_bytes(std::uint64_t tag,
                                               std::uint32_t version) const;

    bool supports(const PrimitiveRequirement& requirement) const;
    std::vector<PrimitiveDescriptor> descriptors() const;

private:
    using Key = std::pair<std::uint64_t, std::uint32_t>;
    std::map<Key, std::shared_ptr<const PrimitiveProvider>> providers_;
};

// Portable transmitted object: Wasm bytecode plus an explicit primitive
// manifest. The evaluator validates the manifest before running the module and
// both runtime host calls reject any primitive not declared here.
struct WasmMathProgram {
    std::vector<std::uint8_t> wasm;
    std::string entrypoint{"v0id_main"};
    std::vector<PrimitiveRequirement> required_primitives;
};

struct SandboxLimits {
    std::size_t max_module_bytes{1024 * 1024};
    std::uint32_t max_memory_pages{16};            // 16 * 64 KiB = 1 MiB
    std::uint32_t stack_bytes{64 * 1024};

    // Keep the WAMR host-managed app heap disabled. WAMR inserts that heap into
    // the module's linear-memory allocation and can therefore enlarge the actual
    // addressable memory beyond the module-declared page count. V0ID's MathVM
    // uses bounded static/linear-memory buffers instead so max_memory_pages is a
    // meaningful hard ceiling for this profile.
    std::uint32_t host_managed_heap_bytes{0};

    std::size_t runtime_pool_bytes{16 * 1024 * 1024};
    int max_wasm_instructions{1'000'000};
    std::uint64_t max_provider_calls{4096};
    std::uint64_t max_provider_cost{1'000'000};
    std::size_t max_provider_input_bytes{256 * 1024};
    std::size_t max_provider_output_bytes{256 * 1024};
};

struct ExecutionReport {
    std::uint64_t result{};
    std::uint64_t provider_calls{};
    std::uint64_t provider_cost{};
};

// Default providers include exact modular arithmetic, SHA3-256, the existing
// toy affine plumbing primitive, and ML-KEM-768 encapsulation when the linked
// OpenSSL provider actually exposes ML-KEM (OpenSSL 3.5+ default/FIPS provider).
// ML-KEM is optional at runtime so V0ID still builds on older OpenSSL 3.x hosts.
PrimitiveRegistry make_default_registry();

} // namespace v0id::mathvm
