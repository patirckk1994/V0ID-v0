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

inline constexpr std::uint32_t MATHVM_ABI_VERSION = 1;

// Stable numeric tags used by the generic Wasm host import. They are protocol
// identifiers, not security values. The textual id remains the canonical name
// used in manifests/logging and later capability negotiation.
inline constexpr std::uint64_t PRIMITIVE_ADD_MOD_U64 = 0x0001'0001ull;
inline constexpr std::uint64_t PRIMITIVE_MUL_MOD_U64 = 0x0001'0002ull;
inline constexpr std::uint64_t PRIMITIVE_TOY_LWE_AFFINE_U64 = 0x7fff'0001ull;

struct PrimitiveDescriptor {
    std::uint64_t tag{};
    std::string id;
    std::uint32_t version{};
    std::uint64_t cost{};
    bool experimental{};
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

    // V0.4.2 starts with a deliberately tiny exact scalar ABI. Larger vectors,
    // matrices and polynomial buffers can be added later behind separate bounded
    // imports without changing the trust model.
    virtual std::uint64_t evaluate_u64(std::uint64_t a,
                                       std::uint64_t b,
                                       std::uint64_t c,
                                       std::uint64_t d) const = 0;
};

using U64PrimitiveFunction = std::function<std::uint64_t(
    std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t)>;

class FunctionalU64Provider final : public PrimitiveProvider {
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

class PrimitiveRegistry {
public:
    void register_provider(std::shared_ptr<const PrimitiveProvider> provider);

    const PrimitiveProvider& require(std::uint64_t tag,
                                     std::uint32_t version) const;
    const PrimitiveProvider& require(const PrimitiveRequirement& requirement) const;

    bool supports(const PrimitiveRequirement& requirement) const;
    std::vector<PrimitiveDescriptor> descriptors() const;

private:
    using Key = std::pair<std::uint64_t, std::uint32_t>;
    std::map<Key, std::shared_ptr<const PrimitiveProvider>> providers_;
};

// Portable transmitted object: Wasm bytecode plus an explicit primitive
// manifest. The evaluator validates the manifest before running the module and
// the runtime host call rejects any primitive not declared here.
struct WasmMathProgram {
    std::vector<std::uint8_t> wasm;
    std::string entrypoint{"v0id_main"};
    std::vector<PrimitiveRequirement> required_primitives;
};

struct SandboxLimits {
    std::size_t max_module_bytes{1024 * 1024};
    std::uint32_t max_memory_pages{16};            // 16 * 64 KiB = 1 MiB
    std::uint32_t stack_bytes{64 * 1024};
    std::uint32_t host_managed_heap_bytes{64 * 1024};
    std::size_t runtime_pool_bytes{16 * 1024 * 1024};
    int max_wasm_instructions{1'000'000};
    std::uint64_t max_provider_calls{4096};
    std::uint64_t max_provider_cost{1'000'000};
};

struct ExecutionReport {
    std::uint64_t result{};
    std::uint64_t provider_calls{};
    std::uint64_t provider_cost{};
};

// Classical native providers shipped with the research scaffold. The toy-LWE
// entry is only an interface test: one scalar affine relation is NOT an LWE/PQ
// encryption scheme and must never be advertised as one.
PrimitiveRegistry make_default_registry();

} // namespace v0id::mathvm
