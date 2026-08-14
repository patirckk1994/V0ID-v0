#include "mathvm.hpp"

#include <limits>
#include <stdexcept>
#include <utility>

namespace v0id::mathvm {
namespace {

std::uint64_t add_mod(std::uint64_t a,
                      std::uint64_t b,
                      std::uint64_t modulus) {
    if (modulus == 0)
        throw std::runtime_error("modulus must be non-zero");

    a %= modulus;
    b %= modulus;
    return a >= modulus - b ? a - (modulus - b) : a + b;
}

std::uint64_t mul_mod(std::uint64_t a,
                      std::uint64_t b,
                      std::uint64_t modulus) {
    if (modulus == 0)
        throw std::runtime_error("modulus must be non-zero");

    a %= modulus;
    b %= modulus;
    std::uint64_t out = 0;

    // Portable overflow-free double-and-add. The provider boundary lets this be
    // replaced later with platform-specific bigint/AVX/GPU code without changing
    // transmitted Wasm modules.
    while (b != 0) {
        if (b & 1u)
            out = add_mod(out, a, modulus);
        b >>= 1u;
        if (b != 0)
            a = add_mod(a, a, modulus);
    }
    return out;
}

} // namespace

FunctionalU64Provider::FunctionalU64Provider(PrimitiveDescriptor descriptor,
                                             U64PrimitiveFunction function)
    : descriptor_(std::move(descriptor)), function_(std::move(function)) {
    if (descriptor_.tag == 0)
        throw std::runtime_error("primitive tag zero is reserved");
    if (descriptor_.id.empty())
        throw std::runtime_error("primitive id must not be empty");
    if (descriptor_.version == 0)
        throw std::runtime_error("primitive version must be positive");
    if (descriptor_.cost == 0)
        throw std::runtime_error("primitive cost must be positive");
    if (!function_)
        throw std::runtime_error("primitive function must not be empty");
}

PrimitiveDescriptor FunctionalU64Provider::descriptor() const {
    return descriptor_;
}

std::uint64_t FunctionalU64Provider::evaluate_u64(std::uint64_t a,
                                                  std::uint64_t b,
                                                  std::uint64_t c,
                                                  std::uint64_t d) const {
    return function_(a, b, c, d);
}

void PrimitiveRegistry::register_provider(
    std::shared_ptr<const PrimitiveProvider> provider) {
    if (!provider)
        throw std::runtime_error("cannot register null primitive provider");

    const auto descriptor = provider->descriptor();
    if (descriptor.tag == 0 || descriptor.id.empty() || descriptor.version == 0)
        throw std::runtime_error("invalid primitive descriptor");

    const Key key{descriptor.tag, descriptor.version};
    if (providers_.contains(key))
        throw std::runtime_error("duplicate primitive tag/version registration");

    // Refuse textual aliases for the same numeric protocol tag/version. This
    // keeps manifests deterministic and avoids peers disagreeing about meaning.
    providers_.emplace(key, std::move(provider));
}

const PrimitiveProvider& PrimitiveRegistry::require(std::uint64_t tag,
                                                    std::uint32_t version) const {
    const auto it = providers_.find(Key{tag, version});
    if (it == providers_.end())
        throw std::runtime_error("required MathVM primitive is not installed");
    return *it->second;
}

const PrimitiveProvider& PrimitiveRegistry::require(
    const PrimitiveRequirement& requirement) const {
    const auto& provider = require(requirement.tag, requirement.version);
    const auto descriptor = provider.descriptor();
    if (descriptor.id != requirement.id)
        throw std::runtime_error("primitive manifest id/tag mismatch");
    return provider;
}

bool PrimitiveRegistry::supports(const PrimitiveRequirement& requirement) const {
    try {
        (void)require(requirement);
        return true;
    } catch (...) {
        return false;
    }
}

std::vector<PrimitiveDescriptor> PrimitiveRegistry::descriptors() const {
    std::vector<PrimitiveDescriptor> out;
    out.reserve(providers_.size());
    for (const auto& [_, provider] : providers_)
        out.push_back(provider->descriptor());
    return out;
}

PrimitiveRegistry make_default_registry() {
    PrimitiveRegistry registry;

    registry.register_provider(std::make_shared<FunctionalU64Provider>(
        PrimitiveDescriptor{
            PRIMITIVE_ADD_MOD_U64,
            "v0id.math.add-mod-u64",
            1,
            1,
            false,
        },
        [](std::uint64_t a, std::uint64_t b, std::uint64_t modulus,
           std::uint64_t) {
            return add_mod(a, b, modulus);
        }));

    registry.register_provider(std::make_shared<FunctionalU64Provider>(
        PrimitiveDescriptor{
            PRIMITIVE_MUL_MOD_U64,
            "v0id.math.mul-mod-u64",
            1,
            64,
            false,
        },
        [](std::uint64_t a, std::uint64_t b, std::uint64_t modulus,
           std::uint64_t) {
            return mul_mod(a, b, modulus);
        }));

    registry.register_provider(std::make_shared<FunctionalU64Provider>(
        PrimitiveDescriptor{
            PRIMITIVE_TOY_LWE_AFFINE_U64,
            "v0id.experimental.toy-lwe-affine-u64",
            1,
            65,
            true,
        },
        [](std::uint64_t a, std::uint64_t secret, std::uint64_t error,
           std::uint64_t modulus) {
            // Interface plumbing only: b = a*s + e mod q. Real LWE requires a
            // properly parameterized high-dimensional distribution and security
            // analysis. This scalar function deliberately makes no PQ claim.
            return add_mod(mul_mod(a, secret, modulus), error, modulus);
        }));

    return registry;
}

} // namespace v0id::mathvm
