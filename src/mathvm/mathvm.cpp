#include "mathvm.hpp"

#include <openssl/err.h>
#include <openssl/evp.h>

#include <array>
#include <cstdint>
#include <limits>
#include <memory>
#include <stdexcept>
#include <utility>
#include <vector>

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

std::vector<std::uint8_t> sha3_256(
    const std::vector<std::uint8_t>& input) {
    using MdPtr = std::unique_ptr<EVP_MD, decltype(&EVP_MD_free)>;
    using CtxPtr = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;

    MdPtr md(EVP_MD_fetch(nullptr, "SHA3-256", nullptr), EVP_MD_free);
    if (!md)
        throw std::runtime_error("OpenSSL SHA3-256 provider unavailable");

    CtxPtr ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!ctx)
        throw std::runtime_error("EVP_MD_CTX_new failed");

    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned int digest_len = 0;

    if (EVP_DigestInit_ex(ctx.get(), md.get(), nullptr) != 1)
        throw std::runtime_error("SHA3-256 init failed");
    if (!input.empty() &&
        EVP_DigestUpdate(ctx.get(), input.data(), input.size()) != 1)
        throw std::runtime_error("SHA3-256 update failed");
    if (EVP_DigestFinal_ex(ctx.get(), digest.data(), &digest_len) != 1)
        throw std::runtime_error("SHA3-256 final failed");
    if (digest_len != 32)
        throw std::runtime_error("SHA3-256 returned unexpected digest length");

    return {digest.begin(), digest.begin() + digest_len};
}

bool openssl_has_ml_kem_768() {
    ERR_clear_error();
    EVP_PKEY_CTX* raw =
        EVP_PKEY_CTX_new_from_name(nullptr, "ML-KEM-768", nullptr);
    if (!raw) {
        ERR_clear_error();
        return false;
    }
    EVP_PKEY_CTX_free(raw);
    ERR_clear_error();
    return true;
}

void append_u32_be(std::vector<std::uint8_t>& out, std::uint32_t value) {
    out.push_back(static_cast<std::uint8_t>((value >> 24) & 0xffu));
    out.push_back(static_cast<std::uint8_t>((value >> 16) & 0xffu));
    out.push_back(static_cast<std::uint8_t>((value >> 8) & 0xffu));
    out.push_back(static_cast<std::uint8_t>(value & 0xffu));
}

std::vector<std::uint8_t> ml_kem_768_encapsulate(
    const std::vector<std::uint8_t>& raw_public_key) {
    using KeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
    using CtxPtr = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;

    if (raw_public_key.empty())
        throw std::runtime_error("ML-KEM-768 public key is empty");

    ERR_clear_error();
    KeyPtr public_key(
        EVP_PKEY_new_raw_public_key_ex(
            nullptr,
            "ML-KEM-768",
            nullptr,
            raw_public_key.data(),
            raw_public_key.size()),
        EVP_PKEY_free);
    if (!public_key) {
        ERR_clear_error();
        throw std::runtime_error(
            "ML-KEM-768 public key import failed or provider unavailable");
    }

    CtxPtr ctx(EVP_PKEY_CTX_new_from_pkey(nullptr, public_key.get(), nullptr),
               EVP_PKEY_CTX_free);
    if (!ctx)
        throw std::runtime_error("ML-KEM-768 context creation failed");
    if (EVP_PKEY_encapsulate_init(ctx.get(), nullptr) <= 0)
        throw std::runtime_error("ML-KEM-768 encapsulation init failed");

    std::size_t ciphertext_len = 0;
    std::size_t secret_len = 0;
    if (EVP_PKEY_encapsulate(
            ctx.get(), nullptr, &ciphertext_len, nullptr, &secret_len) <= 0)
        throw std::runtime_error("ML-KEM-768 output-size query failed");

    if (ciphertext_len == 0 || secret_len == 0 ||
        ciphertext_len > std::numeric_limits<std::uint32_t>::max() ||
        secret_len > std::numeric_limits<std::uint32_t>::max())
        throw std::runtime_error("ML-KEM-768 returned invalid output lengths");

    std::vector<std::uint8_t> ciphertext(ciphertext_len);
    std::vector<std::uint8_t> secret(secret_len);
    if (EVP_PKEY_encapsulate(ctx.get(),
                             ciphertext.data(), &ciphertext_len,
                             secret.data(), &secret_len) <= 0)
        throw std::runtime_error("ML-KEM-768 encapsulation failed");

    ciphertext.resize(ciphertext_len);
    secret.resize(secret_len);

    // Canonical MathVM byte-provider encoding:
    //   u32be ciphertext_len || u32be shared_secret_len || ciphertext || secret
    std::vector<std::uint8_t> out;
    out.reserve(8 + ciphertext.size() + secret.size());
    append_u32_be(out, static_cast<std::uint32_t>(ciphertext.size()));
    append_u32_be(out, static_cast<std::uint32_t>(secret.size()));
    out.insert(out.end(), ciphertext.begin(), ciphertext.end());
    out.insert(out.end(), secret.begin(), secret.end());
    return out;
}

void validate_descriptor_common(const PrimitiveDescriptor& descriptor) {
    if (descriptor.tag == 0)
        throw std::runtime_error("primitive tag zero is reserved");
    if (descriptor.id.empty())
        throw std::runtime_error("primitive id must not be empty");
    if (descriptor.version == 0)
        throw std::runtime_error("primitive version must be positive");
    if (descriptor.cost == 0)
        throw std::runtime_error("primitive cost must be positive");
}

} // namespace

FunctionalU64Provider::FunctionalU64Provider(PrimitiveDescriptor descriptor,
                                             U64PrimitiveFunction function)
    : descriptor_(std::move(descriptor)), function_(std::move(function)) {
    validate_descriptor_common(descriptor_);
    if (descriptor_.abi != PrimitiveAbi::u64)
        throw std::runtime_error("u64 provider registered with non-u64 ABI");
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

FunctionalBytesProvider::FunctionalBytesProvider(
    PrimitiveDescriptor descriptor,
    BytePrimitiveFunction function)
    : descriptor_(std::move(descriptor)), function_(std::move(function)) {
    validate_descriptor_common(descriptor_);
    if (descriptor_.abi != PrimitiveAbi::bytes)
        throw std::runtime_error("byte provider registered with non-byte ABI");
    if (descriptor_.max_input_bytes == 0 || descriptor_.max_output_bytes == 0)
        throw std::runtime_error("byte provider requires non-zero buffer bounds");
    if (!function_)
        throw std::runtime_error("byte primitive function must not be empty");
}

PrimitiveDescriptor FunctionalBytesProvider::descriptor() const {
    return descriptor_;
}

std::vector<std::uint8_t> FunctionalBytesProvider::evaluate_bytes(
    const std::vector<std::uint8_t>& input) const {
    if (input.size() > descriptor_.max_input_bytes)
        throw std::runtime_error("byte primitive input exceeds provider limit");
    auto out = function_(input);
    if (out.size() > descriptor_.max_output_bytes)
        throw std::runtime_error("byte primitive output exceeds provider limit");
    return out;
}

void PrimitiveRegistry::register_provider(
    std::shared_ptr<const PrimitiveProvider> provider) {
    if (!provider)
        throw std::runtime_error("cannot register null primitive provider");

    const auto descriptor = provider->descriptor();
    validate_descriptor_common(descriptor);

    if (descriptor.abi == PrimitiveAbi::u64) {
        if (dynamic_cast<const U64PrimitiveProvider*>(provider.get()) == nullptr)
            throw std::runtime_error("u64 descriptor/provider ABI mismatch");
    } else if (descriptor.abi == PrimitiveAbi::bytes) {
        if (dynamic_cast<const BytePrimitiveProvider*>(provider.get()) == nullptr)
            throw std::runtime_error("byte descriptor/provider ABI mismatch");
        if (descriptor.max_input_bytes == 0 || descriptor.max_output_bytes == 0)
            throw std::runtime_error("byte provider descriptor lacks bounds");
    } else {
        throw std::runtime_error("unknown primitive ABI");
    }

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

const U64PrimitiveProvider& PrimitiveRegistry::require_u64(
    std::uint64_t tag,
    std::uint32_t version) const {
    const auto& provider = require(tag, version);
    if (provider.descriptor().abi != PrimitiveAbi::u64)
        throw std::runtime_error("primitive is not a u64 provider");
    const auto* typed = dynamic_cast<const U64PrimitiveProvider*>(&provider);
    if (!typed)
        throw std::runtime_error("u64 primitive provider type mismatch");
    return *typed;
}

const BytePrimitiveProvider& PrimitiveRegistry::require_bytes(
    std::uint64_t tag,
    std::uint32_t version) const {
    const auto& provider = require(tag, version);
    if (provider.descriptor().abi != PrimitiveAbi::bytes)
        throw std::runtime_error("primitive is not a byte provider");
    const auto* typed = dynamic_cast<const BytePrimitiveProvider*>(&provider);
    if (!typed)
        throw std::runtime_error("byte primitive provider type mismatch");
    return *typed;
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
            PrimitiveAbi::u64,
            0,
            0,
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
            PrimitiveAbi::u64,
            0,
            0,
        },
        [](std::uint64_t a, std::uint64_t b, std::uint64_t modulus,
           std::uint64_t) {
            return mul_mod(a, b, modulus);
        }));

    registry.register_provider(std::make_shared<FunctionalBytesProvider>(
        PrimitiveDescriptor{
            PRIMITIVE_SHA3_256_BYTES,
            "v0id.crypto.sha3-256",
            1,
            256,
            false,
            PrimitiveAbi::bytes,
            256 * 1024,
            32,
        },
        [](const std::vector<std::uint8_t>& input) {
            return sha3_256(input);
        }));

    // OpenSSL added standardized ML-KEM in 3.5. Probe the linked provider at
    // runtime rather than making all MathVM builds require 3.5: older OpenSSL 3.x
    // hosts keep the rest of ABI v2 and simply do not advertise this capability.
    if (openssl_has_ml_kem_768()) {
        registry.register_provider(std::make_shared<FunctionalBytesProvider>(
            PrimitiveDescriptor{
                PRIMITIVE_ML_KEM_768_ENCAP_BYTES,
                "v0id.pq.ml-kem-768.encapsulate",
                1,
                50'000,
                false,
                PrimitiveAbi::bytes,
                2 * 1024,
                4 * 1024,
            },
            [](const std::vector<std::uint8_t>& raw_public_key) {
                return ml_kem_768_encapsulate(raw_public_key);
            }));
    }

    registry.register_provider(std::make_shared<FunctionalU64Provider>(
        PrimitiveDescriptor{
            PRIMITIVE_TOY_LWE_AFFINE_U64,
            "v0id.experimental.toy-lwe-affine-u64",
            1,
            65,
            true,
            PrimitiveAbi::u64,
            0,
            0,
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
