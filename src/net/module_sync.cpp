#include "module_sync.hpp"

#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string_view>
#include <tuple>
#include <vector>

namespace v0id::net {
namespace {

constexpr std::array<std::uint8_t, 8> MAGIC{'V','0','M','O','D','1','\0','\0'};
constexpr std::uint8_t VERSION = 1;

void put_u64(std::vector<std::uint8_t>& out, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8)
        out.push_back(static_cast<std::uint8_t>((value >> shift) & 0xffu));
}

std::uint64_t get_u64(const std::uint8_t*& p, const std::uint8_t* end) {
    if (end - p < 8) throw std::runtime_error("truncated module bundle");
    std::uint64_t value = 0;
    for (int i = 0; i < 8; ++i) value = (value << 8) | p[i];
    p += 8;
    return value;
}

void put_blob(std::vector<std::uint8_t>& out,
              const std::uint8_t* data,
              std::size_t size) {
    put_u64(out, static_cast<std::uint64_t>(size));
    if (size != 0) out.insert(out.end(), data, data + size);
}

void put_string(std::vector<std::uint8_t>& out, std::string_view value) {
    put_blob(out,
             reinterpret_cast<const std::uint8_t*>(value.data()),
             value.size());
}

std::vector<std::uint8_t> get_blob(const std::uint8_t*& p,
                                   const std::uint8_t* end,
                                   std::size_t max_size,
                                   const char* what) {
    const auto n64 = get_u64(p, end);
    if (n64 > max_size)
        throw std::runtime_error(std::string(what) + " exceeds module-sync limit");
    const auto n = static_cast<std::size_t>(n64);
    if (static_cast<std::size_t>(end - p) < n)
        throw std::runtime_error(std::string("truncated ") + what);
    std::vector<std::uint8_t> out(p, p + n);
    p += n;
    return out;
}

std::string get_string(const std::uint8_t*& p,
                       const std::uint8_t* end,
                       std::size_t max_size,
                       const char* what) {
    const auto bytes = get_blob(p, end, max_size, what);
    return {bytes.begin(), bytes.end()};
}

bool digest_all_zero(const ModuleDigest512& digest) {
    return std::all_of(digest.begin(), digest.end(),
                       [](std::uint8_t b) { return b == 0; });
}

void validate_kind(ModuleKind kind) {
    switch (kind) {
        case ModuleKind::strategy_wasm:
        case ModuleKind::mathvm_wasm:
        case ModuleKind::polymorphism_wasm:
        case ModuleKind::neural_wasm:
            return;
    }
    throw std::runtime_error("unknown module kind");
}

void validate_visibility(ModuleVisibility visibility) {
    switch (visibility) {
        case ModuleVisibility::private_local:
        case ModuleVisibility::shared_sync:
            return;
    }
    throw std::runtime_error("unknown module visibility");
}

void validate_shared_descriptor(const ModuleDescriptor& d) {
    if (d.protocol_id != "v0id-module-sync-v1")
        throw std::runtime_error("unsupported module-sync protocol");
    validate_kind(d.kind);
    validate_visibility(d.visibility);
    if (d.visibility != ModuleVisibility::shared_sync)
        throw std::runtime_error("private-local module cannot enter shared module set");
    if (d.module_id.empty() || d.module_version == 0)
        throw std::runtime_error("module descriptor missing id/version");
    if (d.byte_size == 0)
        throw std::runtime_error("shared module descriptor has zero byte size");
    if (digest_all_zero(d.digest))
        throw std::runtime_error("module descriptor has zero digest");
}

} // namespace

ModuleDigest512 module_digest512(const std::vector<std::uint8_t>& bytes) {
    EVP_MD* md = EVP_MD_fetch(nullptr, "SHA3-512", nullptr);
    if (!md)
        throw std::runtime_error("OpenSSL SHA3-512 unavailable for module sync");
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        EVP_MD_free(md);
        throw std::runtime_error("EVP_MD_CTX_new failed");
    }

    ModuleDigest512 out{};
    unsigned int written = 0;
    const bool ok =
        EVP_DigestInit_ex2(ctx, md, nullptr) == 1 &&
        EVP_DigestUpdate(ctx, bytes.data(), bytes.size()) == 1 &&
        EVP_DigestFinal_ex(ctx, out.data(), &written) == 1;
    EVP_MD_CTX_free(ctx);
    EVP_MD_free(md);
    if (!ok || written != out.size())
        throw std::runtime_error("OpenSSL SHA3-512 module digest failed");
    return out;
}

ModuleDescriptor describe_module(ModuleKind kind,
                                 ModuleVisibility visibility,
                                 const std::string& module_id,
                                 std::uint64_t module_version,
                                 const std::vector<std::uint8_t>& bytes) {
    validate_kind(kind);
    validate_visibility(visibility);
    if (module_id.empty() || module_version == 0)
        throw std::runtime_error("module descriptor requires id/version");

    ModuleDescriptor out;
    out.kind = kind;
    out.visibility = visibility;
    out.module_id = module_id;
    out.module_version = module_version;
    out.byte_size = static_cast<std::uint64_t>(bytes.size());
    out.digest = module_digest512(bytes);
    return out;
}

ModuleDigest512 shared_module_set_digest512(
    const std::vector<ModuleDescriptor>& descriptors) {
    std::vector<ModuleDescriptor> sorted = descriptors;
    for (const auto& d : sorted) validate_shared_descriptor(d);

    std::sort(sorted.begin(), sorted.end(), [](const auto& a, const auto& b) {
        return std::tie(a.kind, a.module_id, a.module_version, a.digest, a.byte_size) <
               std::tie(b.kind, b.module_id, b.module_version, b.digest, b.byte_size);
    });

    for (std::size_t i = 1; i < sorted.size(); ++i) {
        const auto& a = sorted[i - 1];
        const auto& b = sorted[i];
        if (a.kind == b.kind && a.module_id == b.module_id &&
            a.module_version == b.module_version)
            throw std::runtime_error(
                "duplicate shared module kind/id/version in module set");
    }

    std::vector<std::uint8_t> canonical;
    put_string(canonical, "V0ID-SHARED-MODULE-SET-v1");
    put_u64(canonical, static_cast<std::uint64_t>(sorted.size()));
    for (const auto& d : sorted) {
        put_string(canonical, d.protocol_id);
        put_u64(canonical, static_cast<std::uint64_t>(d.kind));
        put_u64(canonical, static_cast<std::uint64_t>(d.visibility));
        put_string(canonical, d.module_id);
        put_u64(canonical, d.module_version);
        put_u64(canonical, d.byte_size);
        put_blob(canonical, d.digest.data(), d.digest.size());
    }
    return module_digest512(canonical);
}

void verify_module_bundle(const ModuleBundle& bundle,
                          std::size_t max_module_bytes,
                          bool require_shared) {
    const auto& d = bundle.descriptor;
    if (d.protocol_id != "v0id-module-sync-v1")
        throw std::runtime_error("unsupported module-sync protocol");
    validate_kind(d.kind);
    validate_visibility(d.visibility);
    if (require_shared && d.visibility != ModuleVisibility::shared_sync)
        throw std::runtime_error("private-local module cannot be synchronized");
    if (d.module_id.empty() || d.module_version == 0)
        throw std::runtime_error("module descriptor missing id/version");
    if (bundle.bytes.empty())
        throw std::runtime_error("module bundle has empty bytecode");
    if (bundle.bytes.size() > max_module_bytes)
        throw std::runtime_error("module bytecode exceeds synchronization limit");
    if (d.byte_size != bundle.bytes.size())
        throw std::runtime_error("module descriptor byte size mismatch");
    if (digest_all_zero(d.digest))
        throw std::runtime_error("module descriptor has zero digest");
    if (module_digest512(bundle.bytes) != d.digest)
        throw std::runtime_error("module content digest mismatch");
}

std::vector<std::uint8_t> encode_shared_module_bundle(const ModuleBundle& bundle) {
    verify_module_bundle(bundle, 1024 * 1024, true);

    const auto& d = bundle.descriptor;
    std::vector<std::uint8_t> out;
    out.reserve(128 + d.module_id.size() + bundle.bytes.size());
    out.insert(out.end(), MAGIC.begin(), MAGIC.end());
    out.push_back(VERSION);
    out.push_back(static_cast<std::uint8_t>(d.kind));
    out.push_back(static_cast<std::uint8_t>(d.visibility));
    out.push_back(0); // reserved
    put_string(out, d.protocol_id);
    put_string(out, d.module_id);
    put_u64(out, d.module_version);
    put_u64(out, d.byte_size);
    out.insert(out.end(), d.digest.begin(), d.digest.end());
    put_blob(out, bundle.bytes.data(), bundle.bytes.size());
    return out;
}

ModuleBundle decode_shared_module_bundle(const void* data,
                                         std::size_t size,
                                         std::size_t max_module_bytes) {
    if (!data || size < MAGIC.size() + 4)
        throw std::runtime_error("module bundle too short");

    const auto* p = static_cast<const std::uint8_t*>(data);
    const auto* end = p + size;
    if (!std::equal(MAGIC.begin(), MAGIC.end(), p))
        throw std::runtime_error("bad module bundle magic");
    p += MAGIC.size();
    const auto version = *p++;
    if (version != VERSION)
        throw std::runtime_error("unsupported module bundle version");

    ModuleBundle out;
    out.descriptor.kind = static_cast<ModuleKind>(*p++);
    out.descriptor.visibility = static_cast<ModuleVisibility>(*p++);
    ++p; // reserved
    out.descriptor.protocol_id = get_string(p, end, 128, "module protocol id");
    out.descriptor.module_id = get_string(p, end, 256, "module id");
    out.descriptor.module_version = get_u64(p, end);
    out.descriptor.byte_size = get_u64(p, end);
    if (end - p < static_cast<std::ptrdiff_t>(out.descriptor.digest.size()))
        throw std::runtime_error("truncated module digest");
    std::copy(p, p + out.descriptor.digest.size(), out.descriptor.digest.begin());
    p += out.descriptor.digest.size();
    out.bytes = get_blob(p, end, max_module_bytes, "module bytecode");
    if (p != end)
        throw std::runtime_error("module bundle has trailing bytes");

    verify_module_bundle(out, max_module_bytes, true);
    return out;
}

std::string module_digest_hex(const ModuleDigest512& digest) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (const auto b : digest) oss << std::setw(2) << static_cast<unsigned>(b);
    return oss.str();
}

std::string to_string(ModuleKind kind) {
    switch (kind) {
        case ModuleKind::strategy_wasm: return "STRATEGY_WASM";
        case ModuleKind::mathvm_wasm: return "MATHVM_WASM";
        case ModuleKind::polymorphism_wasm: return "POLYMORPHISM_WASM";
        case ModuleKind::neural_wasm: return "NEURAL_WASM";
    }
    return "UNKNOWN_MODULE_KIND";
}

std::string to_string(ModuleVisibility visibility) {
    switch (visibility) {
        case ModuleVisibility::private_local: return "PRIVATE_LOCAL";
        case ModuleVisibility::shared_sync: return "SHARED_SYNC";
    }
    return "UNKNOWN_MODULE_VISIBILITY";
}

} // namespace v0id::net
