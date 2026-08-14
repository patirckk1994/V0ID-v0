#pragma once

#include "binfhecontext-ser.h"

#include <array>
#include <cstdint>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace v0id::fhe {

template <typename T>
std::vector<std::uint8_t> serialize_binary(const T& object) {
    std::ostringstream stream(std::ios::out | std::ios::binary);
    lbcrypto::Serial::Serialize(object, stream, lbcrypto::SerType::BINARY);
    const auto data = stream.str();
    return {data.begin(), data.end()};
}

template <typename T>
void deserialize_binary(const std::vector<std::uint8_t>& data, T& object) {
    const std::string serialized(data.begin(), data.end());
    std::istringstream stream(serialized, std::ios::in | std::ios::binary);
    lbcrypto::Serial::Deserialize(object, stream, lbcrypto::SerType::BINARY);
}

struct RemoteEvalBundle {
    std::vector<std::uint8_t> context;
    std::vector<std::uint8_t> refresh_key;
    std::vector<std::uint8_t> switching_key;
    std::vector<std::uint8_t> ciphertext;
};

namespace detail {

constexpr std::array<std::uint8_t, 8> FHE_MAGIC{'V','0','I','D','F','H','E','1'};

inline void put_u64(std::vector<std::uint8_t>& out, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8)
        out.push_back(static_cast<std::uint8_t>((value >> shift) & 0xffu));
}

inline std::uint64_t get_u64(const std::uint8_t*& p, const std::uint8_t* end) {
    if (end - p < 8) throw std::runtime_error("truncated V0ID FHE bundle");
    std::uint64_t value = 0;
    for (int i = 0; i < 8; ++i) value = (value << 8) | p[i];
    p += 8;
    return value;
}

inline void append_blob(std::vector<std::uint8_t>& out,
                        const std::vector<std::uint8_t>& blob) {
    put_u64(out, static_cast<std::uint64_t>(blob.size()));
    out.insert(out.end(), blob.begin(), blob.end());
}

inline std::vector<std::uint8_t> read_blob(const std::uint8_t*& p,
                                           const std::uint8_t* end) {
    const auto size = get_u64(p, end);
    const auto remaining = static_cast<std::uint64_t>(end - p);
    if (size > remaining) throw std::runtime_error("bad V0ID FHE bundle length");
    std::vector<std::uint8_t> out(p, p + static_cast<std::size_t>(size));
    p += static_cast<std::size_t>(size);
    return out;
}

} // namespace detail

inline std::vector<std::uint8_t> pack_remote_eval_bundle(const RemoteEvalBundle& bundle) {
    std::vector<std::uint8_t> out;
    out.insert(out.end(), detail::FHE_MAGIC.begin(), detail::FHE_MAGIC.end());
    detail::append_blob(out, bundle.context);
    detail::append_blob(out, bundle.refresh_key);
    detail::append_blob(out, bundle.switching_key);
    detail::append_blob(out, bundle.ciphertext);
    return out;
}

inline RemoteEvalBundle unpack_remote_eval_bundle(const std::vector<std::uint8_t>& wire) {
    if (wire.size() < detail::FHE_MAGIC.size() + 4 * sizeof(std::uint64_t))
        throw std::runtime_error("V0ID FHE bundle too short");

    const auto* p = wire.data();
    const auto* end = p + wire.size();

    for (const auto expected : detail::FHE_MAGIC) {
        if (p == end || *p++ != expected)
            throw std::runtime_error("bad V0ID FHE bundle magic");
    }

    RemoteEvalBundle bundle;
    bundle.context = detail::read_blob(p, end);
    bundle.refresh_key = detail::read_blob(p, end);
    bundle.switching_key = detail::read_blob(p, end);
    bundle.ciphertext = detail::read_blob(p, end);

    if (p != end) throw std::runtime_error("trailing bytes in V0ID FHE bundle");
    return bundle;
}

} // namespace v0id::fhe
