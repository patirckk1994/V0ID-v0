#include "tfhe_cloud_codec.hpp"

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace {

void require(bool condition, const std::string& what) {
    if (!condition)
        throw std::runtime_error(what);
}

v0id::net::TfheCloudSessionId session_id() {
    v0id::net::TfheCloudSessionId id{};
    for (std::size_t i = 0; i < id.size(); ++i)
        id[i] = static_cast<std::uint8_t>(i + 1);
    return id;
}

v0id::net::Envelope envelope() {
    v0id::net::Envelope out;
    out.peer_id = "codec-test-peer";
    out.job_id = "codec-test-job";
    out.epoch = 17;
    return out;
}

} // namespace

int main() try {
    int passed = 0;
    auto pass = [&](bool ok, const char* label) {
        require(ok, label);
        ++passed;
        std::cout << "[PASS] " << label << '\n';
    };

    const auto id = session_id();

    v0id::net::TfheCloudInstall install;
    install.session_id = id;
    install.total_instruction_count = 65;
    install.output_word_count = 8;
    install.server_key_blob = {1,2,3,4};
    install.encrypted_init_blob = {5,6,7};
    auto install_wire = v0id::net::pack_tfhe_cloud_install(envelope(), std::move(install));
    pass(install_wire.envelope.type == v0id::net::MessageType::install_tfhe_session &&
             install_wire.frames.size() == 2,
         "install uses typed metadata plus two multipart blob frames");
    const auto install_back = v0id::net::unpack_tfhe_cloud_install(std::move(install_wire));
    pass(install_back.session_id == id &&
             install_back.total_instruction_count == 65 &&
             install_back.output_word_count == 8 &&
             install_back.server_key_blob == std::vector<std::uint8_t>({1,2,3,4}) &&
             install_back.encrypted_init_blob == std::vector<std::uint8_t>({5,6,7}),
         "install round-trip preserves session shape and opaque frames");

    v0id::net::TfheCloudChunk chunk;
    chunk.session_id = id;
    chunk.start_instruction = 32;
    chunk.instruction_count = 32;
    chunk.total_instruction_count = 65;
    chunk.encrypted_chunk_blob = {9,8,7,6,5};
    auto chunk_back = v0id::net::unpack_tfhe_cloud_chunk(
        v0id::net::pack_tfhe_cloud_chunk(envelope(), std::move(chunk)));
    pass(chunk_back.session_id == id &&
             chunk_back.start_instruction == 32 &&
             chunk_back.instruction_count == 32 &&
             chunk_back.total_instruction_count == 65 &&
             chunk_back.encrypted_chunk_blob == std::vector<std::uint8_t>({9,8,7,6,5}),
         "chunk round-trip preserves explicit start/count/total sequence metadata");

    const v0id::net::TfheCloudAck ack{id, 64};
    const auto ack_back = v0id::net::unpack_tfhe_cloud_ack(
        v0id::net::pack_tfhe_cloud_ack(
            envelope(), ack, v0id::net::MessageType::tfhe_chunk_ready),
        v0id::net::MessageType::tfhe_chunk_ready);
    pass(ack_back.session_id == id && ack_back.completed_instruction_count == 64,
         "chunk acknowledgement round-trip preserves completed instruction count");

    const v0id::net::TfheCloudFinish finish{id, 65, 8};
    const auto finish_back = v0id::net::unpack_tfhe_cloud_finish(
        v0id::net::pack_tfhe_cloud_finish(envelope(), finish));
    pass(finish_back.session_id == id &&
             finish_back.expected_instruction_count == 65 &&
             finish_back.expected_output_word_count == 8,
         "finish message binds expected instruction and output counts");

    v0id::net::TfheCloudResult result;
    result.session_id = id;
    result.completed_instruction_count = 65;
    result.encrypted_result_blob = {0xaa,0xbb,0xcc};
    const auto result_back = v0id::net::unpack_tfhe_cloud_result(
        v0id::net::pack_tfhe_cloud_result(envelope(), std::move(result)));
    pass(result_back.session_id == id &&
             result_back.completed_instruction_count == 65 &&
             result_back.encrypted_result_blob == std::vector<std::uint8_t>({0xaa,0xbb,0xcc}),
         "result round-trip preserves completed count and encrypted result frame");

    bool zero_rejected = false;
    try {
        v0id::net::TfheCloudFinish invalid{};
        invalid.expected_instruction_count = 1;
        invalid.expected_output_word_count = 1;
        (void)v0id::net::pack_tfhe_cloud_finish(envelope(), invalid);
    } catch (const std::runtime_error&) {
        zero_rejected = true;
    }
    pass(zero_rejected, "all-zero TFHE cloud session id is rejected");

    bool bad_frame_rejected = false;
    try {
        v0id::net::TfheCloudInstall bad;
        bad.session_id = id;
        bad.total_instruction_count = 1;
        bad.output_word_count = 1;
        bad.server_key_blob = {1,2};
        bad.encrypted_init_blob = {3};
        auto wire = v0id::net::pack_tfhe_cloud_install(envelope(), std::move(bad));
        wire.frames[0].push_back(4); // metadata still advertises two bytes
        (void)v0id::net::unpack_tfhe_cloud_install(std::move(wire));
    } catch (const std::runtime_error&) {
        bad_frame_rejected = true;
    }
    pass(bad_frame_rejected, "advertised multipart frame length mismatch is rejected");

    bool oversized_chunk_count_rejected = false;
    try {
        v0id::net::TfheCloudChunk bad;
        bad.session_id = id;
        bad.start_instruction = 0;
        bad.instruction_count = 65;
        bad.total_instruction_count = 65;
        bad.encrypted_chunk_blob = {1};
        (void)v0id::net::pack_tfhe_cloud_chunk(envelope(), std::move(bad));
    } catch (const std::runtime_error&) {
        oversized_chunk_count_rejected = true;
    }
    pass(oversized_chunk_count_rejected,
         "chunk instruction count above protocol maximum is rejected");

    std::cout << "TFHE cloud codec tests: " << passed << " passed, 0 failed\n";
    return 0;
} catch (const std::exception& e) {
    std::cerr << "TFHE cloud codec tests FAILED: " << e.what() << '\n';
    return 1;
}
