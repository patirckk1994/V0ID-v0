#include "boolean_program_image.hpp"
#include "gpu_fhe_backend.hpp"

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

void require(bool condition, const std::string& what) {
    if (!condition)
        throw std::runtime_error(what);
}

} // namespace

int main() try {
#ifndef V0ID_GPU_FHE_ENABLED
    std::cout << "[SKIP] small FHE smoke test requires the gpu-fhe preset\n";
    return 0;
#else
    using v0id::integrity::BooleanProgramImage;
    using v0id::integrity::BooleanProgramInstruction;
    using v0id::integrity::BooleanProgramOpcode;

    // Deliberately tiny: this route proves real homomorphic execution and the
    // streamed client/evaluator boundary without paying the cost of the full
    // 2105-instruction SHA3 stress image.
    constexpr std::uint64_t input_word = 0x0123456789abcdefULL;
    constexpr std::uint64_t mask = 0xa5a55a5af0f00f0fULL;

    BooleanProgramImage image;
    image.register_count = 2;
    image.input_word_count = 1;

    BooleanProgramInstruction load;
    load.op = BooleanProgramOpcode::XorInput;
    load.dst = 0;
    load.a = 0;
    load.input_index = 0;
    image.instructions.push_back(load);

    BooleanProgramInstruction mix;
    mix.op = BooleanProgramOpcode::XorConst;
    mix.dst = 1;
    mix.a = 0;
    mix.immediate = mask;
    image.instructions.push_back(mix);

    image.output_registers = {1};
    image.validate();

    const std::vector<std::uint64_t> inputs{input_word};
    const auto plain = v0id::integrity::evaluate_boolean_program_image(image, inputs);
    require(plain.output_words.size() == 1,
            "small plaintext oracle returned wrong output count");
    require(plain.output_words[0] == (input_word ^ mask),
            "small plaintext oracle returned wrong value");

    std::cout << "V0ID small streamed TFHE CUDA smoke test\n"
              << "  instructions              : " << image.instructions.size() << '\n'
              << "  expected output           : 0x" << std::hex
              << plain.output_words[0] << std::dec << '\n';

    std::size_t last_execution = static_cast<std::size_t>(-1);
    auto progress = [&](v0id::fhe::GpuFheProgressStage stage,
                        std::size_t current,
                        std::size_t total) {
        if (stage == v0id::fhe::GpuFheProgressStage::Execution &&
            current != last_execution) {
            last_execution = current;
            std::cout << "  [CUDA] encrypted execution "
                      << current << '/' << total << '\n';
        }
    };

    auto prepared = v0id::fhe::prepare_boolean_program_image_tfhe_cuda_client(
        image, inputs, progress);
    require(!prepared.client_key_blob.empty(), "empty private client key blob");
    require(!prepared.server_key_blob.empty(), "empty evaluator server key blob");
    require(!prepared.encrypted_init_blob.empty(), "empty encrypted init blob");
    require(prepared.instruction_count == image.instructions.size(),
            "prepared session instruction count mismatch");

    std::cout << "  client key bytes          : " << prepared.client_key_blob.size() << '\n'
              << "  server key bytes (once)   : " << prepared.server_key_blob.size() << '\n'
              << "  encrypted init bytes      : " << prepared.encrypted_init_blob.size() << '\n'
              << "  evaluator receives SK     : NO\n";

    v0id::fhe::TfheCudaServerSession server(
        prepared.server_key_blob, prepared.encrypted_init_blob);

    const auto encrypted_chunk =
        v0id::fhe::encrypt_boolean_program_chunk_tfhe_cuda_client(
            prepared.client_key_blob,
            std::span<const BooleanProgramInstruction>(
                image.instructions.data(), image.instructions.size()),
            0,
            image.instructions.size(),
            progress);
    require(!encrypted_chunk.empty(), "small encrypted instruction chunk is empty");

    std::cout << "  encrypted chunk bytes     : " << encrypted_chunk.size() << '\n';

    server.evaluate_chunk(encrypted_chunk, progress);
    const auto encrypted_result = server.finish(progress);
    require(!encrypted_result.empty(), "small evaluator result blob is empty");

    const auto decrypted =
        v0id::fhe::decrypt_boolean_program_image_tfhe_cuda_client(
            prepared.client_key_blob,
            encrypted_result,
            prepared.instruction_count,
            prepared.output_word_count);

    require(decrypted == plain.output_words,
            "small streamed TFHE result differs from plaintext oracle");

    std::cout << "[PASS] real TFHE CUDA executed the tiny Boolean program\n"
              << "[PASS] client/evaluator split stayed serialized and key-separated\n"
              << "[PASS] streamed encrypted result matches the plaintext oracle\n";
    return 0;
#endif
} catch (const std::exception& e) {
    std::cerr << "small streamed TFHE smoke test FAILED: " << e.what() << '\n';
    return 1;
}
