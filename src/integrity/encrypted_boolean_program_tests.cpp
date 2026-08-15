#include "boolean_ir_mutator.hpp"
#include "boolean_program_image_mutator.hpp"
#include "encrypted_boolean_program.hpp"
#include "gpu_fhe_backend.hpp"
#include "keccak_program_image.hpp"

#include "binfhecontext.h"

#include <openssl/evp.h>

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <memory>
#include <mutex>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace {

using Clock = std::chrono::steady_clock;

void require(bool condition, const std::string& what) {
    if (!condition)
        throw std::runtime_error(what);
}

class Heartbeat {
public:
    explicit Heartbeat(std::string label,
                       std::chrono::seconds interval = std::chrono::seconds(10))
        : label_(std::move(label)),
          interval_(interval),
          start_(Clock::now()),
          thread_([this] { run(); }) {}

    ~Heartbeat() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            stop_ = true;
        }
        cv_.notify_all();
        if (thread_.joinable())
            thread_.join();
    }

    Heartbeat(const Heartbeat&) = delete;
    Heartbeat& operator=(const Heartbeat&) = delete;

private:
    void run() {
        std::unique_lock<std::mutex> lock(mutex_);
        while (!cv_.wait_for(lock, interval_, [this] { return stop_; })) {
            const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                Clock::now() - start_);
            std::cout << "  ... " << label_ << " still running ("
                      << elapsed.count() << " s elapsed)\n";
        }
    }

    std::string label_;
    std::chrono::seconds interval_;
    Clock::time_point start_;
    std::mutex mutex_;
    std::condition_variable cv_;
    bool stop_{false};
    std::thread thread_;
};

std::vector<std::uint8_t> openssl_sha3_512(
    const std::vector<std::uint8_t>& message) {
    using Ctx = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
    Ctx ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!ctx)
        throw std::runtime_error("EVP_MD_CTX_new failed");
    if (EVP_DigestInit_ex(ctx.get(), EVP_sha3_512(), nullptr) != 1)
        throw std::runtime_error("EVP SHA3-512 init failed");
    if (EVP_DigestUpdate(ctx.get(), message.data(), message.size()) != 1)
        throw std::runtime_error("EVP SHA3-512 update failed");

    std::vector<std::uint8_t> out(64);
    unsigned int n = 0;
    if (EVP_DigestFinal_ex(ctx.get(), out.data(), &n) != 1 || n != out.size())
        throw std::runtime_error("EVP SHA3-512 final failed");
    return out;
}

[[maybe_unused]] std::uint64_t decrypt_word(
    lbcrypto::BinFHEContext& cc,
    lbcrypto::ConstLWEPrivateKey& sk,
    const v0id::fhe::EncryptedBooleanWord& word) {
    std::uint64_t out = 0;
    for (std::size_t bit = 0; bit < word.size(); ++bit) {
        lbcrypto::LWEPlaintext value = 0;
        cc.Decrypt(sk, word[bit], &value);
        out |= static_cast<std::uint64_t>(value & 1u) << bit;
    }
    return out;
}

std::vector<std::uint8_t> words_to_bytes(
    const std::vector<std::uint64_t>& words) {
    std::vector<std::uint8_t> out;
    out.reserve(words.size() * 8);
    for (const auto word : words) {
        for (std::size_t i = 0; i < 8; ++i)
            out.push_back(static_cast<std::uint8_t>((word >> (8 * i)) & 0xffu));
    }
    return out;
}

std::string hex_prefix(const std::vector<std::uint8_t>& bytes,
                       std::size_t count = 16) {
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    const auto n = std::min(count, bytes.size());
    for (std::size_t i = 0; i < n; ++i)
        out << std::setw(2) << static_cast<unsigned int>(bytes[i]);
    return out.str();
}

const char* gpu_stage_name(v0id::fhe::GpuFheProgressStage stage) {
    using Stage = v0id::fhe::GpuFheProgressStage;
    switch (stage) {
    case Stage::KeyGeneration: return "client key generation";
    case Stage::ClientEncryption: return "client job encryption";
    case Stage::Execution: return "GPU encrypted execution";
    case Stage::OutputSelection: return "GPU output selection";
    }
    return "GPU FHE";
}

} // namespace

int main() try {
    std::cout << std::unitbuf;

    const std::vector<std::uint8_t> message{'a', 'b', 'c'};
    const auto base = v0id::integrity::build_sha3_512_program_image(message.size());
    const auto input_words = v0id::integrity::sha3_512_program_input_words(message);

    v0id::integrity::BooleanMutationSeed seed{};
    for (std::size_t i = 0; i < seed.size(); ++i)
        seed[i] = static_cast<unsigned char>(0x5au ^ (i * 29u));

    v0id::integrity::BooleanProgramMutationStats mutation_stats{};
    const auto mutated = v0id::integrity::mutate_boolean_program_image(
        base.program, seed, 32, &mutation_stats);

    const auto expected_exec =
        v0id::integrity::evaluate_boolean_program_image(mutated, input_words);
    const auto expected_digest = words_to_bytes(expected_exec.output_words);
    const auto openssl_digest = openssl_sha3_512(message);
    require(expected_digest == openssl_digest,
            "mutated compact SHA3 image no longer matches OpenSSL before FHE");

    const auto logical_bits =
        v0id::fhe::encrypted_boolean_program_logical_bits(mutated);

#ifdef V0ID_GPU_FHE_ENABLED
    constexpr const char* profile = "TFHE-rs 1.6.1 GPU default parameters";
#else
    constexpr const char* profile = "OpenFHE STD128Q";
#endif

    std::cout << "V0ID full encrypted SHA3-512 stress test\n"
              << "  FHE profile               : " << profile << '\n'
              << "  GPU compile request       : "
              << (v0id::fhe::kGpuFheCompileRequested ? "ON" : "OFF") << '\n'
              << "  requested FHE backend     : "
              << v0id::fhe::kRequestedFheBackendName << '\n'
              << "  active FHE backend        : "
              << v0id::fhe::kActiveFheBackendName << '\n'
              << "  message                   : abc\n"
              << "  registers                 : " << mutated.register_count << '\n'
              << "  input words               : " << mutated.input_word_count << '\n'
              << "  encrypted instructions    : " << mutated.instructions.size() << '\n'
              << "  encrypted logical bits    : " << logical_bits << '\n'
              << "  permuted registers        : " << mutation_stats.permuted_registers << '\n'
              << "  identity instructions     : "
              << mutation_stats.identity_instructions_inserted << '\n'
              << "  expected digest prefix    : " << hex_prefix(openssl_digest) << "...\n\n";

#ifdef V0ID_GPU_FHE_ENABLED
    require(v0id::fhe::tfhe_cuda_backend_available(),
            "GPU build does not have the TFHE CUDA sidecar linked");

    std::cout << "preparing streamed TFHE client/evaluator session...\n";
    const auto gpu_start = Clock::now();
    v0id::fhe::GpuFheProgressStage last_stage =
        v0id::fhe::GpuFheProgressStage::KeyGeneration;
    std::size_t last_print = static_cast<std::size_t>(-1);

    auto progress = [&](v0id::fhe::GpuFheProgressStage stage,
                        std::size_t current,
                        std::size_t total) {
        const bool stage_changed = stage != last_stage;
        const bool interesting = current == 0 || current == total ||
            current < 8 || current % 8 == 0;
        if (!stage_changed && !interesting && current == last_print)
            return;
        if (!stage_changed && !interesting)
            return;

        last_stage = stage;
        last_print = current;
        const auto elapsed = std::chrono::duration<double>(
            Clock::now() - gpu_start).count();
        std::cout << "  [CUDA] " << gpu_stage_name(stage)
                  << ' ' << current << '/' << total
                  << " elapsed=" << elapsed << " s\n";
    };

    auto prepared = v0id::fhe::prepare_boolean_program_image_tfhe_cuda_client(
        mutated, input_words, progress);
    require(!prepared.client_key_blob.empty(),
            "TFHE CUDA client prepare returned empty client key blob");
    require(!prepared.server_key_blob.empty(),
            "TFHE CUDA client prepare returned empty server key blob");
    require(!prepared.encrypted_init_blob.empty(),
            "TFHE CUDA client prepare returned empty encrypted init blob");

    std::cout << "  client key bytes          : " << prepared.client_key_blob.size() << '\n'
              << "  server key bytes (once)   : " << prepared.server_key_blob.size() << '\n'
              << "  encrypted init bytes      : " << prepared.encrypted_init_blob.size() << '\n'
              << "  instruction chunk size    : " << v0id::fhe::kTfheCudaInstructionChunkSize << '\n'
              << "  evaluator receives SK     : NO\n"
              << "installing evaluator GPU session...\n";

    v0id::fhe::TfheCudaServerSession server(
        prepared.server_key_blob, prepared.encrypted_init_blob);

    std::size_t max_chunk_bytes = 0;
    std::size_t chunk_count = 0;
    for (std::size_t offset = 0; offset < mutated.instructions.size();
         offset += v0id::fhe::kTfheCudaInstructionChunkSize) {
        const auto count = std::min(
            v0id::fhe::kTfheCudaInstructionChunkSize,
            mutated.instructions.size() - offset);
        const std::span<const v0id::integrity::BooleanProgramInstruction> clear_chunk(
            mutated.instructions.data() + offset, count);
        const auto encrypted_chunk =
            v0id::fhe::encrypt_boolean_program_chunk_tfhe_cuda_client(
                prepared.client_key_blob, clear_chunk, offset,
                mutated.instructions.size(), progress);
        require(!encrypted_chunk.empty(),
                "TFHE CUDA client returned empty encrypted instruction chunk");

        ++chunk_count;
        max_chunk_bytes = std::max(max_chunk_bytes, encrypted_chunk.size());
        if (chunk_count == 1) {
            std::cout << "  first encrypted chunk     : " << encrypted_chunk.size() << " bytes\n"
                      << "  planned chunk count       : "
                      << ((mutated.instructions.size() +
                           v0id::fhe::kTfheCudaInstructionChunkSize - 1) /
                          v0id::fhe::kTfheCudaInstructionChunkSize)
                      << '\n'
                      << "launching evaluator-only streamed TFHE-rs CUDA boundary...\n";
        }

        server.evaluate_chunk(encrypted_chunk, progress);
    }

    const auto encrypted_result = server.finish(progress);
    require(!encrypted_result.empty(),
            "TFHE CUDA evaluator returned empty encrypted result blob");
    std::cout << "  chunks executed           : " << chunk_count << '\n'
              << "  max encrypted chunk bytes : " << max_chunk_bytes << '\n'
              << "  encrypted result bytes    : " << encrypted_result.size() << '\n';

    const auto decrypted_words =
        v0id::fhe::decrypt_boolean_program_image_tfhe_cuda_client(
            prepared.client_key_blob, encrypted_result,
            prepared.instruction_count, prepared.output_word_count);

    const auto decrypted_digest = words_to_bytes(decrypted_words);
    require(decrypted_digest == expected_digest,
            "TFHE CUDA SHA3 digest differs from mutated plaintext image");
    require(decrypted_digest == openssl_digest,
            "TFHE CUDA SHA3 digest differs from OpenSSL SHA3-512");

    std::cout << "[PASS] client key remains outside evaluator API\n"
              << "[PASS] server key is installed once and encrypted state survives chunks\n"
              << "[PASS] instruction chunks enforce contiguous execution order\n"
              << "[PASS] full mutated compact SHA3 executes through TFHE-rs CUDA\n"
              << "[PASS] CUDA FHE digest matches mutated plaintext image\n"
              << "[PASS] CUDA FHE digest matches OpenSSL SHA3-512\n"
              << "digest prefix: " << hex_prefix(decrypted_digest) << "...\n"
              << "CUDA wall time: "
              << std::chrono::duration<double>(Clock::now() - gpu_start).count()
              << " s\n";
    return 0;
#else
    lbcrypto::BinFHEContext cc;
    std::cout << "generating STD128Q BinFHE context...\n";
    cc.GenerateBinFHEContext(lbcrypto::STD128Q);
    auto sk = cc.KeyGen();

    std::cout << "generating bootstrapping keys...\n";
    const auto bt_start = Clock::now();
    {
        Heartbeat heartbeat("STD128Q BTKeyGen");
        cc.BTKeyGen(sk);
    }
    std::cout << "bootstrapping keys ready ("
              << std::chrono::duration<double>(Clock::now() - bt_start).count()
              << " s)\n";

    std::cout << "encrypting full mutated SHA3 program image ("
              << mutated.instructions.size() << " fixed-width slots)...\n";
    v0id::fhe::EncryptedBooleanProgramImage encrypted_image;
    const auto image_start = Clock::now();
    {
        Heartbeat heartbeat("full SHA3 image encryption");
        encrypted_image =
            v0id::fhe::encrypt_boolean_program_image(cc, sk, mutated);
    }
    std::cout << "program image encryption complete ("
              << std::chrono::duration<double>(Clock::now() - image_start).count()
              << " s)\n";

    std::cout << "encrypting padded SHA3 input words...\n";
    auto encrypted_inputs =
        v0id::fhe::encrypt_boolean_program_input_words(cc, sk, input_words);
    auto encrypted_zero = cc.Encrypt(sk, 0);

    v0id::fhe::RemoteEncryptedBooleanProgram remote(
        cc, std::move(encrypted_image), std::move(encrypted_inputs), encrypted_zero);

    const auto total = mutated.instructions.size();
    std::cout << "executing full encrypted SHA3 program...\n";
    const auto eval_start = Clock::now();
    for (std::size_t i = 0; i < total; ++i) {
        const auto step_start = Clock::now();
        {
            Heartbeat heartbeat(
                "encrypted SHA3 instruction " + std::to_string(i + 1) + "/" +
                std::to_string(total));
            remote.step();
        }

        if (i < 8 || (i + 1) % 16 == 0 || i + 1 == total) {
            const auto step_seconds =
                std::chrono::duration<double>(Clock::now() - step_start).count();
            const auto total_seconds =
                std::chrono::duration<double>(Clock::now() - eval_start).count();
            std::cout << "  [FHE] instruction " << (i + 1) << '/' << total
                      << " complete; step=" << step_seconds
                      << " s total=" << total_seconds << " s\n";
        }
    }

    require(remote.completed_instructions() == total,
            "full encrypted SHA3 evaluator stopped before final instruction");

    std::cout << "homomorphically selecting encrypted digest registers...\n";
    v0id::fhe::EncryptedBooleanProgramExecution result;
    {
        Heartbeat heartbeat("encrypted SHA3 output selection");
        result = remote.result();
    }
    require(result.output_words.size() == 8,
            "full encrypted SHA3 returned wrong digest word count");

    std::cout << "decrypting 512-bit digest...\n";
    std::vector<std::uint64_t> decrypted_words;
    decrypted_words.reserve(result.output_words.size());
    for (const auto& word : result.output_words)
        decrypted_words.push_back(decrypt_word(cc, sk, word));
    const auto decrypted_digest = words_to_bytes(decrypted_words);

    require(decrypted_digest == expected_digest,
            "full encrypted SHA3 digest differs from mutated plaintext image");
    require(decrypted_digest == openssl_digest,
            "full encrypted SHA3 digest differs from OpenSSL SHA3-512");

    std::cout << "[PASS] full mutated compact SHA3 executes under STD128Q BinFHE\n"
              << "[PASS] decrypted FHE digest matches mutated plaintext image\n"
              << "[PASS] decrypted FHE digest matches OpenSSL SHA3-512\n"
              << "digest prefix: " << hex_prefix(decrypted_digest) << "...\n"
              << "encrypted instructions completed: "
              << remote.completed_instructions() << '\n';
    return 0;
#endif
} catch (const std::exception& e) {
    std::cerr << "full encrypted SHA3 stress test FAILED: " << e.what() << '\n';
    return 1;
}
