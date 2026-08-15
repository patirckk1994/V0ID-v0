#include "boolean_ir_mutator.hpp"
#include "boolean_program_image_mutator.hpp"
#include "encrypted_boolean_program.hpp"
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

std::uint64_t decrypt_word(lbcrypto::BinFHEContext& cc,
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

    std::cout << "V0ID full encrypted SHA3-512 stress test\n"
              << "  BinFHE profile            : OpenFHE STD128Q\n"
              << "  message                   : abc\n"
              << "  registers                 : " << mutated.register_count << '\n'
              << "  input words               : " << mutated.input_word_count << '\n'
              << "  encrypted instructions    : " << mutated.instructions.size() << '\n'
              << "  encrypted logical bits    : " << logical_bits << '\n'
              << "  permuted registers        : " << mutation_stats.permuted_registers << '\n'
              << "  identity instructions     : "
              << mutation_stats.identity_instructions_inserted << '\n'
              << "  expected digest prefix    : " << hex_prefix(openssl_digest) << "...\n\n";

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
} catch (const std::exception& e) {
    std::cerr << "full encrypted SHA3 stress test FAILED: " << e.what() << '\n';
    return 1;
}
