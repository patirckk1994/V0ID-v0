#include "gpu_fhe_backend.hpp"

#include <array>
#include <stdexcept>
#include <string>
#include <utility>

namespace v0id::fhe {
namespace {

[[noreturn]] void throw_unavailable() {
    throw std::runtime_error(
        "TFHE CUDA backend was not compiled; configure with V0ID_ENABLE_GPU_FHE=ON");
}

#ifdef V0ID_GPU_FHE_ENABLED

struct TfheInstructionC {
    std::uint32_t op{};
    std::uint32_t dst{};
    std::uint32_t a{};
    std::uint32_t b{};
    std::uint32_t c{};
    std::uint32_t d{};
    std::uint32_t e{};
    std::uint32_t input_index{};
    std::uint32_t rotate{};
    std::uint64_t immediate{};
};

struct TfheBlobC {
    std::uint8_t* data{};
    std::size_t len{};
};

using TfheProgressFn = void (*)(std::uint32_t, std::uint64_t, std::uint64_t);

extern "C" int v0id_tfhe_cuda_client_prepare(
    const TfheInstructionC* instructions,
    std::size_t instruction_count,
    std::size_t register_count,
    const std::uint64_t* input_words,
    std::size_t input_word_count,
    const std::uint32_t* output_registers,
    std::size_t output_register_count,
    TfheBlobC* client_key_out,
    TfheBlobC* server_key_out,
    TfheBlobC* encrypted_job_out,
    TfheProgressFn progress_cb);

extern "C" int v0id_tfhe_cuda_server_evaluate(
    const std::uint8_t* server_key_data,
    std::size_t server_key_len,
    const std::uint8_t* encrypted_job_data,
    std::size_t encrypted_job_len,
    TfheBlobC* encrypted_result_out,
    TfheProgressFn progress_cb);

extern "C" int v0id_tfhe_cuda_client_decrypt(
    const std::uint8_t* client_key_data,
    std::size_t client_key_len,
    const std::uint8_t* encrypted_result_data,
    std::size_t encrypted_result_len,
    std::uint64_t* output_words,
    std::size_t output_word_capacity,
    std::size_t* output_word_count);

extern "C" void v0id_tfhe_cuda_blob_free(TfheBlobC* blob);

extern "C" std::size_t v0id_tfhe_cuda_last_error(
    std::uint8_t* buffer,
    std::size_t capacity);

thread_local GpuFheProgressCallback* g_progress = nullptr;

extern "C" void progress_trampoline(std::uint32_t stage,
                                      std::uint64_t current,
                                      std::uint64_t total) {
    if (!g_progress || !*g_progress)
        return;
    (*g_progress)(static_cast<GpuFheProgressStage>(stage),
                  static_cast<std::size_t>(current),
                  static_cast<std::size_t>(total));
}

std::string last_tfhe_error() {
    std::array<std::uint8_t, 2048> buffer{};
    const auto needed = v0id_tfhe_cuda_last_error(buffer.data(), buffer.size());
    if (needed == 0)
        return "TFHE CUDA backend failed without an error string";
    return std::string(reinterpret_cast<const char*>(buffer.data()));
}

class RustBlob final {
public:
    RustBlob() = default;
    ~RustBlob() { v0id_tfhe_cuda_blob_free(&blob_); }

    RustBlob(const RustBlob&) = delete;
    RustBlob& operator=(const RustBlob&) = delete;

    TfheBlobC* out() { return &blob_; }

    std::vector<std::uint8_t> copy() const {
        if (blob_.len == 0)
            return {};
        if (!blob_.data)
            throw std::runtime_error("TFHE CUDA sidecar returned a null non-empty blob");
        return std::vector<std::uint8_t>(blob_.data, blob_.data + blob_.len);
    }

private:
    TfheBlobC blob_{};
};

std::vector<TfheInstructionC> encode_instructions(
    const v0id::integrity::BooleanProgramImage& image) {
    std::vector<TfheInstructionC> instructions;
    instructions.reserve(image.instructions.size());
    for (const auto& ins : image.instructions) {
        TfheInstructionC out;
        out.op = static_cast<std::uint32_t>(ins.op);
        out.dst = ins.dst;
        out.a = ins.a;
        out.b = ins.b;
        out.c = ins.c;
        out.d = ins.d;
        out.e = ins.e;
        out.input_index = ins.input_index;
        out.rotate = ins.rotate;
        out.immediate = ins.immediate;
        instructions.push_back(out);
    }
    return instructions;
}

std::vector<std::uint32_t> encode_outputs(
    const v0id::integrity::BooleanProgramImage& image) {
    std::vector<std::uint32_t> outputs;
    outputs.reserve(image.output_registers.size());
    for (const auto reg : image.output_registers)
        outputs.push_back(reg);
    return outputs;
}

TfheProgressFn install_progress(GpuFheProgressCallback& progress) {
    g_progress = &progress;
    return progress ? &progress_trampoline : nullptr;
}

void clear_progress() {
    g_progress = nullptr;
}

#endif

} // namespace

bool tfhe_cuda_backend_available() {
#ifdef V0ID_GPU_FHE_ENABLED
    return true;
#else
    return false;
#endif
}

TfheCudaPreparedJob prepare_boolean_program_image_tfhe_cuda_client(
    const v0id::integrity::BooleanProgramImage& image,
    const std::vector<std::uint64_t>& input_words,
    GpuFheProgressCallback progress) {
#ifndef V0ID_GPU_FHE_ENABLED
    (void)image;
    (void)input_words;
    (void)progress;
    throw_unavailable();
#else
    image.validate();
    if (input_words.size() != image.input_word_count)
        throw std::runtime_error("TFHE CUDA input word count mismatch");

    const auto instructions = encode_instructions(image);
    const auto outputs = encode_outputs(image);
    RustBlob client_key;
    RustBlob server_key;
    RustBlob encrypted_job;

    const auto callback = install_progress(progress);
    const auto rc = v0id_tfhe_cuda_client_prepare(
        instructions.data(), instructions.size(), image.register_count,
        input_words.empty() ? nullptr : input_words.data(), input_words.size(),
        outputs.data(), outputs.size(),
        client_key.out(), server_key.out(), encrypted_job.out(), callback);
    clear_progress();

    if (rc != 0)
        throw std::runtime_error(last_tfhe_error());

    TfheCudaPreparedJob prepared;
    prepared.client_key_blob = client_key.copy();
    prepared.server_key_blob = server_key.copy();
    prepared.encrypted_job_blob = encrypted_job.copy();
    prepared.output_word_count = outputs.size();
    return prepared;
#endif
}

std::vector<std::uint8_t> evaluate_boolean_program_image_tfhe_cuda_server(
    const std::vector<std::uint8_t>& server_key_blob,
    const std::vector<std::uint8_t>& encrypted_job_blob,
    GpuFheProgressCallback progress) {
#ifndef V0ID_GPU_FHE_ENABLED
    (void)server_key_blob;
    (void)encrypted_job_blob;
    (void)progress;
    throw_unavailable();
#else
    if (server_key_blob.empty() || encrypted_job_blob.empty())
        throw std::runtime_error("TFHE CUDA evaluator received an empty cloud blob");

    RustBlob encrypted_result;
    const auto callback = install_progress(progress);
    const auto rc = v0id_tfhe_cuda_server_evaluate(
        server_key_blob.data(), server_key_blob.size(),
        encrypted_job_blob.data(), encrypted_job_blob.size(),
        encrypted_result.out(), callback);
    clear_progress();

    if (rc != 0)
        throw std::runtime_error(last_tfhe_error());
    return encrypted_result.copy();
#endif
}

std::vector<std::uint64_t> decrypt_boolean_program_image_tfhe_cuda_client(
    const std::vector<std::uint8_t>& client_key_blob,
    const std::vector<std::uint8_t>& encrypted_result_blob,
    std::size_t expected_output_word_count) {
#ifndef V0ID_GPU_FHE_ENABLED
    (void)client_key_blob;
    (void)encrypted_result_blob;
    (void)expected_output_word_count;
    throw_unavailable();
#else
    if (client_key_blob.empty() || encrypted_result_blob.empty())
        throw std::runtime_error("TFHE CUDA client decrypt received an empty cloud blob");
    if (expected_output_word_count == 0)
        throw std::runtime_error("TFHE CUDA expected output count must be positive");

    std::vector<std::uint64_t> outputs(expected_output_word_count, 0);
    std::size_t written = 0;
    const auto rc = v0id_tfhe_cuda_client_decrypt(
        client_key_blob.data(), client_key_blob.size(),
        encrypted_result_blob.data(), encrypted_result_blob.size(),
        outputs.data(), outputs.size(), &written);
    if (rc != 0)
        throw std::runtime_error(last_tfhe_error());
    if (written != expected_output_word_count)
        throw std::runtime_error("TFHE CUDA evaluator returned unexpected output cardinality");
    return outputs;
#endif
}

std::vector<std::uint64_t> evaluate_boolean_program_image_tfhe_cuda(
    const v0id::integrity::BooleanProgramImage& image,
    const std::vector<std::uint64_t>& input_words,
    GpuFheProgressCallback progress) {
#ifndef V0ID_GPU_FHE_ENABLED
    (void)image;
    (void)input_words;
    (void)progress;
    throw_unavailable();
#else
    auto prepared = prepare_boolean_program_image_tfhe_cuda_client(
        image, input_words, progress);

    // This call intentionally receives only evaluator-visible material. The
    // client key remains in prepared.client_key_blob and never crosses the API.
    const auto encrypted_result = evaluate_boolean_program_image_tfhe_cuda_server(
        prepared.server_key_blob, prepared.encrypted_job_blob, progress);

    return decrypt_boolean_program_image_tfhe_cuda_client(
        prepared.client_key_blob, encrypted_result, prepared.output_word_count);
#endif
}

} // namespace v0id::fhe
