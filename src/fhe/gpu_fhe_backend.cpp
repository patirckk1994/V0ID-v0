#include "gpu_fhe_backend.hpp"

#include <array>
#include <stdexcept>
#include <string>
#include <utility>

namespace v0id::fhe {
namespace {

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

using TfheProgressFn = void (*)(std::uint32_t, std::uint64_t, std::uint64_t);

extern "C" int v0id_tfhe_cuda_run_program(
    const TfheInstructionC* instructions,
    std::size_t instruction_count,
    std::size_t register_count,
    const std::uint64_t* input_words,
    std::size_t input_word_count,
    const std::uint32_t* output_registers,
    std::size_t output_register_count,
    std::uint64_t* output_words,
    std::size_t output_word_capacity,
    TfheProgressFn progress_cb);

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

#endif

} // namespace

bool tfhe_cuda_backend_available() {
#ifdef V0ID_GPU_FHE_ENABLED
    return true;
#else
    return false;
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
    throw std::runtime_error(
        "TFHE CUDA backend was not compiled; configure with V0ID_ENABLE_GPU_FHE=ON");
#else
    image.validate();
    if (input_words.size() != image.input_word_count)
        throw std::runtime_error("TFHE CUDA input word count mismatch");

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

    std::vector<std::uint32_t> outputs;
    outputs.reserve(image.output_registers.size());
    for (const auto reg : image.output_registers)
        outputs.push_back(reg);

    std::vector<std::uint64_t> result(outputs.size(), 0);
    g_progress = &progress;
    const auto rc = v0id_tfhe_cuda_run_program(
        instructions.data(), instructions.size(), image.register_count,
        input_words.empty() ? nullptr : input_words.data(), input_words.size(),
        outputs.data(), outputs.size(), result.data(), result.size(),
        progress ? &progress_trampoline : nullptr);
    g_progress = nullptr;

    if (rc != 0)
        throw std::runtime_error(last_tfhe_error());
    return result;
#endif
}

} // namespace v0id::fhe
