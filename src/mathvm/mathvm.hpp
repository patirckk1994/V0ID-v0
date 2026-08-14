#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace v0id::mathvm {

inline constexpr std::uint32_t MATHVM_VERSION = 1;

// Exact, bounded value container. A scalar is represented by exactly one word;
// providers may consume/produce bounded vectors of words. No pointers, handles,
// files, sockets or host objects can exist in a MathVM value.
struct MathValue {
    std::vector<std::uint64_t> words;

    static MathValue scalar(std::uint64_t value) { return MathValue{{value}}; }
    bool is_scalar() const noexcept { return words.size() == 1; }
    std::uint64_t scalar_value() const;
};

enum class Opcode : std::uint8_t {
    constant_u64 = 1,
    add_u64 = 2,
    sub_u64 = 3,
    xor_u64 = 4,
    and_u64 = 5,
    or_u64 = 6,
    add_mod_u64 = 7,
    mul_mod_u64 = 8,
    select_u64 = 9,
    provider_call = 32,
};

// Straight-line SSA instruction. Inputs occupy registers [0,input_count).
// Every instruction writes one previously-undefined destination register and
// may only read registers that have already been defined. There are no jumps.
struct Instruction {
    Opcode opcode{Opcode::constant_u64};
    std::uint32_t dst{};
    std::vector<std::uint32_t> src;
    std::uint64_t immediate{};

    // provider_call only. Peers exchange identifiers/versions and MathVM code;
    // they never transmit native libraries through this interface.
    std::string primitive_id;
    std::uint32_t primitive_version{};
    std::vector<std::uint8_t> parameters;
};

struct Program {
    std::uint32_t vm_version{MATHVM_VERSION};
    std::uint32_t input_count{};
    std::uint32_t register_count{};
    std::vector<Instruction> instructions;
    std::vector<std::uint32_t> outputs;
};

struct SandboxLimits {
    std::size_t max_instructions{4096};
    std::size_t max_registers{4096};
    std::size_t max_inputs{128};
    std::size_t max_outputs{128};
    std::size_t max_sources_per_instruction{16};
    std::size_t max_parameter_bytes{64 * 1024};
    std::size_t max_total_parameter_bytes{1024 * 1024};
    std::size_t max_words_per_value{4096};
    std::size_t max_total_words{65536};
    std::uint64_t max_cost{10'000'000};
};

struct PrimitiveDescriptor {
    std::string id;
    std::uint32_t version{};
    std::size_t min_inputs{};
    std::size_t max_inputs{};
    std::size_t max_output_words{};
    std::uint64_t max_cost{};
};

class PrimitiveProvider {
public:
    virtual ~PrimitiveProvider() = default;
    virtual PrimitiveDescriptor descriptor() const = 0;

    // Must be deterministic from call metadata and must not inspect host state.
    // It is used before execution so the sandbox can reject oversized work.
    virtual std::uint64_t estimate_cost(
        const std::vector<std::uint8_t>& parameters,
        std::size_t input_count) const = 0;

    // Trusted local implementation of a mathematical primitive. The registry is
    // populated by the embedding process; remote peers cannot load code here.
    virtual MathValue evaluate(
        const std::vector<MathValue>& inputs,
        const std::vector<std::uint8_t>& parameters) const = 0;
};

class PrimitiveRegistry {
public:
    void register_provider(std::shared_ptr<const PrimitiveProvider> provider);
    const PrimitiveProvider& require(const std::string& id,
                                     std::uint32_t version) const;
    std::vector<PrimitiveDescriptor> descriptors() const;

private:
    using Key = std::pair<std::string, std::uint32_t>;
    std::map<Key, std::shared_ptr<const PrimitiveProvider>> providers_;
};

struct ValidationResult {
    std::uint64_t estimated_cost{};
    std::size_t provider_calls{};
    std::vector<PrimitiveDescriptor> required_providers;
};

ValidationResult validate_program(const Program& program,
                                  const PrimitiveRegistry& registry,
                                  const SandboxLimits& limits = {});

struct ExecutionResult {
    std::vector<MathValue> outputs;
    std::uint64_t estimated_cost{};
    std::size_t total_words_materialized{};
};

ExecutionResult execute_classical(const Program& program,
                                  const std::vector<MathValue>& inputs,
                                  const PrimitiveRegistry& registry,
                                  const SandboxLimits& limits = {});

std::string to_string(Opcode opcode);

} // namespace v0id::mathvm
