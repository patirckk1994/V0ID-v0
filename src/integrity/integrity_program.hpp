#pragma once

#include "canonical_self_image.hpp"
#include "integrity_program_compiler.hpp"
#include "program_morpher.hpp"
#include "series_first_stack.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace v0id::integrity {

struct IntegrityHashProfile {
    std::string algorithm_id;
    std::uint64_t algorithm_version{1};
    std::size_t digest_bytes{};

    bool operator==(const IntegrityHashProfile&) const = default;
};

// Client-side reference backend. This computes the expected digest over the
// canonical self-image. It is intentionally separate from the runtime Program
// hook: the runtime hook must synthesize a machine implementation that consumes
// the encrypted canonical subject during execution rather than asking the server
// to call this plaintext backend.
class IntegrityHashBackend {
public:
    virtual ~IntegrityHashBackend() = default;
    virtual IntegrityHashProfile profile() const = 0;
    virtual std::vector<std::uint8_t> digest(
        const std::vector<std::uint8_t>& canonical_subject) const = 0;
};

// Strong default reference primitive. Uses OpenSSL SHA3-512. This class does NOT
// claim to lower Keccak into the current one-tape Program model; a runtime hook
// must provide a real Program implementation or construction fails closed.
class Sha3_512IntegrityHashBackend final : public IntegrityHashBackend {
public:
    IntegrityHashProfile profile() const override;
    std::vector<std::uint8_t> digest(
        const std::vector<std::uint8_t>& canonical_subject) const override;
};

struct IntegrityProgramBuildRequest {
    IntegrityHashProfile hash_profile;
    std::size_t canonical_subject_bits{};
    std::size_t digest_bits{};

    // Private algorithm-later material derived from StackPurpose::execution_integrity.
    // It may drive decomposition, state allocation, instruction ordering, dummy
    // work and other implementation mutations. It is never part of RMJ3 itself.
    std::vector<std::uint8_t> private_algorithm_material;
};

struct IntegrityProgramArtifact {
    v0id::core::Program program;
    std::size_t initial_state{};
    std::size_t rounds{};

    // Issuer-only metadata produced by the hook/module. Never required by the
    // remote evaluator and deliberately absent from wire codecs.
    std::vector<std::uint8_t> private_manifest;
};

// Private client-side hook that synthesizes the runtime integrity Program.
// Implementations may be native trusted code or adapters around sandboxed local
// modules. There is intentionally no serialize()/wire method on this interface.
class IntegrityProgramHook {
public:
    virtual ~IntegrityProgramHook() = default;

    virtual std::string local_id() const = 0;
    virtual std::uint64_t local_version() const = 0;
    virtual IntegrityHashProfile supported_hash() const = 0;

    // Private binding mixed only after the execution_integrity purpose series has
    // been derived. A local module adapter should normally return a digest of its
    // exact module bytes plus local id/version.
    virtual std::vector<std::uint8_t> private_binding() const = 0;

    virtual IntegrityProgramArtifact build(
        const IntegrityProgramBuildRequest& request) const = 0;
};

// Convenience adapter for private-local modules/hooks. `module_bytes` never have
// a transport path here. `runner` is the trusted/sandbox adapter that turns the
// private module into a validated Program artifact; a future WAMR adapter can
// implement that runner without changing the execution-integrity architecture.
class PrivateLocalIntegrityProgramHook final : public IntegrityProgramHook {
public:
    using Runner = std::function<IntegrityProgramArtifact(
        const IntegrityProgramBuildRequest&,
        const std::vector<std::uint8_t>& module_bytes)>;

    PrivateLocalIntegrityProgramHook(std::string local_id,
                                     std::uint64_t local_version,
                                     IntegrityHashProfile supported_hash,
                                     std::vector<std::uint8_t> module_bytes,
                                     Runner runner);

    std::string local_id() const override;
    std::uint64_t local_version() const override;
    IntegrityHashProfile supported_hash() const override;
    std::vector<std::uint8_t> private_binding() const override;
    IntegrityProgramArtifact build(
        const IntegrityProgramBuildRequest& request) const override;

private:
    std::string local_id_;
    std::uint64_t local_version_{};
    IntegrityHashProfile supported_hash_;
    std::vector<std::uint8_t> module_bytes_;
    Runner runner_;
};

struct CombinedIntegrityExecutable {
    v0id::core::BoundedIntegrityProgram combined;
    v0id::polymorph::MorphedProgram morphed;

    // Mapped state ids occupied by the integrity implementation in the final
    // polymorphic image. Client-private; used to mask those rows from the
    // canonical self-image and never required by the evaluator.
    std::vector<std::size_t> morphed_integrity_states;

    std::vector<std::uint8_t> canonical_subject;
    std::vector<int> canonical_subject_bits;
    std::vector<std::uint8_t> expected_digest;
    std::vector<std::uint8_t> private_algorithm_material;

    std::size_t total_execution_rounds{};
};

// Batch-B construction boundary:
//
// execution_integrity purpose series already exists
//        -> algorithm-later hash/profile + private hook binding
//        -> private hook builds runtime integrity Program
//        -> semantic + integrity Programs are combined
//        -> ONE ProgramMorpher pass covers the whole machine
//        -> final morphed integrity rows are masked from CanonicalSelfImageV1
//        -> client reference backend hashes that exact final subject
//
// This function does not put the canonical subject onto RMJ3 yet; the next
// network batch must encrypt/provide it as runtime-readable data for the embedded
// integrity Program. Until that exists, this object is construction evidence,
// not an execution-proof acceptance path.
CombinedIntegrityExecutable build_combined_integrity_executable(
    const v0id::core::Program& semantic_program,
    std::size_t semantic_initial_state,
    std::size_t semantic_rounds,
    std::size_t public_state_count,
    std::size_t integrity_candidate_count,
    const v0id::crypto::StackSeriesKey& execution_integrity_series,
    const v0id::polymorph::MorphSeed& whole_machine_morph_seed,
    CanonicalSelfImageContext self_image_context,
    const IntegrityHashBackend& hash_backend,
    const IntegrityProgramHook& program_hook);

} // namespace v0id::integrity
