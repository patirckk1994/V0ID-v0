# V0ID precomputed polymorphism

V0ID does **not** require runtime self-modifying code for its polymorphism goal.

The intended model is client-side, precomputed semantic morphing: before a job is encrypted and outsourced, the client compiles one of many equivalent machine images. Each image has the same externally visible/public shape and computes the same required result, but its internal representation is rearranged.

The purpose is not to replace FHE. FHE hides encrypted transition semantics and data. Polymorphism is an additional anti-correlation layer intended to prevent a remote evaluator from acquiring a stable semantic map of repeated jobs.

## Current implementation

The first `ProgramMorpher` stage is implemented in `src/polymorph/program_morpher.*`.

It currently provides:

- a 256-bit client-side morph seed,
- KMAC-256-derived deterministic pseudorandom state placement,
- a secret mapping from base semantic states to configured public state IDs,
- fixed-size dummy-state padding,
- remapping of the initial state and every next-state transition,
- harmless identity/no-op semantics for unused padded states,
- client-side mapping metadata for testing only.

The universal FHE evaluator already processes every configured public state every round, so padded states also pad evaluator work rather than merely changing serialized metadata.

`src/main.cpp` tests two independently generated morphs of the same increment program and a morph of the decrement program. It checks plaintext semantic equivalence before running the morphs through BinFHE.

## Goal

For a base computation `P`, generate variants:

```text
P -> Morph(P, seed_1) -> P1
P -> Morph(P, seed_2) -> P2
P -> Morph(P, seed_3) -> P3
```

with:

```text
result(P1, x) == result(P2, x) == result(P3, x) == result(P, x)
```

while the evaluator sees the same public dimensions:

```text
same tape size
same state count
same alphabet
same fixed round budget
same wire format
same evaluator implementation
```

The evaluator should not receive stable metadata identifying useful computation, audit computation, scratch regions or integrity-digest locations.

## Morphing stages

### 1. State-label permutation — implemented

A KMAC-derived random placement rewrites every transition:

```text
(q, bit) -> (q2, write, move)
```

into the equivalent transition over mapped state IDs:

```text
(pi(q), bit) -> (pi(q2), write, move)
```

The initial state is mapped through the same permutation.

### 2. Padded dummy states — implemented

Every morph is padded to a configured public state count. Unused states currently act as harmless identity states:

```text
(dummy, 0) -> (dummy, 0, stay)
(dummy, 1) -> (dummy, 1, stay)
```

They are unreachable from the semantic base program, but the fixed evaluator still processes them homomorphically every round.

### 3. Scratch/output relocation — next

Randomize logical scratch and output locations before the existing KMAC physical-remapping layer is applied. No public constant should identify a special `HASH_OUTPUT_SLOT` or similar distinguished location.

### 4. Equivalent subroutine variants

Maintain multiple equivalent implementations of selected Boolean/Turing-machine operations. A morph seed chooses among them before encryption.

### 5. Interleaved integrity work

The integrity/self-fingerprint computation should not exist as one obvious contiguous public phase such as:

```text
real computation
then hash computation
```

Instead the client compiler may interleave fragments of useful work, integrity work and discardable work into one fixed-shape encrypted program.

The server executes the same universal interpreter and should not know which encrypted transitions contribute to the user-visible result, hidden integrity result or decoy work.

## Planned hidden self-fingerprint

The planned integrity mechanism is a computation embedded into the encrypted machine image that computes a fingerprint over a canonical representation of the intended job, excluding the digest slot itself.

Conceptually:

```text
digest = H(
    domain_separator ||
    canonical_program ||
    canonical_input ||
    nonce ||
    epoch
)
```

The client can compute the expected digest independently before outsourcing the job. The evaluator homomorphically computes the corresponding hidden digest while operating on encrypted program/data semantics and returns the encrypted digest with the encrypted result.

The digest location and internal transitions used to compute it may change between precomputed morphs. There is intentionally no recursive definition such as `digest = H(program || digest)`; the digest field is excluded from its own hash domain.

## Threat-model interpretation

This mechanism is intended to make selective cheating and structural correlation harder, not to claim formal Byzantine/verifiable-computation security.

FHE provides confidentiality of hidden data/program semantics. Precomputed polymorphism aims to make questions like these difficult for the evaluator:

```text
Which state corresponds to the same semantic state as last job?
Where is the integrity calculation?
Which encrypted transitions affect the final useful output?
Which encrypted transitions are decoys?
Which logical tape region contains the digest?
```

If selective cheating cannot reliably distinguish useful, audit and discardable work, the evaluator risks corrupting a hidden check whenever it skips or fabricates work.

This can later be combined with hidden known-answer jobs, occasional replication, peer scoring and stronger verifiable-computation mechanisms.

## Current API

```cpp
using MorphSeed = std::array<unsigned char, 32>;

struct MorphedProgram {
    Program program;
    std::size_t initial_state;
    std::vector<std::size_t> base_to_morphed;
    std::vector<std::size_t> dummy_states;
};

class ProgramMorpher {
public:
    static MorphSeed random_seed();

    static MorphedProgram morph(
        const Program& base,
        std::size_t base_initial_state,
        std::size_t public_state_count,
        const MorphSeed& seed);
};
```

`base_to_morphed` and `dummy_states` are compiler/test metadata. They are not intended to accompany an encrypted job to an untrusted evaluator.

## Required tests

The local demo currently checks:

```text
plaintext(base, input, N)
    == plaintext(morph(seed_A), input, N)
    == plaintext(morph(seed_B), input, N)
    == decrypt(FHE(morph(seed_A), Enc(input), N))
    == decrypt(FHE(morph(seed_B), Enc(input), N))
```

and verifies that generated variants expose the same configured public state count and fixed work budget.

More exhaustive randomized differential tests should be added as the morph compiler gains scratch relocation, subroutine variants and integrity work.

## Summary

V0ID polymorphism means:

> The program does not have to change while the evaluator watches it. The client can precompute a different semantically equivalent encrypted machine image for every job, so the evaluator never receives a stable map of where any particular computation — especially the hidden self-check — lives.
