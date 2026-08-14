# V0ID precomputed polymorphism

V0ID does **not** require runtime self-modifying code for its polymorphism goal.

The intended model is client-side, precomputed semantic morphing: before a job is encrypted and outsourced, the client compiles one of many equivalent machine images. Each image has the same externally visible/public shape and computes the same required result, but its internal representation is rearranged.

The purpose is not to replace FHE. FHE hides the encrypted transition semantics and data. Polymorphism is an additional anti-correlation layer intended to prevent a remote evaluator from acquiring a stable semantic map of repeated jobs.

## Goal

For a base computation `P`, generate variants:

```text
P -> Morph(P, seed_1) -> P1
P -> Morph(P, seed_2) -> P2
P -> Morph(P, seed_3) -> P3
```

with these invariants:

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

The evaluator should not receive stable metadata that says where the useful computation, audit computation, scratch region, or integrity digest lives.

## First morphing operations

The initial `ProgramMorpher` should be deliberately simple and testable.

### 1. State-label permutation

Generate a random bijection `pi` over state IDs and rewrite every transition:

```text
(q, bit) -> (q2, write, move)
```

as:

```text
(pi(q), bit) -> (pi(q2), write, move)
```

The machine is semantically equivalent, but state identities no longer have stable meaning across jobs.

### 2. Padded dummy states

Pad every job to a configured public state count. Dummy states may execute harmless/no-op or discarded computations so that the useful program size does not reveal which morph is in use.

### 3. Scratch/output relocation

Randomize logical scratch and output locations before the existing KMAC physical remapping layer is applied. No public constant should identify a special `HASH_OUTPUT_SLOT` or similar distinguished location.

### 4. Equivalent subroutine variants

Maintain multiple equivalent implementations of selected Boolean/Turing-machine operations. A morph seed chooses among them before encryption.

### 5. Interleaved integrity work

The integrity/self-fingerprint computation should not exist as one obvious contiguous public phase such as:

```text
real computation
then hash computation
```

Instead the client compiler may interleave fragments of useful work, integrity work, and discardable work into one fixed-shape encrypted program.

The server executes the same universal interpreter and should not know which encrypted transitions contribute to the user-visible result, which contribute to the hidden integrity result, or which are decoys.

## Hidden self-fingerprint

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

The client can compute the expected digest independently before outsourcing the job.

The evaluator homomorphically computes the corresponding hidden digest while operating on encrypted data/program semantics and returns the encrypted digest with the encrypted result.

The digest location and the internal transitions used to compute it are allowed to change between precomputed morphs.

There is intentionally no recursive definition such as `digest = H(program || digest)`: the digest field is excluded from its own hash domain.

## Threat-model interpretation

This mechanism is intended to make selective cheating and structural correlation harder, not to claim formal Byzantine/verifiable-computation security.

FHE provides confidentiality of the hidden data/program semantics.

Precomputed polymorphism aims to make questions such as these difficult for the evaluator:

```text
Which state corresponds to the same semantic state as last job?
Where is the integrity calculation?
Which encrypted transitions affect the final useful output?
Which encrypted transitions are decoys?
Which logical tape region contains the digest?
```

If selective cheating cannot reliably distinguish useful, audit, and discardable work, the evaluator risks corrupting a hidden check whenever it skips or fabricates work.

This can later be combined with hidden known-answer jobs, occasional replication, peer scoring, and stronger verifiable-computation mechanisms.

## Proposed API

A later implementation should expose a client-side compiler approximately like:

```cpp
struct MorphOptions {
    std::size_t public_state_count;
    std::size_t public_tape_size;
    std::size_t fixed_round_budget;
    std::size_t dummy_state_count;
};

struct MorphedProgram {
    Program program;
    std::vector<std::size_t> state_permutation;
    std::vector<std::size_t> logical_slot_permutation;
    std::size_t integrity_output_slot;
};

class ProgramMorpher {
public:
    MorphedProgram generate(
        const Program& base,
        const Program& integrity_program,
        const std::array<unsigned char, 32>& morph_seed,
        const MorphOptions& options) const;
};
```

The mapping metadata is client-side information and must not be sent to an untrusted evaluator unless required by a later protocol design.

## Required tests

Before networking the morphed machine, generate many deterministic morphs from different seeds and verify:

```text
plaintext(base, input, N)
    == plaintext(morph(seed_i), transformed_input_i, N)
    == decrypt(FHE(morph(seed_i), Enc(transformed_input_i), N))
```

for every tested seed.

Also verify that all generated variants expose identical configured public dimensions and fixed work budgets.

## Summary

V0ID polymorphism means:

> The program does not have to change while the evaluator watches it. The client can precompute a different semantically equivalent encrypted machine image for every job, so the evaluator never receives a stable map of where any particular computation — especially the hidden self-check — lives.
