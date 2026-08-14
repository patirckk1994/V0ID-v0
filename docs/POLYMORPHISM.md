# V0ID precomputed polymorphism

V0ID does **not** require runtime self-modifying code for its polymorphism goal.

The intended model is client-side, precomputed semantic morphing: before a job is encrypted and outsourced, the client compiles one of many equivalent machine images. Each image has the same externally visible/public shape and computes the same required result, but its internal representation is rearranged.

The purpose is not to replace FHE. FHE hides encrypted transition semantics and data. Polymorphism is an additional anti-correlation layer intended to prevent a remote evaluator from acquiring a stable semantic map of repeated jobs.

## Current implementation

`ProgramMorpher` currently provides:

- a 256-bit client-side morph seed generated with `RAND_bytes`,
- KMAC-256-derived deterministic pseudorandom state placement,
- a secret mapping from base semantic states to configured public state IDs,
- fixed-size dummy-state padding,
- remapping of the initial state and every next-state transition,
- harmless identity/no-op semantics for unused padded states,
- a client-only `MorphManifest`,
- a KMAC-derived integrity nonce,
- a private selected integrity return slot,
- private per-slot integrity masks.

The universal FHE evaluator processes every configured public state every round, so padded states pad evaluator work rather than merely changing serialized metadata.

`src/integrity/toy_fingerprint.*` adds the first encrypted self-fingerprint plumbing test.

## Private MorphManifest

The manifest is generated alongside each morph and must remain client-side:

```cpp
struct MorphManifest {
    std::vector<std::size_t> base_to_morphed;
    std::vector<std::size_t> dummy_states;

    std::uint32_t integrity_nonce;
    std::size_t integrity_output_slot;
    std::vector<std::uint32_t> integrity_output_masks;
};
```

The evaluator receives the encrypted machine material needed to perform its job, but not this plaintext semantic map.

The client therefore knows exactly where a generated morph placed its semantic states and which returned integrity slot it intends to check, while the evaluator should not receive those labels.

## Implemented toy self-fingerprint

The current integrity primitive is intentionally small and explicitly **not cryptographically strong**. It exists to prove that plaintext and BinFHE evaluation can compute the same exact fingerprint over the same machine representation.

The canonical semantic input to the toy mixer is:

```text
for every public (state, read) row:
    encrypted next-state one-hot bits
    encrypted write bit
    encrypted move-left/stay/right bits

then:
    encrypted initial tape
    encrypted nonce
```

The plaintext reference consumes the corresponding plaintext bits in exactly the same order.

Conceptually:

```text
morphed Program
       |
       +--> canonical plaintext semantic bits ---> ToyFingerprint32 ---> expected digest
       |
       +--> encrypt transition semantics
                    |
                    v
          canonical encrypted semantic bits
                    + encrypted initial tape
                    + encrypted nonce
                    |
                    v
             ToyFingerprint32/FHE
                    |
                    v
              encrypted digest
```

This is closer to a self-fingerprint than merely hashing a client-provided program tag: the FHE path consumes the encrypted morphed transition table itself.

## Masked integrity candidate bank

The toy digest is copied into a fixed public number of encrypted candidate outputs under different **encrypted client masks**.

For candidate `i`:

```text
candidate_i = digest XOR Enc(mask_i)
```

Only the client manifest contains the plaintext masks and selected output slot.

The client:

```text
1. decrypts manifest.integrity_output_slot
2. XORs the result with manifest.integrity_output_masks[slot]
3. compares the recovered digest with its expected plaintext reference
```

The candidate count is public and fixed across jobs. The selected slot and mask values are client-side secrets.

This is still only experimental uncertainty, not a proof of correct computation.

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
same integrity-bank size
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

into:

```text
(pi(q), bit) -> (pi(q2), write, move)
```

The initial state is mapped through the same permutation.

### 2. Padded dummy states — implemented

Every morph is padded to a configured public state count. Unused states currently act as harmless identity states and are still processed by the fixed evaluator.

### 3. Private integrity placement metadata — implemented

The morph seed derives the client-only nonce, candidate selection and output masks used by the first self-fingerprint test.

### 4. Scratch/output relocation — next

Randomize logical scratch and output locations before the existing KMAC physical-remapping layer is applied. No public constant should identify a special integrity or digest slot.

### 5. Equivalent subroutine variants

Maintain multiple equivalent implementations of selected Boolean/Turing-machine operations. A morph seed chooses among them before encryption.

### 6. Interleaved integrity work

The current toy fingerprint is a recognizable dedicated evaluator subcircuit. That is useful for correctness testing but **not** sufficient for the final threat model.

The intended later design must avoid a stable public phase such as:

```text
real computation
then obvious fingerprint circuit
```

Instead, useful work, integrity work and discardable work should be transformed into a fixed-shape machine whose semantic roles cannot be identified reliably from public execution structure.

## Correlation is a primary remaining weakness

A strong FHE scheme can remain cryptographically intact while the evaluator learns from **patterns**.

Possible observable features include:

```text
execution timing
bootstrapping bursts
dependency depth
message sizes
peer access sequence
STORE/FETCH rhythm
slot reuse patterns
remap cadence
repeated fixed-shape subcircuits
```

Therefore polymorphism has a different failure mode from encryption: an attacker may not recover any plaintext but may still classify jobs or locate recurring semantic roles statistically.

A future test harness should generate many morphs of several computation families and train/measure distinguishers using **only evaluator-visible traces**.

Conceptually:

```text
morph generator G
       |
       v
many equivalent encrypted jobs
       |
       v
observable traces only
       |
       v
attacker / distinguisher D
       |
       +--> which computation family?
       +--> same lineage as previous job?
       +--> where is integrity work likely located?
```

A later adversarial morph generator can optimize transformations against such distinguishers while retaining semantic equivalence.

The cryptographic RNG should provide unpredictability; a learned model should not be treated as an entropy source.

## Seed entropy / post-quantum-facing note

The morph seed is a security-sensitive input. Weak entropy, seed reuse, deterministic reuse across jobs or compromise of the client RNG can collapse the diversity of generated variants and enable straightforward correlation.

The current seed is 256 bits from OpenSSL `RAND_bytes` and is expanded through KMAC-256. This is intended as a strong symmetric construction, but the repository does not claim that its complete composition or current BinFHE parameter selection has been audited for post-quantum deployment.

The local demo currently uses OpenFHE `STD128`; parameter migration/hardening for a formal post-quantum claim remains separate from the polymorphism problem.

## Threat-model interpretation

The current mechanism is intended to make selective cheating and structural correlation harder, not to claim formal Byzantine/verifiable-computation security.

The toy fingerprint currently proves:

```text
client plaintext reference
    == evaluator BinFHE fingerprint
```

for the same morphed program/input/nonce.

It does **not** prove that a malicious evaluator executed the useful Turing-machine computation correctly. A malicious evaluator may still identify the dedicated toy fingerprint circuit and evaluate it honestly while cheating elsewhere.

That limitation is deliberate and documented. The next integrity research problem is making the audit computation semantically ambiguous inside the same polymorphic execution structure.

This can later be combined with hidden known-answer jobs, replication, peer scoring, authenticated transport and stronger verifiable-computation mechanisms.

## Current API

```cpp
using MorphSeed = std::array<unsigned char, 32>;

struct MorphManifest {
    std::vector<std::size_t> base_to_morphed;
    std::vector<std::size_t> dummy_states;
    std::uint32_t integrity_nonce;
    std::size_t integrity_output_slot;
    std::vector<std::uint32_t> integrity_output_masks;
};

struct MorphedProgram {
    Program program;
    std::size_t initial_state;
    MorphManifest manifest;
};
```

The local demo deliberately prints manifest details to make morph differences visible during development. Production evaluator jobs should not receive that plaintext manifest.

## Required tests

The local demo now checks both computation semantics and integrity plumbing:

```text
plaintext(base, input, N)
    == plaintext(morph(seed_A), input, N)
    == plaintext(morph(seed_B), input, N)
    == decrypt(FHE(morph(seed_A), Enc(input), N))
    == decrypt(FHE(morph(seed_B), Enc(input), N))
```

plus:

```text
ToyFingerprint32(plaintext morphed program, input, nonce)
    == unmask(decrypt(FHE ToyFingerprint32(encrypted morphed program, encrypted input, encrypted nonce)))
```

More exhaustive randomized differential tests should be added as scratch relocation, subroutine variants, integrity interleaving and distributed storage are introduced.

## Summary

V0ID polymorphism means:

> The client precomputes a different semantically equivalent encrypted machine image for each job and keeps the semantic decoding manifest private. FHE hides the values; polymorphism attempts to deny the evaluator a stable map of what those values and operations mean across repeated jobs.
