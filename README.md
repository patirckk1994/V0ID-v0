# V0ID

Tiny research prototype for an exact encrypted, runtime-programmable Turing-machine interpreter.

Current V0.3 + network scaffold:

- **Encryption-lite:** OpenFHE BinFHE (`STD128`) exact Boolean gates; no approximate arithmetic.
- **Encrypted program:** transition semantics are encrypted as one-hot next-state selectors plus encrypted write/move selectors.
- **UTM-lite:** one fixed interpreter executes encrypted transition tables over encrypted one-hot state, encrypted one-hot head and encrypted tape. The demo is bounded to 8 cells.
- **Fixed work schedule:** execution uses a public fixed round budget rather than secret-dependent termination.
- **Remap-lite:** OpenSSL 3 `KMAC-256` derives epoch-specific logical-to-physical tape permutations; remaps move ciphertexts only.
- **Precomputed polymorphism:** client-side state-label permutation plus fixed-size dummy-state padding. Different morph seeds produce semantically equivalent machine images with the same public shape.
- **Private morph manifest:** the client keeps the semantic state map, dummy-state map, integrity nonce, selected integrity return slot and output masks. This manifest is not part of the evaluator job.
- **Toy encrypted self-fingerprint:** a test-only 32-bit Boolean mixer consumes the encrypted morphed transition table, encrypted initial tape and encrypted nonce. A plaintext reference computes the same value client-side.
- **Masked integrity bank:** the evaluator produces a fixed public number of encrypted candidate digests. Candidate masks are encrypted; only the client manifest says which slot it checks and how to unmask it.
- **P2P scaffold:** ZeroMQ/cppzmq binary-safe envelopes carry peer id, job id, epoch, message type and opaque payload bytes.
- **FHE-over-network smoke test:** a remote process receives a key-independent BinFHE context, bootstrapping material and ciphertext, evaluates `NOT`, and returns a ciphertext without receiving the LWE secret key.

Correctness and exact encrypted state semantics are invariants; speed and memory are expendable. Experimental research code, not audited production cryptography.

## Precomputed polymorphism + self-check

V0ID polymorphism does **not** require runtime self-modifying code. Before encryption, the client generates a semantically equivalent machine image from a private 256-bit morph seed.

The current morpher produces:

```text
base program
    -> KMAC-derived state permutation
    -> fixed-size dummy-state padding
    -> private MorphManifest
```

The manifest currently contains client-only metadata approximately equivalent to:

```text
base semantic state -> morphed state map
dummy state IDs
integrity nonce
selected integrity output slot
per-slot integrity masks
```

The encrypted self-fingerprint then binds the toy check to the **actual morphed encrypted transition semantics**, not merely a client-provided plaintext program tag:

```text
encrypted morphed transition bits
        + encrypted initial tape
        + encrypted nonce
                |
                v
        ToyFingerprint32
                |
                v
      encrypted digest
                |
        encrypted masks
                |
                v
     fixed candidate bank
```

The client computes the expected toy digest from the same morphed plaintext program/input/nonce, decrypts only the manifest-selected candidate, removes its private mask, and compares.

`ToyFingerprint32` is deliberately **not a cryptographic hash**. It is a plumbing test for exact FHE self-fingerprinting, private placement metadata and later polymorphic integrity work. Replacing it with a real Keccak/KMAC-style circuit is a later step.

The current evaluator can still recognize that a dedicated fingerprint subcircuit exists. Therefore this version does **not** yet solve the harder problem of hiding where integrity work lives from structural/timing/correlation analysis. Future morphing must interleave or otherwise disguise integrity work inside the general computation.

## Known correlation / PQ-facing research issue

The 256-bit morph seed is generated client-side with `RAND_bytes` and expanded with KMAC-256. Seed quality is security-sensitive: weak entropy, seed reuse or accidental deterministic reuse would immediately weaken polymorphic diversity.

Even with strong seed generation, encryption can remain intact while repeated jobs leak **behavioral fingerprints** through observable execution patterns. Candidate correlation features include timing, repeated state/dependency shapes, message sizes, peer access order, remap cadence and future `STORE_SLOT` / `FETCH_SLOT` patterns.

So the remaining polymorphism problem is not merely cryptanalytic. It is also statistical: can an evaluator classify equivalent encrypted computations from their observable traces without decrypting anything? That is a planned adversarial-testing target.

The current BinFHE demo uses `STD128` because this repository is still a functional prototype; parameter selection for a post-quantum security claim is not finalized or audited.

See `docs/POLYMORPHISM.md` for the fuller threat model.

## Hidden vs public

Encrypted locally:

- tape bits,
- active state,
- head position,
- transition next-state choice,
- transition write bit,
- transition movement choice,
- toy fingerprint nonce/masks during evaluation.

Public shape currently includes tape length, public state count, binary alphabet, fixed round count and integrity candidate count.

## Dependencies

- C++20 compiler
- CMake >= 3.20
- Git available during first configure
- OpenFHE installed with `OpenFHEConfig.cmake`
- OpenSSL >= 3 with `KMAC-256`

The network build fetches:

- `zeromq/libzmq` v4.3.5
- `zeromq/cppzmq` v4.11.0

## Build

```sh
cmake -S . -B build
cmake --build build -j
```

### Polymorphic encrypted-machine demo

```sh
./build/v0id
```

The demo generates two independently morphed increment programs and one morphed decrement program, verifies plaintext equivalence, then executes each through BinFHE. Each FHE run also computes and checks the encrypted toy self-fingerprint.

Expected logical outputs remain:

```text
00001101 -> increment -> 00001110
00001101 -> decrement -> 00001100
```

The local demo prints client-side state maps and selected integrity slots for visibility. Those values are debugging output only and would not be transmitted to an untrusted evaluator.

### Local peer transport smoke test

Terminal 1:

```sh
./build/v0id-peer server A tcp://*:7001 2
```

Other terminals:

```sh
./build/v0id-peer client B tcp://127.0.0.1:7001 hello-from-B
./build/v0id-peer client C tcp://127.0.0.1:7001 hello-from-C
```

### FHE-over-network smoke test

Terminal 1:

```sh
./build/v0id-fhe-peer server EVAL tcp://*:7002 2
```

Other terminals:

```sh
./build/v0id-fhe-peer client CLIENT1 tcp://127.0.0.1:7002 1
./build/v0id-fhe-peer client CLIENT2 tcp://127.0.0.1:7002 0
```

## Source layout

```text
src/core/program.hpp                 Rule / Program representation
src/polymorph/program_morpher.*      precomputed semantic morph compiler + private manifest
src/integrity/toy_fingerprint.*      test-only plaintext/FHE self-fingerprint
src/main.cpp                         local plaintext + FHE morph/integrity tests
src/fhe/fhe_codec.hpp                OpenFHE binary serialization helpers
src/net/peer_transport.*             V0ID binary envelope / ZeroMQ transport
src/net/peer_demo.cpp                plain network smoke test
src/net/fhe_peer_demo.cpp            remote BinFHE smoke test
docs/POLYMORPHISM.md                 polymorphism / correlation threat model
```

## Next research milestones

- randomized logical scratch/output relocation before physical KMAC remapping,
- move the fingerprint work from a recognizable dedicated subcircuit toward morphed/interleaved integrity computation,
- equivalent subroutine variants and discardable work,
- distributed encrypted tape with `(peer_id, local_slot)`,
- trace instrumentation for timing/message/peer-access correlation experiments,
- serialization of an entire encrypted machine/program rather than one ciphertext,
- `STORE_SLOT` / `FETCH_SLOT` for ciphertext-resident remote tape cells,
- encrypted halted/no-op semantics under the fixed work budget,
- eventually replace the toy mixer with a real cryptographic construction and stronger verification machinery.

If CMake/compiler complains, report the exact error and installation layout. The code intentionally favors explicit research scaffolding over pretending this is production cryptography.
