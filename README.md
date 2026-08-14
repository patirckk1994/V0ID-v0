# V0ID

Tiny research prototype for an exact encrypted, runtime-programmable Turing-machine interpreter.

Current V0.2 + network scaffold:

- **Encryption-lite:** OpenFHE BinFHE (`STD128`) exact Boolean gates; no approximate arithmetic.
- **Encrypted program:** transition semantics are encrypted as one-hot next-state selectors plus encrypted write/move selectors.
- **UTM-lite:** one fixed interpreter executes encrypted transition tables over encrypted one-hot state, encrypted one-hot head and encrypted tape. The demo is bounded to 8 cells.
- **Fixed work schedule:** execution uses a public fixed round budget rather than secret-dependent termination.
- **Remap-lite:** OpenSSL 3 `KMAC-256` derives epoch-specific logical-to-physical tape permutations; remaps move ciphertexts only.
- **Precomputed polymorphism:** implemented client-side state-label permutation plus fixed-size dummy-state padding. Different morph seeds produce semantically equivalent machine images with the same public state count and evaluator path.
- **P2P scaffold:** ZeroMQ/cppzmq binary-safe envelopes carry peer id, job id, epoch, message type and opaque payload bytes.
- **FHE-over-network smoke test:** a remote process receives a key-independent BinFHE context, bootstrapping material and ciphertext, evaluates `NOT`, and returns a ciphertext without receiving the LWE secret key.

Correctness and exact encrypted state semantics are invariants; speed and memory are expendable. Experimental research code, not audited production cryptography.

## Precomputed polymorphism

V0ID polymorphism does **not** require runtime self-modifying code. Before encryption, the client can generate a semantically equivalent machine image from a private morph seed.

The first implemented `ProgramMorpher` does two things:

```text
base state IDs
    -> KMAC-derived secret permutation
    -> different public state IDs

base program size
    -> fixed configured public state count
    -> remaining states become harmless identity/no-op states
```

Every morph keeps the same configured public dimensions:

```text
same tape size
same public state count
same binary alphabet
same fixed round budget
same evaluator implementation
```

The state mapping is client-side metadata and is not intended to be sent to an untrusted evaluator. Because the universal evaluator visits every public state every round, dummy states pad actual evaluator work as well as the encrypted transition table.

Current demo generation looks conceptually like:

```text
increment
   -> Morph(seed A) -> encrypted morph A -> 14
   -> Morph(seed B) -> encrypted morph B -> 14

decrement
   -> Morph(seed C) -> encrypted morph C -> 12
```

The different morphs can place the original semantic states at different public state IDs while producing identical logical results.

Future morphing stages will add randomized scratch/output placement, equivalent subroutine variants, discardable work and interleaved hidden integrity logic. The goal is to prevent the evaluator from acquiring a stable semantic map such as "these states are the hash checker". FHE provides confidentiality; polymorphism is an additional structural anti-correlation layer.

See `docs/POLYMORPHISM.md` for the design and threat-model notes.

## Hidden vs public

The local prototype encrypts tape bits, active state, head position, transition next-state choice, transition write bit and transition movement choice.

The evaluator still learns public shape information such as tape length, public state count, alphabet and fixed round count. Morph variants are therefore padded to identical public dimensions.

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

The demo first checks the base increment/decrement machines with a plaintext reference interpreter. It then generates two distinct increment morphs and one decrement morph, each padded to the same public state count, verifies plaintext equivalence, encrypts all three programs and executes them through the same fixed BinFHE evaluator.

Expected logical outputs remain:

```text
00001101 -> increment -> 00001110
00001101 -> decrement -> 00001100
```

The program also prints client-side state mappings so the local test visibly demonstrates that two equivalent morphs need not use the same state IDs. Those mappings are debugging output only and would not be transmitted to a remote evaluator.

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

The evaluator reconstructs the key-independent BinFHE context, loads refresh/switching keys, evaluates the gate and returns a serialized result ciphertext. The secret key remains client-side.

## Source layout

```text
src/core/program.hpp                 Rule / Program representation
src/polymorph/program_morpher.*      precomputed semantic morph compiler
src/main.cpp                         local plaintext + FHE morph tests
src/fhe/fhe_codec.hpp                OpenFHE binary serialization helpers
src/net/peer_transport.*             V0ID binary envelope / ZeroMQ transport
src/net/peer_demo.cpp                plain network smoke test
src/net/fhe_peer_demo.cpp            remote BinFHE smoke test
docs/POLYMORPHISM.md                 polymorphism design
```

## Next research milestones

- randomized logical scratch/output relocation before physical KMAC remapping,
- a small hidden integrity/self-fingerprint computation embedded into morphed programs,
- equivalent subroutine variants and interleaving of useful/integrity/discardable work,
- serialization of an entire encrypted machine/program rather than one ciphertext,
- mapping remapped tape slots onto `(peer_id, local_slot)`,
- `STORE_SLOT` / `FETCH_SLOT` for ciphertext-resident remote tape cells,
- encrypted halted/no-op semantics under the fixed work budget,
- probabilistic audit experiments before heavier verifiable-computation machinery.

If CMake/compiler complains, report the exact error and installation layout. The code intentionally favors explicit research scaffolding over pretending this is production cryptography.
