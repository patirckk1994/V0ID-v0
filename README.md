# V0ID

Tiny research prototype for an exact encrypted, runtime-programmable Turing-machine interpreter.

Current V0.1 + network scaffold:

- **Encryption-lite:** OpenFHE BinFHE (`STD128`) exact Boolean gates; no approximate arithmetic.
- **Encrypted program:** transition semantics are encrypted as one-hot next-state selectors plus encrypted write/move selectors. Two different programs with the same public shape execute through the same evaluator control flow.
- **UTM-lite:** one fixed interpreter executes encrypted transition tables over encrypted one-hot state, encrypted one-hot head and encrypted tape. The demo is bounded to 8 cells, so this is a bounded universal-interpreter prototype rather than a claim of an infinite physical tape.
- **Fixed work schedule:** the demo executes a public fixed number of interpreter rounds rather than terminating based on secret program semantics.
- **Remap-lite:** OpenSSL 3 `KMAC-256` derives an epoch-specific exact bijection from logical tape cells to physical slots. The demo changes epochs mid-computation by moving ciphertexts only; it never decrypts the intermediate tape.
- **Precomputed polymorphism model:** V0ID does not require runtime self-modifying code. The client may precompute semantically equivalent machine variants with randomized state labels, scratch/output placement, equivalent subroutine choices, padded dummy work and different placement/interleaving of integrity logic. All variants are intended to expose the same configured public shape before being encrypted.
- **P2P scaffold:** `src/net/peer_transport.*` wraps ZeroMQ through the header-only `cppzmq` C++ API. A versioned binary-safe V0ID envelope carries message type, peer id, job id, epoch and opaque payload bytes.
- **FHE-over-network smoke test:** `v0id-fhe-peer` serializes a key-independent BinFHE context, refresh key, switching key and ciphertext into the opaque payload. A remote evaluator reloads the bootstrapping keys, performs `EvalNOT()` and returns a ciphertext. The LWE secret key never leaves the client.

Correctness and exact encrypted state semantics are invariants; speed and memory are expendable. Experimental research code, not audited production cryptography.

## What is hidden vs public

The current local prototype encrypts:

- tape bits,
- active state,
- head position,
- transition next-state choice,
- transition write bit,
- transition movement choice.

The evaluator still learns public shape information such as tape length, number of states, binary alphabet, and fixed round count.

The FHE network smoke test separates client and evaluator roles: the evaluator receives the key-independent BinFHE context plus bootstrapping material and ciphertext, but not the LWE secret key. This is only a transport/evaluation proof-of-concept; it is not yet the distributed Turing-machine protocol.

## Precomputed polymorphism model

"Polymorphism" in V0ID means **client-side precomputed semantic morphing**, not necessarily code that mutates itself while executing.

For a base computation `P`, the client should eventually be able to generate multiple equivalent machine images:

```text
P -> Morph(P, seed_1) -> P1
P -> Morph(P, seed_2) -> P2
P -> Morph(P, seed_3) -> P3
```

such that:

```text
result(P1, x) == result(P2, x) == result(P3, x) == result(P, x)
```

while every variant exposes the same configured public dimensions:

```text
same tape size
same state count
same alphabet
same fixed round budget
same wire format
same evaluator implementation
```

Candidate morphing operations include:

- random state-label permutations,
- padded dummy/discardable states,
- randomized logical scratch/output placement before KMAC physical remapping,
- multiple equivalent implementations of selected Boolean/TM subroutines,
- interleaving useful work, integrity work and decoy work into one fixed-shape encrypted program.

FHE is what hides the encrypted program/data semantics. The morphing layer has a different purpose: it should make repeated jobs difficult to correlate structurally and prevent the evaluator from acquiring a stable semantic map such as "these states are always the integrity checker" or "this slot is always the digest output".

The full design note is in `docs/POLYMORPHISM.md`.

## Planned hidden self-fingerprint

A future integrity experiment will embed a fingerprint computation into the encrypted program rather than expose a separate public `hash()` phase.

Conceptually, the client knows an expected value such as:

```text
digest = H(
    domain_separator ||
    canonical_program ||
    canonical_input ||
    nonce ||
    epoch
)
```

with the digest field itself excluded from the hash domain.

The remote evaluator should homomorphically execute the hidden fingerprint logic along with the useful computation without receiving metadata that identifies where that logic lives. Different precomputed morphs may place and interleave the integrity work differently while preserving the same public dimensions.

This is intended as a probabilistic/structural cheating-deterrence experiment, not a claim of formal malicious-secure verifiable computation. A later design may combine it with hidden known-answer jobs, replication, peer scoring, or stronger proof machinery.

## Dependencies

- C++20 compiler
- CMake >= 3.20
- Git available during the first CMake configure (for `FetchContent`)
- OpenFHE installed with its CMake package (`OpenFHEConfig.cmake`)
- OpenSSL >= 3 with `KMAC-256`

The network prototype fetches these upstream dependencies automatically:

- `zeromq/libzmq` v4.3.5
- `zeromq/cppzmq` v4.11.0

`cppzmq` is included from C++ as `<zmq.hpp>`; V0ID does not vendor a modified copy.

## Build

```sh
cmake -S . -B build
cmake --build build -j
```

The first configure downloads ZeroMQ/cppzmq from their upstream GitHub repositories.

### Encrypted-machine demo

```sh
./build/v0id
```

The demo encrypts `00001101` (13), then encrypts two different transition programs with the same public shape:

1. binary increment,
2. binary decrement.

Both run through the same fixed evaluator path for four rounds, with a ciphertext-only tape remap after the first round. Only the final tape is decrypted.

Expected logical results:

```text
input           : 00001101
encrypted inc output: 00001110
encrypted dec output: 00001100
OK: same fixed evaluator executed two encrypted transition tables
    + exact encrypted state/tape semantics
    + ciphertext-only epoch remap
```

### Local peer transport smoke test

Terminal 1 starts peer A and accepts two requests:

```sh
./build/v0id-peer server A tcp://*:7001 2
```

Terminal 2:

```sh
./build/v0id-peer client B tcp://127.0.0.1:7001 hello-from-B
```

Terminal 3:

```sh
./build/v0id-peer client C tcp://127.0.0.1:7001 hello-from-C
```

Peer A should print both decoded V0ID envelopes and return a `PONG` acknowledgement. B and C should each print the reply.

### FHE-over-network smoke test

This test actually sends OpenFHE serialization through the V0ID network envelope.

Terminal 1 starts an evaluator:

```sh
./build/v0id-fhe-peer server EVAL tcp://*:7002 2
```

Terminal 2 asks it to evaluate encrypted `NOT(1)`:

```sh
./build/v0id-fhe-peer client CLIENT1 tcp://127.0.0.1:7002 1
```

Terminal 3 asks it to evaluate encrypted `NOT(0)`:

```sh
./build/v0id-fhe-peer client CLIENT2 tcp://127.0.0.1:7002 0
```

Expected client-side result for the first request:

```text
input plaintext  : 1
remote operation : NOT under BinFHE
decrypted result : 0
secret key sent  : NO
OK: remote evaluator transformed ciphertext without secret key
```

The opposite result should be obtained for input `0`.

The client sends:

```text
key-independent BinFHE context
refresh/bootstrapping key
switching key
ciphertext
```

The evaluator reconstructs the BinFHE context, loads the bootstrapping keys, evaluates the gate, and returns only the serialized result ciphertext. The secret key exists only in the client process.

## Network wire scaffold

The current envelope is binary-safe and versioned. It contains:

```text
magic/version
message type
peer id
job id
epoch
opaque payload bytes
```

Reserved message types already include:

```text
HELLO
PONG
STORE_SLOT
FETCH_SLOT
SLOT_VALUE
EXECUTE_JOB
JOB_RESULT
ERROR
```

`src/fhe/fhe_codec.hpp` adds an inner binary bundle for OpenFHE context/key/ciphertext serialization. The outer V0ID envelope does not interpret those bytes.

## Next research milestones

Likely next steps:

- factor `Rule` / `Program` out of `main.cpp` into reusable machine headers,
- implement a deterministic `ProgramMorpher` beginning with state-label permutation and fixed-size dummy-state padding,
- test many morph seeds against a plaintext reference machine and the FHE evaluator,
- embed a small hidden self-fingerprint into morphed machine images before attempting full KMAC/Keccak under FHE,
- serialize an entire encrypted machine/program rather than one test ciphertext,
- map remapped physical tape slots onto `(peer_id, local_slot)`,
- implement `STORE_SLOT` / `FETCH_SLOT` for ciphertext-resident remote tape cells,
- encrypted halted/no-op semantics with a fixed public work budget,
- probabilistic audit/integrity experiments before heavier verifiable-computation machinery.

If CMake/compiler complains about a missing package, target, include path, or OpenFHE API, report the exact error and installation layout. The network dependencies are fetched automatically, while OpenFHE/OpenSSL remain installed system dependencies.
