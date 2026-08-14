# V0ID

Research prototype for exact encrypted, runtime-programmable computation over a bounded Turing-machine-like interpreter, with client-side precomputed polymorphism, a series-first morph derivation layer and experimental hidden-integrity plumbing.

Current V0.4.1 scaffold:

- **Encryption-lite:** OpenFHE BinFHE (`STD128`) exact Boolean gates; no approximate arithmetic.
- **Encrypted program:** transition semantics are encrypted as one-hot next-state selectors plus encrypted write/move selectors.
- **UTM-lite:** one fixed interpreter executes encrypted transition tables over encrypted one-hot state, encrypted one-hot head and encrypted tape. The demo is bounded to 8 cells.
- **Fixed work schedule:** execution uses a public fixed round budget rather than secret-dependent termination.
- **Remap-lite:** the local prototype uses OpenSSL 3 `KMAC-256` for epoch-specific logical-to-physical tape permutations; remaps move ciphertexts only.
- **Precomputed polymorphism:** client-side state-label permutation plus fixed-size dummy-state padding. Different morph seeds produce semantically equivalent machine images with the same public shape.
- **Series-first derivation:** a client-side `PolymorphicSeriesGenerator` derives a private series from input + private 256-bit seed + epoch, then derives the `MorphSeed` used by `ProgramMorpher`.
- **User-injected series seam:** trusted local code can provide a custom generator through `FunctionalSeriesGenerator`; peers never send executable crypto plugins.
- **Private morph manifest:** the client keeps the semantic state map, dummy-state map, integrity nonce, selected integrity return slot and output masks. This manifest is not part of an evaluator job.
- **Toy encrypted self-fingerprint:** a test-only 32-bit Boolean mixer consumes the encrypted morphed transition table, encrypted initial tape and encrypted nonce. A plaintext reference computes the same value client-side.
- **Masked integrity bank:** the evaluator produces a fixed public number of encrypted candidate digests. Candidate masks are encrypted; only the client manifest says which slot it checks and how to unmask it.
- **P2P scaffold:** ZeroMQ/cppzmq binary-safe envelopes carry peer id, job id, epoch, message type and opaque payload bytes.
- **V0.4 full-machine remote path:** `v0id-remote-machine` serializes a whole morphed encrypted program/state/head/tape plus encrypted integrity material, sends it with `EXECUTE_JOB`, executes the fixed public round budget remotely, and returns encrypted final state/head/tape plus all masked integrity candidates. The secret key and `MorphManifest` remain client-side.
- **V0.4.1 public profile IDs:** remote machine wire format `V0IDRMJ2`/`V0IDRMR2` carries bounded identifiers for FHE primitive, parameter set, machine protocol, integrity profile and client-side series generator id/version.

Correctness and exact encrypted state semantics are invariants; speed and memory are expendable. Experimental research code, not audited production cryptography.

## Series first -> morph later

V0.4.1 adds this client-side path:

```text
semantic input
    |
    v
private SeriesSeed + epoch
    |
    v
PolymorphicSeriesGenerator
    |
    +--> private series
    +--> private provenance token
    +--> derived MorphSeed
             |
             v
        ProgramMorpher
             |
             v
      morphed program image
             |
             v
           BinFHE
```

The built-in profile is `v0id-series-kmac-v1`. It uses KMAC-256 under separate domains and the current demo derives a 64-byte private series. The series, series seed, derived morph seed and series private manifest do not leave the client.

This is a concrete experiment for the "series first, algorithm/representation later" idea. It is **not** a proof that an arbitrary or "magic" series is intrinsically post-quantum hard, information-theoretically hidden, or a new cryptographic primitive. See `docs/SERIES_GENERATOR.md`.

A trusted application can inject its own local pattern by implementing `PolymorphicSeriesGenerator` or using `FunctionalSeriesGenerator`. V0ID intentionally does not download or execute crypto plugins supplied by peers.

## Public crypto/profile identifiers

Each V0.4.1 remote job now self-identifies approximately as:

```text
primitive             openfhe-binfhe
parameter set         STD128
machine protocol      v0id-remote-machine-v2
integrity profile     toy-fingerprint32-v1
series generator      v0id-series-kmac-v1 / v1
```

The evaluator fails closed on unsupported execution/integrity profiles. The series generator itself runs entirely client-side; its public identifier is currently provenance for later interoperability/correlation work. The server echoes the full profile in `JOB_RESULT` and the client requires an exact match.

This is not yet a capability handshake. Authenticated suite negotiation and downgrade protection belong later, once at least two genuinely interchangeable profiles exist.

## Precomputed polymorphism + self-check

V0ID polymorphism does **not** require runtime self-modifying code. The client generates a semantically equivalent fixed-size machine image from a private morph seed.

The current morpher performs:

```text
base program
    -> secret state-label permutation
    -> fixed-size dummy-state padding
    -> private MorphManifest
```

The manifest contains client-only metadata approximately equivalent to:

```text
base semantic state -> morphed state map
dummy state IDs
integrity nonce
selected integrity output slot
per-slot integrity masks
```

The encrypted self-fingerprint binds the toy check to the actual morphed encrypted transition semantics plus initial input/nonce. `ToyFingerprint32` is deliberately **not a cryptographic hash**. It proves the FHE/self-check plumbing only; it is not yet proof that every evaluator step was executed honestly and the dedicated fingerprint subcircuit remains structurally recognizable.

## V0.4/V0.4.1 remote machine

```text
CLIENT
  derive private series
  derive morph seed
  Morph(P)
  encrypt transition table
  encrypt state/head/tape
  encrypt nonce + candidate masks
       |
       | EXECUTE_JOB
       v
================ network ================
       |
       v
REMOTE EVALUATOR
  validate public execution profile
  load key-independent BinFHE context
  load refresh/switching evaluation keys
  compute encrypted toy fingerprint
  run exactly N public interpreter rounds
       |
       | JOB_RESULT
       v
================ network ================
       |
       v
CLIENT
  require returned profile == requested profile
  decrypt final tape
  select private integrity candidate
  unmask + verify expected digest
```

The evaluator does **not** receive:

```text
LWE secret key
private series
SeriesSeed
series private manifest
MorphSeed
MorphManifest
base-to-morphed semantic mapping
selected integrity candidate index
plaintext integrity masks
```

The result returns encrypted final state, encrypted final head, encrypted final tape and every masked integrity candidate. State/head are returned so checkpoint/resume can be added later.

### Proven V0.4 milestone

The V0.4 whole-machine path has been run successfully across two local processes. A morphed encrypted increment machine executed four remote BinFHE rounds and the client recovered:

```text
00001101 -> 00001110
```

while verifying its private integrity candidate. In that run the request was roughly 551 MB because the BinFHE evaluation context/bootstrap material was resent with the job, while the encrypted result was roughly 666 KB. Persistent evaluator sessions/key caching are therefore an obvious near-term engineering optimization.

V0.4.1 adds the series/profile layer on top of that proven path and still needs compiler/runtime validation on the current OpenFHE installation.

### Placement boundary

The remote-machine demo currently sends tape ciphertexts in logical tape order. The local `v0id` executable still demonstrates KMAC-derived ciphertext-only epoch remapping, but that physical remap has deliberately not been folded into the remote evaluator yet.

The intended placement chain is:

```text
logical tape cell
    -> client/compiler logical relocation
    -> epoch physical remap
    -> (peer_id, local_slot)
```

That belongs with distributed-tape `STORE_SLOT` / `FETCH_SLOT`. The current remap is not claimed to provide ORAM/access-pattern privacy.

## Correlation / PQ-facing research issue

Encryption can remain intact while repeated jobs leak behavioral fingerprints through timing, dependency shape, message sizes, peer access order, remap cadence and future storage-access patterns.

The central statistical question is therefore whether an evaluator can classify equivalent encrypted computations without decrypting them. The series generator gives V0ID another controllable axis for that experiment: generate many private series/morphs for the same semantic task, record only evaluator-visible traces and test whether a distinguisher can correlate them.

The current BinFHE demo uses `STD128` because this repository is still a functional prototype; parameter selection for a post-quantum security claim is not finalized or audited.

See `docs/POLYMORPHISM.md` and `docs/SERIES_GENERATOR.md`.

## Dependencies

- C++20 compiler
- CMake >= 3.20
- Git available during first configure
- OpenFHE installed with `OpenFHEConfig.cmake`
- OpenSSL >= 3 with `KMAC-256`

The network build fetches `zeromq/libzmq` v4.3.5 and `zeromq/cppzmq` v4.11.0. CMake 4+ is supported through `CMAKE_POLICY_VERSION_MINIMUM=3.5` for the legacy libzmq subproject.

## Build

```sh
cmake -S . -B build
cmake --build build -j
```

### Local polymorphic encrypted-machine demo

```sh
./build/v0id
```

Expected logical outputs:

```text
00001101 -> increment -> 00001110
00001101 -> decrement -> 00001100
```

### Plain peer transport smoke test

```sh
./build/v0id-peer server A tcp://*:7001 2
./build/v0id-peer client B tcp://127.0.0.1:7001 hello-from-B
```

### Single-ciphertext FHE-over-network smoke test

```sh
./build/v0id-fhe-peer server EVAL tcp://*:7002 1
./build/v0id-fhe-peer client CLIENT tcp://127.0.0.1:7002 1
```

### V0.4.1 series-derived remote-machine demo

Terminal 1:

```sh
./build/v0id-remote-machine server EVAL tcp://*:7003 1
```

Terminal 2:

```sh
./build/v0id-remote-machine client CLIENT tcp://127.0.0.1:7003
```

The client derives a private series before morphing, transmits only the public generator id/version, and should eventually verify `00001110` plus a morph-specific private self-check. The server prints public round progress; the demo timeout is one hour.

## Source layout

```text
src/core/program.hpp                    Rule / Program representation
src/polymorph/program_morpher.*         semantic morph compiler + private manifest
src/polymorph/series_generator.*        series-first generator interface + KMAC/default + callback seam
src/integrity/toy_fingerprint.*         test-only plaintext/FHE self-fingerprint
src/main.cpp                            local plaintext + FHE morph/integrity tests
src/fhe/fhe_codec.hpp                   OpenFHE single-object serialization helpers
src/fhe/remote_machine_codec.hpp        bounded RMJ2/RMR2 full-machine/profile wire format
src/fhe/remote_machine.*                fixed-path evaluator over received ciphertext machine
src/net/peer_transport.*                V0ID binary envelope / ZeroMQ transport
src/net/peer_demo.cpp                   plain network smoke test
src/net/fhe_peer_demo.cpp               remote single-ciphertext BinFHE smoke test
src/net/remote_machine_demo.cpp         series-derived client/server whole-machine test
docs/POLYMORPHISM.md                    polymorphism / correlation threat model
docs/SERIES_GENERATOR.md                series-first conjecture implementation boundary
```

## Next research milestones

- compile/run V0.4.1 end-to-end and confirm the private series-driven morph still returns `00001110`,
- persistent evaluator sessions/key caching so huge BinFHE evaluation material is sent once rather than per job,
- generate large morph/series trace sets and build a correlation/distinguisher harness,
- add a second genuinely different series generator before designing capability negotiation,
- randomized logical scratch/output relocation before physical KMAC remapping,
- distributed encrypted tape with `(peer_id, local_slot)` and `STORE_SLOT` / `FETCH_SLOT`,
- move fingerprint work toward morphed/interleaved integrity computation,
- encrypted halted/no-op semantics and checkpoint/resume,
- bind integrity to evolving/final computation state,
- later authenticated crypto-profile negotiation with downgrade protection,
- eventually replace the toy mixer with a real cryptographic construction and stronger verification machinery.

If CMake/compiler complains, report the exact error and installation layout. The code intentionally favors explicit research scaffolding over pretending this is production cryptography.
