# V0ID

Research prototype for exact encrypted, runtime-programmable computation with client-side polymorphism, series-first morph derivation, remote FHE evaluation, SHA3-based integrity research and sandboxed Wasm extension layers.

V0ID is experimental research code, not audited production cryptography. The repository intentionally distinguishes runtime-proven plumbing milestones from implemented-but-unverified changes and from security conjectures.

## Current architecture

```text
                              V0ID
                                |
          +---------------------+---------------------+
          |                                           |
 encrypted machine path                         MathVM path
          |                                           |
 client-only polymorphism.wasm                  sandboxed Wasm
          |                                      visible math/crypto IR
          v                                           |
 DerivedSeries / MorphSeed                     primitive registry
          |                                    /       |        \
 trusted ProgramMorpher                    scalar    bytes    optional PQ
          |
 encrypted program/state
          |
 OpenFHE BinFHE remote path
          +-------------------+
          |                   |
          |             TFHE-rs CUDA
          |             Boolean-program path
          v                   |
 cached remote evaluator      v
                       local CUDA stress boundary
```

The execution paths solve different problems:

- the encrypted Turing-machine-like interpreter is the universal exact path when program/state semantics should remain hidden from the evaluator;
- the compact Boolean-program image is a fixed-width private program representation currently used for the SHA3-512/FHE experiments;
- local `WasmSeriesGenerator` is a client-only programmable polymorphism strategy that derives private morph material before encryption;
- remote MathVM is the bounded portable path when the Wasm composition itself may be visible but arbitrary peer-supplied native plugins are not acceptable.

Wasm does **not** replace the encrypted machine and an RMJ4 encrypted-machine job does not need to carry a Wasm program. The local polymorphism Wasm is not transmitted to the evaluator.

## Proven remote-machine baseline

The original V0.4 whole-machine path was run successfully across two local processes. The client sent encrypted transition/state/head/tape material; the evaluator executed four fixed BinFHE rounds without receiving the LWE secret key or `MorphManifest` and returned encrypted state.

The client recovered:

```text
00001101 -> 00001110
13 -> 14
```

That early run transferred roughly 551 MB in the request because BinFHE context/bootstrap material was embedded in each job. RMS3 later separated expensive evaluator setup from recurring jobs.

## Series first -> morph later

The client-side morph path supports `PolymorphicSeriesGenerator`:

```text
semantic input
    + private SeriesSeed
    + epoch
          |
          v
PolymorphicSeriesGenerator
          |
          +--> private series
          +--> private provenance
          +--> derived MorphSeed
                    |
                    v
               ProgramMorpher
                    |
                    v
             morphed machine image
```

The built-in profile is `v0id-series-kmac-v1`. The private series, series seed, derived morph seed and `MorphManifest` remain client-side. This is series-first plumbing, not a proof that arbitrary generated series are intrinsically post-quantum hard.

See `docs/SERIES_GENERATOR.md`.

## Cached evaluator sessions: RMS3

RMS3 installs expensive evaluator material once:

```text
RMS3 once
    256-bit public session id
    BinFHEContext
    refresh/bootstrap key
    switching key
          |
          v
 evaluator BTKeyLoad + process-local cache
```

The evaluator demo keeps a bounded process-local cache. Duplicate/all-zero IDs are rejected. The session ID is generated independently of `SeriesSeed` and is public routing/cache state rather than key material.

## Current remote job wire: RMJ4 / RMR4

The recurring remote-machine wire has moved from RMJ3/RMR3 to RMJ4/RMR4 because the retired ToyFingerprint fields were removed instead of retained as dead compatibility baggage.

```text
RMJ4 each job
    evaluator session id
    fixed public shape/profile
    encrypted zero
    encrypted program bits
    encrypted state bits
    encrypted head bits
    encrypted tape bits

RMR4 result
    evaluator session id
    same public shape/profile
    encrypted final state
    encrypted final head
    encrypted final tape
```

RMS3 remains the reusable evaluator-session format. RMJ4/RMR4 are intentionally wire-incompatible with RMJ3/RMR3.

See `docs/REMOTE_MACHINE.md`.

## SHA3-512 private program path

The current research branch contains two SHA3 construction layers:

- an auditable BooleanIR using XOR / AND / NOT with Keccak rho/pi represented as wiring;
- a compact 64-bit-lane Boolean program image with seven fixed-width operation classes.

The compact one-block SHA3-512 image uses 60 registers. The canonical image has 2073 instructions; the current deterministic polymorphic stress image permutes the register identities and inserts 32 semantics-preserving identity instructions for 2105 total instructions.

The fixed-path encrypted evaluator keeps opcode, source/destination register ids, input index, rotate amount and immediate encrypted, evaluates every candidate operation and homomorphically selects the active result.

### TFHE-rs CUDA

An optional Rust `cdylib` sidecar uses TFHE-rs 1.6.1 with its CUDA backend. It is exposed to C++ through a small C ABI and built with the `gpu-fhe` CMake preset.

Current boundary:

```text
trusted local C++/Rust sidecar
    keygen + encrypt program/input
             |
             v
       TFHE-rs CUDA VM
             |
             v
       local decrypt/check
```

This is a real CUDA FHE execution path but still a **local differential/stress boundary**, not the final remote protocol. The next protocol split is client-side keygen/encryption/serialization versus evaluator-side server-key-only execution.

The repository owner has built the CUDA path successfully on an RTX 5070 and observed the full mutated SHA3 stress test enter GPU execution. The current high-level universal VM implementation takes roughly 32 seconds per encrypted instruction on that machine, so the full 2105-instruction run is a performance stress case rather than a routine regression test.

## Integrity status

`ToyFingerprint32` has been **retired and removed**. Its plaintext/FHE mixer, candidate-mask bank, dedicated FHE harness and RMJ3/RMR3 wire fields are gone. Generic machine-bit serialization/encryption helpers that were useful independently of the toy experiment were moved into `remote_machine.*`.

The current integrity research is split deliberately:

```text
SHA3-512 quine commitment
    binds the issuer's intended job/context
    does NOT prove remote execution

SHA3-512 round receipt
    binds observed encrypted round states to job/session/profile
    attacks skip/replay/splice shortcuts
    is still research, not a universal proof of correct computation
```

The malicious-evaluator harness now compares final-output-only verification directly against the round-receipt construction. It no longer computes a legacy toy fingerprint.

Longer-term work is to bind integrity state more tightly to execution progress/final state and make the verification mechanism harder to detach from the polymorphed computation itself.

## WAMR MathVM sandbox

V0ID embeds WebAssembly Micro Runtime (WAMR), pinned to `WAMR-2.4.0`, with a deliberately narrow profile:

```text
classic interpreter       ON
instruction metering      ON
WASI                      OFF
libc host shims           OFF
AOT/JIT                    OFF
threads/shared memory     OFF
multi-module              OFF
mini-loader               OFF
```

V0ID pre-validates raw Wasm imports and linear-memory declarations before WAMR loads a module. The remote MathVM exposes bounded scalar and byte-provider ABIs rather than arbitrary peer-supplied native plugins.

Built-in/provider experiments include SHA3-256 and optional ML-KEM-768 through OpenSSL where the linked provider exposes it. Experimental toy arithmetic providers are explicitly not cryptographic security claims.

See `docs/MATHVM.md`.

## Client-only Wasm polymorphism

`WasmSeriesGenerator` is a second `PolymorphicSeriesGenerator` implementation:

```text
private SeriesSeed + semantic input + epoch
                  |
                  v
           polymorphism.wasm
          local WAMR only
                  |
                  v
       bounded private envelope
                  |
                  v
            ProgramMorpher
                  |
                  v
             morphed TM
```

The local Wasm profile forbids host imports, WASI/filesystem/network, clock/RNG imports and start functions, and uses bounded Wasm32 memory plus instruction metering. The guest never receives the plaintext `Program` transition table.

See `docs/POLYMORPH_WASM.md`.

## Remote encrypted-machine demo

Build both sides from the same checkout because RMJ4/RMR4 are intentionally wire-incompatible with the previous job/result format:

```sh
git pull
cmake -S . -B build
cmake --build build -j --target v0id-remote-machine
```

Evaluator (`1` counts encrypted jobs; RMS3 setup does not consume the count):

```sh
./build/v0id-remote-machine server EVAL tcp://*:7003 1
```

Client:

```sh
./build/v0id-remote-machine client CLIENT tcp://127.0.0.1:7003
```

The client prints one-time RMS3 session setup bytes and recurring RMJ4 per-job bytes so the caching win can be measured directly.

## CUDA stress build

```sh
cmake --preset gpu-fhe
cmake --build --preset gpu-fhe

CUDA_MODULE_LOADING=EAGER \
./build-gpu/v0id-encrypted-boolean-program-tests
```

The full SHA3 stress target is deliberately heavy. Fast correctness regression remains covered by the plaintext/OpenSSL and compact-image tests.

## Dependencies

- C++20 compiler
- C compiler for embedded WAMR sources
- CMake >= 3.20 (GPU preset/hook requires newer CMake features)
- Git during first configure
- OpenFHE with `OpenFHEConfig.cmake`
- OpenSSL >= 3 with KMAC-256 and SHA3 support
- OpenSSL 3.5+ provider support only if ML-KEM-768 capability is desired
- threads support
- optional Rust/Cargo + NVIDIA CUDA toolkit for the TFHE-rs CUDA sidecar

Fetched dependencies currently include:

- `zeromq/libzmq` v4.3.5
- `zeromq/cppzmq` v4.11.0
- `wasm-micro-runtime/wasm-micro-runtime` WAMR-2.4.0

## Source layout

```text
src/core/program.hpp                         machine Rule / Program representation
src/polymorph/program_morpher.*              semantic morph compiler + private manifest
src/polymorph/series_generator.*             built-in/functional series-first layer
src/polymorph/wasm_series_generator.*        client-only WAMR series generator
src/integrity/boolean_ir.*                   auditable Boolean construction layer
src/integrity/keccak_program_image.*         compact SHA3/Keccak program image
src/integrity/quine_hash.*                   client SHA3-512 commitment
src/integrity/round_receipt.*                execution-bound receipt research
src/integrity/malicious_evaluator_harness.cpp adversarial execution harness
src/fhe/encrypted_boolean_program.*          fixed-path OpenFHE Boolean evaluator
src/fhe/gpu_fhe_backend.*                    TFHE-rs CUDA C++ adapter
src/fhe/remote_machine_codec.hpp             RMS3/RMJ4/RMR4 wire format
src/fhe/remote_machine.*                     fixed-path encrypted machine evaluator
src/net/peer_transport.*                     binary ZeroMQ envelope transport
src/net/remote_machine_demo.cpp              cached remote encrypted-machine demo
src/mathvm/mathvm.*                          typed primitive registry / MathVM ABI
src/mathvm/wamr_sandbox.*                    WAMR policy + host boundary
docs/REMOTE_MACHINE.md                       current remote session/job protocol
docs/POLYMORPHISM.md                         morph/correlation threat model
docs/SERIES_GENERATOR.md                     series-first research boundary
docs/POLYMORPH_WASM.md                       local Wasm polymorphism boundary
docs/MATHVM.md                               WAMR sandbox/provider architecture
```

## Next milestones

Immediate direction:

```text
1. keep the working CPU/GPU FHE paths as correctness/performance baselines
2. split TFHE client keygen/encryption/serialization from remote server-key evaluation
3. define fixed public execution-envelope classes to reduce shape fingerprinting
4. bind session/job/profile/program/input/result context canonically
5. continue execution-bound integrity / cheap-verification research
6. attack skip/replay/splice/adaptive-evaluator strategies explicitly
```

Parallel later work includes distributed encrypted tape, trace classification, stronger polymorphism, authenticated session/profile binding, encrypted halt/no-op semantics and checkpoint/resume.

V0ID favors explicit research boundaries over features that cannot explain why they exist.

## License

V0ID is dual-licensed under the Apache License, Version 2.0 or the MIT License, at your option. See `LICENSE-APACHE`, `LICENSE-MIT`, and the top-level `LICENSE` notice.

Third-party dependencies and bundled third-party components remain subject to their respective licenses.
