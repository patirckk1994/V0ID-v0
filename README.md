# V0ID

Research prototype for exact encrypted, runtime-programmable computation with client-side polymorphism, series-first morph derivation, remote BinFHE evaluation and sandboxed Wasm extension layers.

**Current research scaffold: V0.4.5.**

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
 OpenFHE BinFHE
          |
 cached remote evaluator
```

The execution paths solve different problems:

- the encrypted Turing-machine-like interpreter is the universal exact path when program/state semantics should remain hidden from the evaluator;
- local `WasmSeriesGenerator` is a client-only programmable polymorphism strategy that derives private morph material before encryption;
- remote MathVM is the bounded portable path when the Wasm composition itself may be visible but arbitrary peer-supplied native plugins are not acceptable.

Wasm does **not** replace the encrypted Turing machine and an RMJ3 encrypted-machine job does not need to carry a Wasm program. The local polymorphism Wasm is not transmitted to the evaluator.

## Proven V0.4 remote-machine milestone

The V0.4 whole-machine path has been run successfully across two local processes.

The client sent encrypted transition/state/head/tape/integrity material; the evaluator executed four fixed BinFHE rounds without receiving the LWE secret key or `MorphManifest` and returned encrypted state.

The client recovered:

```text
00001101 -> 00001110
13 -> 14
```

and verified its private integrity candidate.

That run transferred roughly:

```text
request: ~551 MB
result : ~666 KB
```

because BinFHE context/bootstrap material was embedded in each job.

## V0.4.1: series first -> morph later

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

The built-in profile is `v0id-series-kmac-v1`. The private series, series seed, derived morph seed and `MorphManifest` remain client-side.

This is series-first plumbing, not a proof that arbitrary generated series are intrinsically post-quantum hard.

See `docs/SERIES_GENERATOR.md`.

## V0.4.3: cached BinFHE evaluator sessions

V0.4.3 changes the remote-machine protocol to RMS3/RMJ3/RMR3 so expensive evaluator material can be installed once and reused.

```text
RMS3 once
    256-bit public session id
    BinFHEContext
    refresh/bootstrap key
    switching key
          |
          v
 evaluator BTKeyLoad + process-local cache
          |
          v
RMJ3 each job
    session id
    encrypted machine material only
```

The evaluator demo keeps up to four process-local sessions. Duplicate/all-zero IDs are rejected. The session ID is generated independently of `SeriesSeed` and is public routing/cache state rather than key material.

An RMJ3 job must match the cached session's primitive and parameter set; RMR3 echoes session ID and full public crypto profile and the client requires exact matches.

**Status:** implemented, not yet rebuilt/run on the development host after the V0.4.3 caching change. The next remote runtime gate is to confirm the existing series-derived `13 -> 14` computation and measure one-time RMS3 bytes versus recurring RMJ3 bytes.

See `docs/REMOTE_MACHINE.md`.

## V0.4.2 baseline: WAMR MathVM sandbox

V0.4.2 embedded WebAssembly Micro Runtime (WAMR), pinned to `WAMR-2.4.0`, with a deliberately narrow profile:

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

V0ID pre-validates raw Wasm imports and linear-memory declarations before WAMR loads a module. The earlier rejection-boundary suite was runtime-verified:

```text
V0ID MathVM sandbox tests: 11 passed, 0 failed
OK: local MathVM sandbox rejection boundary exercised
```

The external scalar guest was also runtime-verified:

```text
module bytes         : 458
result               : 1596
provider calls       : 3
provider cost        : 130
```

That establishes the scalar/WAMR baseline; it is not a proof that WAMR or the V0ID host ABI is vulnerability-free.

## V0.4.4: MathVM primitive ABI v2

V0.4.4 turns the primitive layer from a scalar demo into a usable bounded crypto-provider interface.

ABI v1 scalar import remains:

```text
v0id_math.primitive_u64(
    tag, version,
    a, b, c, d
) -> u64
```

ABI v2 adds:

```text
v0id_math.primitive_bytes(
    tag, version,
    input_ptr, input_len,
    output_ptr, output_capacity
) -> i32 written
```

The host validates complete Wasm input/output ranges, copies the input into host-owned memory, enforces global and per-provider byte limits, invokes the typed provider, checks the returned size and copies the result back into the validated Wasm buffer.

Provider descriptors declare stable tag, canonical id, version, abstract cost, experimental flag, ABI kind and byte limits. A byte provider cannot be invoked through the scalar host call and vice versa.

### Built-in providers

```text
0x00010001  v0id.math.add-mod-u64/v1
0x00010002  v0id.math.mul-mod-u64/v1
0x00020001  v0id.crypto.sha3-256/v1                     [bytes]
0x00030301  v0id.pq.ml-kem-768.encapsulate/v1           [bytes, optional]
0x7fff0001  v0id.experimental.toy-lwe-affine-u64/v1     [EXPERIMENTAL]
```

`v0id.crypto.sha3-256` is an actual SHA3-256 provider backed by OpenSSL. `v0id.pq.ml-kem-768.encapsulate` wraps OpenSSL's standardized ML-KEM-768 KEM implementation when the linked OpenSSL provider exposes it. Only encapsulation is exposed; there is deliberately no remote decapsulation provider that would encourage sending a client's private KEM key to an untrusted evaluator.

The toy affine provider still computes only:

```text
b = a*s + e mod q
```

and remains interface plumbing, **not LWE encryption and not a PQ security claim**.

### Runtime-verified V0.4.4 gate

The development host has now run:

```text
V0ID MathVM sandbox/provider tests: 16 passed, 0 failed
V0ID MathVM byte-boundary tests:    4 passed, 0 failed
```

The passing gate includes SHA3-256 known-answer testing, a real ML-KEM-768 encapsulate/decapsulate round trip, undeclared/ABI mismatch rejection, instruction/provider budgets, input/output OOB rejection and sandbox recovery after traps.

The external compiled SHA3 guest also ran successfully:

```text
V0ID MathVM ABI      : v2
module bytes         : 671
result               : 32
provider calls       : 1
provider cost        : 256
```

The UBSan-aware WAMR build also completed the 16-test suite successfully. The separate ASan build remains blocked by WAMR 2.4.0's native-stack-overflow detector before the test body and is not claimed as ASan-clean.

See `docs/MATHVM.md`.

## MathVM resource limits

Default limits are:

```text
Wasm module             <= 1 MiB
linear memory           <= 16 pages / 1 MiB
stack                   <= 64 KiB
host-managed app heap   disabled
WAMR runtime pool       <= 16 MiB
Wasm instructions       <= 1,000,000
provider calls          <= 4,096
provider cost           <= 1,000,000 units
provider input buffer   <= 256 KiB
provider output buffer  <= 256 KiB
```

The host-managed app heap is disabled because WAMR inserts it into the module's linear-memory allocation and can otherwise enlarge the actually addressable range beyond the module-declared page count. V0ID keeps `max_memory_pages` as the meaningful hard linear-memory ceiling for this profile.

Native provider work has separate call/cost limits because time spent inside native crypto is not represented by Wasm instruction metering.

## V0.4.5: client-only Wasm polymorphism

V0.4.5 adds `WasmSeriesGenerator` as a second `PolymorphicSeriesGenerator` implementation.

```text
private SeriesSeed + semantic input + epoch
                  |
                  v
           polymorphism.wasm
          local WAMR only
                  |
                  v
       V0P1 bounded envelope
      series + MorphSeed + manifest
                  |
                  v
          trusted validation
                  |
                  v
            ProgramMorpher
                  |
                  v
             morphed TM
```

The local Wasm profile is intentionally stricter than remote MathVM:

```text
host imports             0 / forbidden
WASI/filesystem/network  unavailable
clock/RNG imports        unavailable
start function           forbidden
host-managed app heap    disabled
instruction metering     enabled
bounded Wasm32 memory    required
```

The guest never receives the `Program` transition table. It returns only a canonical `V0P1` envelope containing a private series, 32-byte `MorphSeed` and private manifest. Trusted C++ validates the envelope and keeps state permutation, dummy-state insertion, transition rewriting and integrity placement inside `ProgramMorpher`.

**Status:** implementation and self-contained tests are in-tree; runtime verification of the V0.4.5 gate is pending.

See `docs/POLYMORPH_WASM.md`.

### V0.4.5 test gate

```sh
git pull
cmake -S . -B build
cmake --build build -j --target v0id-wasm-polymorph-tests
./build/v0id-wasm-polymorph-tests
```

The suite constructs tiny Wasm modules in memory and checks deterministic derivation, epoch/input sensitivity, V0P1 parsing, import/memory/output rejection, instruction metering and semantic preservation through trusted `ProgramMorpher`.

External guest:

```sh
clang --target=wasm32 -O2 -nostdlib \
  -Wl,--no-entry \
  -Wl,--export=v0id_buffer_base \
  -Wl,--export=v0id_polymorph \
  -Wl,--initial-memory=1048576 \
  -Wl,--max-memory=1048576 \
  examples/polymorph/series_mixer.c \
  -o build/series_mixer.wasm

cmake --build build -j --target v0id-wasm-polymorph-demo
./build/v0id-wasm-polymorph-demo build/series_mixer.wasm
```

`series_mixer.c` is demonstration plumbing, not a cryptographic PRF/KDF claim.

## V0.4.3 remote encrypted-machine demo

Build both sides from the same checkout because RMJ3 is wire-incompatible with RMJ2:

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

The client prints one-time session setup bytes and recurring RMJ3 per-job bytes so the caching win can be measured directly.

## Integrity status

`ToyFingerprint32` remains test-only plumbing. It binds the encrypted morphed job image plus initial input/nonce and demonstrates private integrity-candidate placement, but it does not prove that every requested remote round was honestly performed.

The longer-term integrity experiment is to bind verification state to **execution progress/final state** and interleave it with the polymorphed encrypted machine so an evaluator cannot trivially identify and preserve only the checking logic. Polymorphism can help hide structural roles; it does not by itself constitute a proof of correct execution.

## Dependencies

- C++20 compiler
- C compiler for embedded WAMR sources
- CMake >= 3.20
- Git during first configure
- OpenFHE with `OpenFHEConfig.cmake`
- OpenSSL >= 3 with `KMAC-256` and SHA3-256
- OpenSSL 3.5+ provider support only if ML-KEM-768 capability is desired
- threads support

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
src/polymorph/wasm_series_tests.cpp          local Wasm polymorphism regression gate
src/polymorph/wasm_series_demo.cpp           external local Wasm guest runner
src/integrity/toy_fingerprint.*              test-only plaintext/FHE fingerprint
src/fhe/fhe_codec.hpp                        OpenFHE serialization helpers
src/fhe/remote_machine_codec.hpp             RMS3/RMJ3/RMR3 session/job wire format
src/fhe/remote_machine.*                     fixed-path encrypted evaluator
src/net/peer_transport.*                     binary ZeroMQ envelope transport
src/net/remote_machine_demo.cpp              cached remote encrypted-machine demo
src/mathvm/mathvm.*                          typed primitive registry / MathVM ABI v2
src/mathvm/wamr_sandbox.*                    WAMR policy + scalar/byte host boundary
src/mathvm/mathvm_demo.cpp                    external remote-visible Wasm demo runner
src/mathvm/mathvm_tests.cpp                   sandbox/provider regression gate
src/mathvm/byte_boundary_tests.cpp            explicit ABI-v2 pointer/length gate
examples/mathvm/series_math.c                 no-WASI scalar composition guest
examples/mathvm/sha3_bytes.c                  no-WASI bounded byte-provider guest
examples/polymorph/series_mixer.c             client-only Wasm polymorphism guest
docs/POLYMORPHISM.md                         morph/correlation threat model
docs/SERIES_GENERATOR.md                     series-first research boundary
docs/POLYMORPH_WASM.md                       local Wasm polymorphism ABI/boundary
docs/REMOTE_MACHINE.md                       remote encrypted-machine/session protocol
docs/MATHVM.md                               WAMR sandbox/provider architecture
```

## Next milestones

Immediate order:

```text
1. build/run V0.4.5 local Wasm polymorphism gate
2. compile/run the external series_mixer.wasm demo
3. if both pass, optionally wire WasmSeriesGenerator into the remote-machine client path
4. rebuild/run V0.4.3 RMS3 -> cached evaluator -> RMJ3 -> BinFHE -> remote -> 14
5. record actual one-time evaluator setup bytes vs recurring RMJ3 bytes
6. move next to execution-bound integrity / cheap verification research
7. continue generated-relation / series-first primitive research only under explicit assumptions
```

Parallel later work includes distributed encrypted tape, trace classification, stronger polymorphism, authenticated session/profile binding, encrypted halt/no-op semantics and checkpoint/resume.

V0ID currently favors explicit research boundaries over features that cannot explain why they exist.
