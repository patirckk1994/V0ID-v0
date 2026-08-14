# V0ID

Research prototype for exact encrypted, runtime-programmable computation with client-side polymorphism, series-first morph derivation, remote BinFHE evaluation and a sandboxed mathematical/cryptographic extension layer.

**Current research scaffold: V0.4.4.**

V0ID is experimental research code, not audited production cryptography. The repository intentionally distinguishes runtime-proven plumbing milestones from implemented-but-unverified changes and from security conjectures.

## Current architecture

```text
                         V0ID
                           |
        +------------------+------------------+
        |                                     |
 encrypted machine path                  MathVM path
        |                                     |
 bounded universal                      sandboxed Wasm
 Boolean interpreter                    visible math/crypto IR
        |                                     |
 OpenFHE BinFHE                         primitive registry
        |                              /       |        \
 remote evaluator                 scalar    bytes    optional PQ
        |
 cached evaluator session
```

The two execution paths solve different problems:

- the encrypted Turing-machine-like interpreter is the universal exact path when program/state semantics should remain hidden from the evaluator;
- remote MathVM is the bounded portable path when the Wasm composition itself may be visible but arbitrary peer-supplied native plugins are not acceptable.

Wasm does **not** replace the encrypted Turing machine and an RMJ3 encrypted-machine job does not need to carry a Wasm program.

A separate future use of WAMR is client-only polymorphism: a `WasmSeriesGenerator` / morph generator can eventually run private user-defined transformation logic before encryption without transmitting that Wasm to the evaluator.

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

**Status:** implemented, not yet rebuilt/run on the development host. The next remote runtime gate is to confirm the existing series-derived `13 -> 14` computation and measure one-time RMS3 bytes versus recurring RMJ3 bytes.

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

WAMR validates the Wasm pointer/length pairs before the native call. V0ID copies the input into host-owned memory, enforces global and per-provider byte limits, invokes the typed provider, checks the returned size, and copies the result back into the validated Wasm buffer.

Provider descriptors now declare:

```text
stable tag
canonical id
version
abstract cost
experimental flag
ABI kind: u64 | bytes
max input bytes
max output bytes
```

A byte provider cannot be invoked through the scalar host call and vice versa.

### Built-in providers

```text
0x00010001  v0id.math.add-mod-u64/v1
0x00010002  v0id.math.mul-mod-u64/v1
0x00020001  v0id.crypto.sha3-256/v1                     [bytes]
0x00030301  v0id.pq.ml-kem-768.encapsulate/v1           [bytes, optional]
0x7fff0001  v0id.experimental.toy-lwe-affine-u64/v1     [EXPERIMENTAL]
```

`v0id.crypto.sha3-256` is an actual SHA3-256 provider backed by OpenSSL and is covered by a known-answer test for `"abc"`.

`v0id.pq.ml-kem-768.encapsulate` wraps OpenSSL's standardized ML-KEM-768 KEM implementation when the linked OpenSSL provider exposes it. V0ID probes that capability at runtime, so older OpenSSL 3.x hosts still build and simply do not advertise ML-KEM. V0ID does not implement ML-KEM arithmetic itself.

The ML-KEM provider accepts a raw public key and returns:

```text
u32be ciphertext_length
u32be shared_secret_length
ciphertext
shared_secret
```

Only encapsulation is exposed; there is deliberately no remote decapsulation provider that would encourage sending a client's private KEM key to an untrusted evaluator.

The toy affine provider still computes only:

```text
b = a*s + e mod q
```

and remains interface plumbing, **not LWE encryption and not a PQ security claim**.

See `docs/MATHVM.md`.

## MathVM resource limits

Default limits are:

```text
Wasm module             <= 1 MiB
linear memory           <= 16 pages / 1 MiB
stack                   <= 64 KiB
host-managed heap       <= 64 KiB
WAMR runtime pool       <= 16 MiB
Wasm instructions       <= 1,000,000
provider calls          <= 4,096
provider cost           <= 1,000,000 units
provider input buffer   <= 256 KiB
provider output buffer  <= 256 KiB
```

Native provider work has separate call/cost limits because time spent inside native crypto is not represented by Wasm instruction metering.

V0ID still rejects module memory declarations above the configured cap itself. ABI v2 therefore leaves WAMR's `max_memory_pages` override unset, avoiding the harmless warning produced when WAMR was asked to raise a module's own smaller maximum.

## V0.4.4 test gate

The updated test executable now covers the earlier rejection boundary plus:

```text
primitive_bytes through real WAMR memory
SHA3-256 known-answer test
undersized output-buffer rejection
scalar/byte ABI mismatch rejection
optional ML-KEM-768 encapsulate -> decapsulate round trip
```

On OpenSSL without ML-KEM the final test records the PQ provider as an unavailable optional capability instead of failing the suite.

**Status:** implemented, awaiting local compile/runtime verification.

Build and run:

```sh
git pull
cmake -S . -B build
cmake --build build -j --target v0id-mathvm-tests v0id-mathvm
./build/v0id-mathvm-tests
```

## External MathVM demos

Scalar composition:

```sh
clang --target=wasm32 -O2 -nostdlib \
  -Wl,--no-entry \
  -Wl,--allow-undefined \
  -Wl,--export=v0id_main \
  -Wl,--initial-memory=131072 \
  -Wl,--max-memory=1048576 \
  examples/mathvm/series_math.c \
  -o build/series_math.wasm

./build/v0id-mathvm build/series_math.wasm series
```

Byte-provider SHA3 demo:

```sh
clang --target=wasm32 -O2 -nostdlib \
  -Wl,--no-entry \
  -Wl,--allow-undefined \
  -Wl,--export=v0id_main \
  -Wl,--initial-memory=131072 \
  -Wl,--max-memory=1048576 \
  examples/mathvm/sha3_bytes.c \
  -o build/sha3_bytes.wasm

./build/v0id-mathvm build/sha3_bytes.wasm sha3
```

The SHA3 guest hashes `"abc"` through `primitive_bytes`, compares all 32 returned bytes against the known digest inside Wasm and returns `32` only on exact match.

Expected after runtime validation:

```text
result               : 32
provider calls       : 1
provider cost        : 256
```

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

The client prints:

```text
session setup bytes
  context bytes
  refresh key bytes
  switching key bytes
RMJ3 per-job bytes
cached setup resent: NO
```

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
src/core/program.hpp                    machine Rule / Program representation
src/polymorph/program_morpher.*         semantic morph compiler + private manifest
src/polymorph/series_generator.*        series-first generator layer
src/integrity/toy_fingerprint.*         test-only plaintext/FHE fingerprint
src/fhe/fhe_codec.hpp                   OpenFHE serialization helpers
src/fhe/remote_machine_codec.hpp        RMS3/RMJ3/RMR3 session/job wire format
src/fhe/remote_machine.*                fixed-path encrypted evaluator
src/net/peer_transport.*                binary ZeroMQ envelope transport
src/net/remote_machine_demo.cpp         cached remote encrypted-machine demo
src/mathvm/mathvm.*                     typed primitive registry / MathVM ABI v2
src/mathvm/wamr_sandbox.*               WAMR policy + scalar/byte host boundary
src/mathvm/mathvm_demo.cpp               external Wasm guest demo runner
src/mathvm/mathvm_tests.cpp              sandbox/provider regression gate
examples/mathvm/series_math.c            no-WASI scalar composition guest
examples/mathvm/sha3_bytes.c             no-WASI bounded byte-provider guest
docs/POLYMORPHISM.md                    morph/correlation threat model
docs/SERIES_GENERATOR.md                series-first research boundary
docs/REMOTE_MACHINE.md                  remote encrypted-machine/session protocol
docs/MATHVM.md                          WAMR sandbox/provider architecture
```

## Next milestones

Immediate order:

```text
1. rebuild/run V0.4.4 MathVM ABI-v2 provider gate and external SHA3 guest
2. rebuild/run V0.4.3 RMS3 -> cached evaluator -> RMJ3 -> BinFHE -> remote -> 14
3. record actual one-time evaluator setup bytes vs recurring RMJ3 bytes
4. add multi-job/session lifecycle tests + authenticated session/profile binding
5. add authenticated remote MathVM/provider capability negotiation if remote MathVM is needed
6. wire WAMR locally as a WasmSeriesGenerator / polymorphism-generator option
7. continue generated-relation / series-first primitive research only under explicit assumptions
```

Parallel later work includes distributed encrypted tape, trace classification, stronger polymorphism, execution-bound integrity, encrypted halt/no-op semantics and checkpoint/resume.

V0ID currently favors explicit research boundaries over features that cannot explain why they exist.
