# V0ID

Research prototype for exact encrypted, runtime-programmable computation with client-side polymorphism, series-first morph derivation, remote BinFHE evaluation and a sandboxed mathematical extension layer.

**Current research scaffold: V0.4.2.**

V0ID is experimental research code, not audited production cryptography. The repository intentionally distinguishes proven plumbing milestones from security conjectures and future work.

## Current architecture

```text
                         V0ID
                           |
        +------------------+------------------+
        |                                     |
 encrypted machine path                  MathVM path
        |                                     |
 bounded universal                      sandboxed Wasm
 Boolean interpreter                    mathematical IR
        |                                     |
 OpenFHE BinFHE                         primitive registry
        |                              /       |        \
 remote evaluator                 classical   PQ   experimental
        |                                     |
        +------------------+------------------+
                           |
                 series / polymorphism
```

The two execution paths currently serve different purposes:

- the encrypted Turing-machine-like interpreter is the universal exact encrypted reference path;
- MathVM is the new bounded, faster, portable way to compose mathematical primitives without allowing peers to transmit native plugins.

## Proven V0.4 remote-machine milestone

The V0.4 whole-machine path has been run successfully across two local processes.

The client:

```text
semantic program
    -> private morph
    -> encrypted transition table
    -> encrypted state/head/tape
    -> encrypted integrity material
    -> network
```

The evaluator executed four fixed BinFHE rounds without receiving the LWE secret key or `MorphManifest`, then returned encrypted final machine state.

The client recovered:

```text
00001101 -> 00001110
13 -> 14
```

and verified its private integrity candidate.

The successful run transferred roughly:

```text
request: ~551 MB
result : ~666 KB
```

because BinFHE context/bootstrap material is still resent with every full-machine job. Persistent evaluator session/key caching is therefore a near-term engineering priority.

## V0.4.1: series first -> morph later

The client-side morph path now supports a `PolymorphicSeriesGenerator`:

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

The built-in profile is `v0id-series-kmac-v1`. Trusted local code can also inject its own generator through the generator interface/callback seam.

The private series, series seed, derived morph seed and `MorphManifest` do not leave the client.

This is an implementation of the **series-first research direction**, not a proof that an arbitrary generated series is intrinsically post-quantum hard.

See `docs/SERIES_GENERATOR.md`.

## V0.4.1 remote profile identifiers

The bounded remote-machine wire format is now `V0IDRMJ2` / `V0IDRMR2` and carries public profile identifiers such as:

```text
primitive             openfhe-binfhe
parameter set         STD128
machine protocol      v0id-remote-machine-v2
integrity profile     toy-fingerprint32-v1
series generator      v0id-series-kmac-v1 / v1
```

The evaluator fails closed on unsupported execution/integrity profiles and returns the profile with the result. The client requires an exact match.

This is self-description, not yet a full authenticated capability-negotiation protocol.

## V0.4.2: WAMR MathVM sandbox

V0.4.2 adds a portable mathematical execution layer based on WebAssembly Micro Runtime (WAMR), pinned to `WAMR-2.4.0`.

Instead of allowing this:

```text
peer -> arbitrary crypto_plugin.so -> evaluator
```

V0ID moves toward:

```text
peer/user
    -> portable Wasm mathematical composition
    -> explicit primitive manifest
    -> WAMR sandbox
    -> locally installed trusted primitive providers
```

The V0ID WAMR profile currently enables:

```text
classic interpreter       ON
instruction metering      ON
WASI                      OFF
libc host shims           OFF
AOT                       OFF
JIT                       OFF
threads/shared memory     OFF
multi-module              OFF
mini-loader               OFF
```

The current host ABI exposes only one generic scalar import:

```text
v0id_math.primitive_u64(
    tag,
    version,
    a,
    b,
    c,
    d
) -> u64
```

Every call is checked against the program's declared `PrimitiveRequirement` manifest.

Current built-in providers:

```text
0x00010001  v0id.math.add-mod-u64/v1
0x00010002  v0id.math.mul-mod-u64/v1
0x7fff0001  v0id.experimental.toy-lwe-affine-u64/v1
```

The experimental provider computes only:

```text
b = a*s + e mod q
```

and exists solely to prove the PQ-provider/plugin architecture. It is **not LWE encryption and carries no post-quantum security claim**.

See `docs/MATHVM.md`.

## MathVM sandbox limits

The initial defaults are deliberately bounded:

```text
Wasm module             <= 1 MiB
linear memory           <= 16 pages / 1 MiB
stack                   <= 64 KiB
host-managed heap       <= 64 KiB
WAMR runtime pool       <= 16 MiB
Wasm instructions       <= 1,000,000
provider calls          <= 4,096
provider cost           <= 1,000,000 units
```

Native provider work has a separate call/cost budget because time spent inside a native accelerator is not represented by Wasm instruction count.

## V0.4.2 sandbox self-tests

`v0id-mathvm-tests` constructs its Wasm modules directly in memory, so it does not need a wasm32 compiler.

The suite exercises:

- normal Wasm execution,
- a declared provider call,
- manifest id/tag mismatch rejection,
- undeclared provider rejection,
- provider call-budget exhaustion,
- infinite-loop instruction metering,
- oversized module rejection,
- excessive linear-memory rejection,
- non-Wasm/AOT-like input rejection,
- WASI import rejection,
- recovery after trapped/rejected jobs.

Build and run:

```sh
git pull
cmake -S . -B build
cmake --build build -j --target v0id-mathvm-tests
./build/v0id-mathvm-tests
```

This test target is the immediate validation gate before MathVM bytecode is placed on the network.

## Optional MathVM guest demo

Build the host:

```sh
cmake --build build -j --target v0id-mathvm
```

Compile the bundled no-WASI guest with a clang that supports `wasm32`:

```sh
clang --target=wasm32 -O2 -nostdlib \
  -Wl,--no-entry \
  -Wl,--allow-undefined \
  -Wl,--export=v0id_main \
  -Wl,--initial-memory=65536 \
  -Wl,--max-memory=1048576 \
  examples/mathvm/series_math.c \
  -o build/series_math.wasm
```

Run:

```sh
./build/v0id-mathvm build/series_math.wasm
```

Expected result:

```text
13 + 29 mod 97      = 42
5*7 + 3 mod 12289   = 38
42 * 38 mod 65537   = 1596

result: 1596
provider calls: 3
```

## Remote encrypted-machine demo

Build:

```sh
cmake -S . -B build
cmake --build build -j --target v0id-remote-machine
```

Evaluator:

```sh
./build/v0id-remote-machine server EVAL tcp://*:7003 1
```

Client:

```sh
./build/v0id-remote-machine client CLIENT tcp://127.0.0.1:7003
```

The V0.4.1 series/profile revision still needs an end-to-end regression run after the proven V0.4 baseline.

## Integrity status

`ToyFingerprint32` remains test-only plumbing.

It currently binds the encrypted morphed job image plus initial input/nonce and demonstrates private integrity-candidate placement, but:

- it is not a cryptographic hash,
- its dedicated evaluator circuit is recognizable,
- it does not prove every requested remote execution step was honestly performed,
- it is not yet bound to evolving/final machine state.

Future integrity work must move toward a real cryptographic construction and stronger verification machinery.

## Placement / correlation boundary

Remote tape ciphertexts are still transferred in logical tape order. Physical KMAC remapping and future distributed storage are separate work.

The intended later chain is:

```text
logical tape cell
    -> compiler relocation
    -> epoch remap
    -> peer selection
    -> peer-local slot
```

The existing remap is not claimed to provide ORAM/access-pattern privacy.

Evaluator-visible correlation surfaces still include timing, dependency shape, message sizes, peer access order, remap cadence and future storage-access patterns. Large morph/series trace sets and a classifier/distinguisher harness remain planned research work.

## Dependencies

- C++20 compiler
- C compiler for embedded WAMR sources
- CMake >= 3.20
- Git during first configure
- OpenFHE with `OpenFHEConfig.cmake`
- OpenSSL >= 3 with `KMAC-256`
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
src/fhe/remote_machine_codec.hpp        RMJ2/RMR2 machine/profile wire format
src/fhe/remote_machine.*                fixed-path encrypted evaluator
src/net/peer_transport.*                binary ZeroMQ envelope transport
src/net/remote_machine_demo.cpp         remote encrypted whole-machine demo
src/mathvm/mathvm.*                     primitive registry / MathVM ABI
src/mathvm/wamr_sandbox.*               WAMR sandbox wrapper and resource limits
src/mathvm/mathvm_demo.cpp               external Wasm guest demo runner
src/mathvm/mathvm_tests.cpp              self-contained sandbox rejection tests
examples/mathvm/series_math.c            no-WASI mathematical guest
docs/POLYMORPHISM.md                    morph/correlation threat model
docs/SERIES_GENERATOR.md                series-first research boundary
docs/REMOTE_MACHINE.md                  remote encrypted-machine protocol
docs/MATHVM.md                          WAMR sandbox/provider architecture
```

## Next milestones

Immediate order:

```text
1. compile/run v0id-mathvm-tests
2. fix every sandbox rejection failure until fail-closed behavior is confirmed
3. regression-run V0.4.1 series -> morph -> BinFHE -> remote -> 14
4. add persistent evaluator session/evaluation-key caching
5. define and transmit RemoteMathProgram
6. add authenticated MathVM/provider capability negotiation + downgrade protection
7. integrate a real standardized PQ provider
8. only then experiment with generated-relation / series-first key-exchange research
```

Parallel later work includes distributed encrypted tape, trace classification, stronger polymorphism, encrypted halt/no-op semantics, checkpoint/resume and real hidden-integrity machinery.

V0ID currently favors explicit research boundaries over pretending unproven components are secure.
