# V0ID

Research prototype for exact encrypted, runtime-programmable computation with client-side polymorphism, series-first morph derivation, remote BinFHE evaluation and a sandboxed mathematical extension layer.

**Current research scaffold: V0.4.3.**

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
 cached evaluator session                     |
        |                                     |
        +------------------+------------------+
                           |
                 series / polymorphism
```

The two execution paths currently serve different purposes:

- the encrypted Turing-machine-like interpreter is the universal exact encrypted reference path;
- MathVM is the bounded, faster, portable way to compose mathematical primitives without allowing peers to transmit native plugins.

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

The successful V0.4 run transferred roughly:

```text
request: ~551 MB
result : ~666 KB
```

The large request was dominated by BinFHE context/bootstrap material being resent with the job. V0.4.3 now addresses that engineering bottleneck by separating evaluator-session setup from recurring RMJ3 jobs.

## V0.4.1: series first -> morph later

The client-side morph path supports a `PolymorphicSeriesGenerator`:

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

## V0.4.3: cached BinFHE evaluator sessions

V0.4.1 introduced public crypto/profile IDs in RMJ2/RMR2. V0.4.3 bumps the remote-machine protocol to RMS3/RMJ3/RMR3 and removes the expensive evaluator material from each job.

Old shape:

```text
RMJ2 every job
    BinFHEContext
    refresh/bootstrap key
    switching key
    encrypted machine
```

V0.4.3 shape:

```text
RMS3 once per evaluator session
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
    encrypted machine only
```

The evaluator demo currently retains up to four loaded sessions in memory. Sessions are not persisted to disk and disappear when the process exits. Duplicate/all-zero IDs are rejected.

The session ID is generated independently of `SeriesSeed`; it is public routing/cache state, not secret key material.

Current job profile:

```text
primitive             openfhe-binfhe
parameter set         STD128
machine protocol      v0id-remote-machine-v3
integrity profile     toy-fingerprint32-v1
series generator      v0id-series-kmac-v1 / v1
```

An RMJ3 job must reference an installed session whose primitive and parameter set match the job profile. The server echoes both session ID and full profile in RMR3 and the client requires exact matches.

This is still self-description rather than authenticated negotiation. Session/profile authentication and downgrade protection remain future work.

See `docs/REMOTE_MACHINE.md`.

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
    -> V0ID Wasm pre-validator
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

Every call is checked against the program's declared `PrimitiveRequirement` manifest. Before WAMR loads the module, V0ID also rejects non-allowlisted imports and linear-memory declarations outside the sandbox policy.

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

## Proven V0.4.2 local MathVM milestone

The WAMR host and rejection-boundary suite have been compiled and run successfully on the project's Linux development host:

```text
V0ID MathVM sandbox tests: 11 passed, 0 failed
OK: local MathVM sandbox rejection boundary exercised
```

Verified cases include valid execution, manifest enforcement, undeclared-provider rejection, provider-budget exhaustion, infinite-loop instruction metering, module-size/memory limits, non-Wasm rejection, WASI/non-allowlisted-import rejection and recovery after trapped jobs.

The externally compiled no-WASI guest has also been run successfully. With the current clang/wasm-ld toolchain it produced a 458-byte module and reported:

```text
V0ID MathVM ABI      : v1
module bytes         : 458
result               : 1596
provider calls       : 3
provider cost        : 130
OK: sandboxed Wasm composed locally installed math/PQ-test providers
```

This is a functional local sandbox/ABI milestone, not a proof that WAMR or the V0ID host ABI is vulnerability-free.

Build and rerun the rejection gate with:

```sh
git pull
cmake -S . -B build
cmake --build build -j --target v0id-mathvm-tests
./build/v0id-mathvm-tests
```

## MathVM guest demo

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
  -Wl,--initial-memory=131072 \
  -Wl,--max-memory=1048576 \
  examples/mathvm/series_math.c \
  -o build/series_math.wasm
```

Run:

```sh
./build/v0id-mathvm build/series_math.wasm
```

## V0.4.3 remote encrypted-machine demo

Build both client and evaluator from the same checkout because RMJ3 is wire-incompatible with RMJ2:

```sh
git pull
cmake -S . -B build
cmake --build build -j --target v0id-remote-machine
```

Evaluator (`1` counts jobs; the RMS3 setup message does not consume the count):

```sh
./build/v0id-remote-machine server EVAL tcp://*:7003 1
```

Client:

```sh
./build/v0id-remote-machine client CLIENT tcp://127.0.0.1:7003
```

The client prints the one-time session setup size and the new RMJ3 per-job size separately:

```text
session setup bytes
  context bytes
  refresh key bytes
  switching key bytes
RMJ3 per-job bytes
cached setup resent: NO
```

V0.4.3 is implemented but has not yet been rebuilt/run locally. The next runtime milestone is to confirm the existing series-derived `13 -> 14` computation and private self-check still pass while measuring how far the recurring RMJ3 payload falls below the old ~551 MB request.

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
src/fhe/remote_machine_codec.hpp        RMS3/RMJ3/RMR3 session/job wire format
src/fhe/remote_machine.*                fixed-path encrypted evaluator
src/net/peer_transport.*                binary ZeroMQ envelope transport
src/net/remote_machine_demo.cpp         cached remote encrypted-machine demo
src/mathvm/mathvm.*                     primitive registry / MathVM ABI
src/mathvm/wamr_sandbox.*               WAMR sandbox wrapper and resource limits
src/mathvm/mathvm_demo.cpp               external Wasm guest demo runner
src/mathvm/mathvm_tests.cpp              self-contained sandbox rejection tests
examples/mathvm/series_math.c            no-WASI mathematical guest
docs/POLYMORPHISM.md                    morph/correlation threat model
docs/SERIES_GENERATOR.md                series-first research boundary
docs/REMOTE_MACHINE.md                  remote encrypted-machine/session protocol
docs/MATHVM.md                          WAMR sandbox/provider architecture
```

## Next milestones

Immediate order:

```text
1. rebuild/run V0.4.3 RMS3 -> cached evaluator -> RMJ3 -> BinFHE -> remote -> 14
2. record actual one-time setup bytes vs recurring per-job bytes
3. add multi-job/session lifecycle tests and authenticated session/profile binding
4. define and transmit RemoteMathProgram
5. add authenticated MathVM/provider capability negotiation + downgrade protection
6. integrate a real standardized PQ provider
7. experiment with generated-relation / series-first key-exchange research only under explicit assumptions
```

Parallel later work includes distributed encrypted tape, trace classification, stronger polymorphism, encrypted halt/no-op semantics, checkpoint/resume and real hidden-integrity machinery.

V0ID currently favors explicit research boundaries over pretending unproven components are secure.
