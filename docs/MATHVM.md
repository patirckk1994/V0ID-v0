# V0ID MathVM / Wasm sandbox (V0.4.2)

V0ID MathVM is the experimental portability/sandbox layer for user-defined mathematical constructions.

The design deliberately does **not** transmit native `.so`, `.dll` or machine-code plugins. A user transmits portable WebAssembly containing mathematical composition/control, while the evaluator exposes only a small allowlisted V0ID host ABI backed by locally installed trusted primitive providers.

```text
user mathematical construction
          |
          v
portable .wasm bytecode
+ declared primitive manifest
          |
          v
V0ID WAMR sandbox
          |
          +--> exact classical providers
          +--> standardized crypto providers later
          +--> explicitly experimental PQ-test providers
```

This is a research scaffold, not an audited cryptographic sandbox or a claim that user-provided mathematics is secure.

## Why WAMR

V0.4.2 replaces the unfinished home-grown MathVM instruction-set draft with the WebAssembly Micro Runtime (WAMR), pinned to `WAMR-2.4.0`.

V0ID still defines the security policy and mathematical ABI; WAMR supplies the bytecode loader/interpreter, linear-memory sandbox and instruction metering.

The V0ID build profile intentionally selects:

```text
WAMR classic interpreter       ON
instruction metering           ON
WASI                           OFF
libc builtin/WASI shims        OFF
AOT                            OFF
JIT / fast-JIT                 OFF
threads                        OFF
shared memory                  OFF
multi-module                   OFF
mini-loader                    OFF
configurable bounds bypass     OFF
```

Instruction metering is the reason the first profile uses the classic interpreter rather than the faster interpreter/JIT paths.

## Trust boundary

A remote/user-supplied Wasm module may contain WebAssembly instructions, constants, local memory and calls to the single V0ID import:

```text
module: v0id_math
import: primitive_u64
signature:
    (tag:u64, version:u64, a:u64, b:u64, c:u64, d:u64) -> u64
```

It does **not** receive direct filesystem, socket, process, environment, thread or native-library APIs from V0ID.

The module must also travel with a `PrimitiveRequirement` manifest. Before execution V0ID verifies every requirement against the local `PrimitiveRegistry`. During execution the generic host call rejects any `(tag, version)` that was not declared by that program, even if the evaluator has such a provider installed.

This means a module cannot silently discover/use extra locally installed provider capabilities.

## Resource bounds

The current default `SandboxLimits` are intentionally small:

```text
Wasm module bytes       1 MiB
linear memory           16 pages = 1 MiB
Wasm stack              64 KiB
host-managed app heap   64 KiB
WAMR runtime pool       16 MiB
Wasm instructions       1,000,000
provider calls          4,096
provider cost           1,000,000 abstract units
```

The WAMR runtime itself is initialized from the fixed V0ID pool. The module is instantiated with a maximum page count and executed under WAMR instruction metering.

Native providers need a separate budget because time spent inside a native accelerator is not represented by Wasm bytecode instruction count. Every provider therefore has a declared cost; the host import counts both calls and accumulated provider cost and traps when either public limit is exhausted.

V0.4.2 allows one active `WamrMathSandbox` per process and serializes calls through it. This keeps the first trust model simple while WAMR is configured without application threads.

## Primitive registry

`src/mathvm/mathvm.hpp` contains the local provider interface.

A primitive has:

```text
stable numeric tag
canonical textual id
version
abstract cost
experimental flag
local evaluate_u64 implementation
```

The numeric tag is a protocol dispatch value, not a secret or cryptographic hash.

Current built-ins:

```text
0x00010001  v0id.math.add-mod-u64/v1
0x00010002  v0id.math.mul-mod-u64/v1
0x7fff0001  v0id.experimental.toy-lwe-affine-u64/v1
```

The first two are exact classical arithmetic providers.

The third computes only:

```text
b = a*s + e mod q
```

for scalar `u64` inputs. It exists solely to prove the provider/plugin plumbing. It is **not LWE encryption, not a post-quantum primitive, and carries no security claim**. Real LWE-style work requires dimensions, distributions, parameter selection and analysis that are intentionally absent here.

Trusted local applications can register additional `PrimitiveProvider` implementations. Remote peers still exchange only Wasm + identifiers/manifests; they do not install native code.

## Demo guest

`examples/mathvm/series_math.c` is a bare no-WASI guest that composes all three current providers.

Build the host sandbox:

```sh
git pull
cmake -S . -B build
cmake --build build -j --target v0id-mathvm
```

Build the example Wasm with a clang that supports the `wasm32` target:

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

The example computes:

```text
add-mod:       13 + 29 mod 97         = 42
toy relation:  5*7 + 3 mod 12289      = 38
mul-mod:       42 * 38 mod 65537       = 1596
```

Expected final result:

```text
result: 1596
provider calls: 3
OK: sandboxed Wasm composed locally installed math/PQ-test providers
```

## What is transmitted later

The next network object should look conceptually like:

```cpp
struct RemoteMathProgram {
    uint32_t mathvm_abi_version;
    bytes wasm;
    string entrypoint;
    vector<PrimitiveRequirement> required_primitives;
    public SandboxLimits limits;
};
```

Before accepting a remote math job, a peer can compare `required_primitives` with its installed registry. This is the beginning of capability negotiation without a native plugin loader.

The eventual handshake should authenticate the agreed VM ABI, provider ids/versions and resource profile to prevent downgrade/substitution.

## Planned provider expansion

The scalar ABI is intentionally tiny. Once the sandbox itself is proven, add bounded buffer-based imports for useful exact mathematical objects rather than expressing heavy work in Wasm instructions:

```text
byte strings / hashes
bounded big integers
mod-q vectors
matrices
polynomials
NTT/polynomial transforms
finite-field operations
standardized PQ primitives where appropriate
```

The pattern remains:

```text
Wasm = portable composition
provider = optimized local implementation
```

so a provider can later use ordinary C++, OpenSSL, a PQ library, AVX, GPU acceleration or a future backend without changing the transmitted mathematical program.

## Relationship to V0ID's encrypted Turing machine

MathVM is not currently replacing the encrypted TM. The near-term architecture is:

```text
TM path
    universal encrypted reference semantics

MathVM path
    fast, bounded, portable mathematical composition
    + user-defined primitive profiles
```

Later, selected MathVM operations may compile into or invoke FHE/PQ backends. Keeping these layers separate now lets V0ID test the sandbox and provider protocol at classical speed before paying BinFHE costs.

## Non-claims / open work

V0.4.2 does not yet provide:

- remote MathVM transport,
- authenticated capability negotiation,
- cryptographic signatures over Wasm/manifests,
- canonical Wasm normalization/hashing,
- vector/matrix/polynomial provider ABI,
- standardized PQ provider integration,
- a proof that WAMR + the V0ID host ABI is vulnerability-free,
- a proof that any user-defined series or primitive is post-quantum secure.

The immediate milestone is much narrower: compile the pinned WAMR profile, execute the bundled no-WASI module, verify resource limits and provider allowlisting, then fuzz/reject malformed modules before putting MathVM programs on the network.
