# V0ID MathVM / Wasm sandbox (ABI v2)

V0ID MathVM is the portability/sandbox layer for user-defined mathematical and cryptographic compositions.

It deliberately does **not** let a peer install native `.so`, `.dll` or machine-code plugins. A program may instead carry portable WebAssembly plus an explicit primitive manifest; the evaluator exposes only a tiny allowlisted V0ID host ABI backed by locally installed providers.

```text
visible mathematical / crypto composition
                |
                v
        portable .wasm bytecode
      + primitive requirement list
                |
                v
        V0ID Wasm pre-validator
                |
                v
             WAMR
                |
        +-------+-------+
        |               |
 primitive_u64     primitive_bytes
        |               |
 local scalar      local bounded-buffer
 providers         crypto providers
```

This is experimental research code, not an audited cryptographic sandbox.

## Relationship to the encrypted Turing-machine path

MathVM does **not** replace V0ID's encrypted Turing machine.

The two paths solve different problems:

```text
encrypted TM
    hidden program semantics
    encrypted state/head/tape
    BinFHE evaluator executes a fixed universal path

remote MathVM
    evaluator is allowed to see the Wasm composition
    Wasm selects/composes locally installed math/crypto providers
    no peer-supplied native code
```

Therefore an encrypted-TM job does not need to transmit Wasm alongside its encrypted transition table.

A second, separate use of WAMR is planned on the **client only**: a future `WasmSeriesGenerator` / polymorphism generator can run private user-defined morph logic locally before the machine is encrypted. That Wasm would not be sent to the evaluator.

## WAMR profile

WAMR remains pinned to `WAMR-2.4.0` and is embedded with a deliberately narrow configuration:

```text
classic interpreter       ON
instruction metering      ON
WASI                      OFF
libc builtin/WASI shims   OFF
AOT                       OFF
JIT / fast-JIT            OFF
threads                    OFF
shared memory              OFF
multi-module               OFF
mini-loader                OFF
configurable bounds bypass OFF
```

V0ID still owns the security policy. WAMR supplies bytecode validation/execution, linear-memory isolation and instruction metering.

Before WAMR loads a module, V0ID also parses enough of the raw Wasm binary to fail closed on the host surface and memory policy. Only the two `v0id_math` function imports below are accepted. WASI, other host modules, imported memories/tables/globals, unbounded memory, memory64 and shared-memory forms are rejected.

## ABI v2 host imports

ABI v2 is additive. Existing scalar guests keep using:

```text
module: v0id_math
import: primitive_u64

(tag:u64,
 version:u64,
 a:u64,
 b:u64,
 c:u64,
 d:u64) -> u64
```

ABI v2 adds:

```text
module: v0id_math
import: primitive_bytes

(tag:u64,
 version:u64,
 input:*u8,
 input_len:u32,
 output:*u8,
 output_capacity:u32) -> i32 written
```

WAMR's native signature is `(II*~*~)i`, so it converts the two Wasm offsets to native addresses only after checking each pointer against the following byte length. V0ID then copies the input into host-owned memory before invoking the provider and copies the bounded result back into the validated Wasm output buffer.

A byte call traps if:

- the primitive is undeclared,
- the tag/version refers to a scalar provider,
- input exceeds the provider or sandbox input limit,
- output exceeds the provider or sandbox output limit,
- the supplied Wasm output buffer is too small,
- provider call/cost budgets are exhausted,
- the provider itself rejects the input.

This keeps raw unchecked Wasm pointers out of the provider interface.

## Primitive manifests and registry

Every `WasmMathProgram` carries `PrimitiveRequirement` entries:

```text
numeric tag
canonical textual id
version
```

The local `PrimitiveDescriptor` additionally declares:

```text
abstract cost
experimental flag
ABI kind: u64 | bytes
maximum input bytes       (byte providers)
maximum output bytes      (byte providers)
```

The registry refuses duplicate tag/version registrations and verifies the canonical id. At runtime the selected host import must also match the provider ABI: a byte provider cannot be invoked through `primitive_u64`, and vice versa.

The numeric tags are protocol dispatch values, not secrets or cryptographic hashes.

## Built-in providers

Current built-ins are:

```text
0x00010001  v0id.math.add-mod-u64/v1
            ABI: u64

0x00010002  v0id.math.mul-mod-u64/v1
            ABI: u64

0x00020001  v0id.crypto.sha3-256/v1
            ABI: bytes
            standardized SHA3-256 through OpenSSL

0x00030301  v0id.pq.ml-kem-768.encapsulate/v1
            ABI: bytes
            optional standardized ML-KEM-768 encapsulation
            registered only when the linked OpenSSL provider exposes ML-KEM

0x7fff0001  v0id.experimental.toy-lwe-affine-u64/v1
            ABI: u64
            EXPERIMENTAL / NO SECURITY CLAIM
```

The toy affine provider still computes only:

```text
b = a*s + e mod q
```

for scalar integers. It remains interface plumbing, **not LWE encryption and not a post-quantum primitive**.

### SHA3-256 byte provider

Input is an arbitrary bounded byte string. Output is exactly 32 bytes.

The test suite checks the standard SHA3-256 digest of `"abc"` and also calls the provider from an in-memory Wasm module through `primitive_bytes`.

### Optional ML-KEM-768 provider

V0ID does not implement ML-KEM arithmetic itself. When the linked OpenSSL installation exposes `ML-KEM-768`, the default registry installs an encapsulation-only provider around OpenSSL's EVP KEM API.

Input:

```text
raw ML-KEM-768 public key bytes
```

Output uses one canonical V0ID envelope:

```text
u32be ciphertext_length
u32be shared_secret_length
ciphertext[ciphertext_length]
shared_secret[shared_secret_length]
```

Only encapsulation is exposed. There is deliberately no remote MathVM decapsulation provider in this scaffold because blindly moving a client's private KEM key into an untrusted evaluator would defeat the intended trust boundary.

The provider is an optional capability rather than a build requirement. OpenSSL versions/providers without ML-KEM still build ABI v2 and advertise SHA3/scalar providers normally.

When ML-KEM is available, `v0id-mathvm-tests` generates an ML-KEM-768 keypair, exports the public key, encapsulates through the V0ID provider, decapsulates with OpenSSL and requires the two shared secrets to match.

## Resource bounds

Default `SandboxLimits` are:

```text
Wasm module bytes         1 MiB
linear memory             16 pages = 1 MiB
Wasm stack                64 KiB
host-managed app heap     64 KiB
WAMR runtime pool         16 MiB
Wasm instructions         1,000,000
provider calls            4,096
provider cost             1,000,000 abstract units
provider input buffer     256 KiB
provider output buffer    256 KiB
```

Provider byte limits may not exceed the entire linear-memory sandbox cap. Individual byte-provider descriptors can impose smaller limits.

Native provider work has a separate call/cost budget because time spent inside a native implementation is not represented by Wasm instruction count.

V0ID pre-validates each module's declared linear-memory min/max against the sandbox cap. Because that policy is already fail-closed, ABI v2 no longer asks WAMR to override a module's smaller maximum at instantiation; this removes the harmless `Cannot override max memory with value greater than module max memory` warning seen in the earlier external demo.

## Runtime-verified baseline vs ABI v2 status

The earlier scalar/rejection boundary is runtime-verified on the project's Linux host:

```text
V0ID MathVM sandbox tests: 11 passed, 0 failed
```

and the external scalar guest was also run successfully:

```text
module bytes         : 458
result               : 1596
provider calls       : 3
provider cost        : 130
```

ABI v2, the byte-provider tests, SHA3 guest and optional ML-KEM round-trip are **implemented but still require the next local rebuild/run**. Do not treat them as runtime-verified until that output is recorded.

Run the gate with:

```sh
git pull
cmake -S . -B build
cmake --build build -j --target v0id-mathvm-tests v0id-mathvm
./build/v0id-mathvm-tests
```

## External scalar demo

Compile:

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
./build/v0id-mathvm build/series_math.wasm series
```

Expected result remains `1596` with three provider calls.

## External byte-provider demo

`examples/mathvm/sha3_bytes.c` hashes `"abc"` through `primitive_bytes`, compares all 32 returned digest bytes against the known SHA3-256 value inside Wasm, and returns `32` only when they match.

Compile:

```sh
clang --target=wasm32 -O2 -nostdlib \
  -Wl,--no-entry \
  -Wl,--allow-undefined \
  -Wl,--export=v0id_main \
  -Wl,--initial-memory=131072 \
  -Wl,--max-memory=1048576 \
  examples/mathvm/sha3_bytes.c \
  -o build/sha3_bytes.wasm
```

Run:

```sh
./build/v0id-mathvm build/sha3_bytes.wasm sha3
```

Expected ABI-v2 result after runtime validation:

```text
result               : 32
provider calls       : 1
provider cost        : 256
```

## What may be transmitted later

For a **visible MathVM computation**, the network object can eventually be:

```cpp
struct RemoteMathProgram {
    uint32_t mathvm_abi_version;
    bytes wasm;
    string entrypoint;
    vector<PrimitiveRequirement> required_primitives;
    public SandboxLimits limits;
};
```

The receiver can reject unsupported provider ids/versions before execution. An authenticated negotiation must eventually bind the agreed VM ABI, provider set and resource profile to prevent downgrade/substitution.

This object is not needed for the encrypted-TM protocol. The TM path already transmits its program as encrypted transition data.

## Remaining primitive-layer work

The basic provider architecture is now feature-complete enough for useful cryptographic work: scalar calls, bounded bytes, explicit provider type, manifests, resource budgets, one always-available standardized byte provider and one optional standardized PQ provider.

Further additions should earn their existence. Useful next extensions include bounded structured encodings for:

```text
big integers
mod-q vectors
matrices
polynomials / NTT operands
standardized signature operations where the trust boundary makes sense
```

Those do not require another VM architecture; they are provider formats layered on the existing bounded byte call.

## Non-claims / open work

MathVM still does not provide:

- audited sandbox security,
- authenticated remote capability negotiation,
- signatures over Wasm/manifests,
- canonical Wasm normalization/hashing,
- privacy for the Wasm program itself when it is sent to an evaluator,
- a proof that arbitrary user-defined mathematics is secure,
- a new post-quantum hardness assumption.

ML-KEM security, when available, comes from the standardized ML-KEM implementation supplied by OpenSSL; V0ID's contribution here is the bounded provider/orchestration boundary, not a new KEM.
