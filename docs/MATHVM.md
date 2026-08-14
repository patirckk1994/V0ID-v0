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

## Relationship to the encrypted-machine path

MathVM does **not** replace V0ID's encrypted Turing-machine-like interpreter.

```text
encrypted machine
    hidden program semantics
    encrypted state/head/tape
    BinFHE evaluator executes a fixed universal path

remote MathVM
    evaluator may see the Wasm composition
    Wasm selects/composes locally installed math/crypto providers
    no peer-supplied native code

local Wasm polymorphism (V0.4.5)
    client-only private strategy
    derives series/MorphSeed before ProgramMorpher
    Wasm is never transmitted to the evaluator
```

The local polymorphism layer has its own stricter ABI and is documented in `docs/POLYMORPH_WASM.md`.

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

V0ID owns the policy. WAMR supplies bytecode validation/execution, linear-memory isolation and instruction metering.

Before WAMR loads a MathVM module, V0ID parses enough raw Wasm to fail closed on the host surface and memory policy. Only `v0id_math.primitive_u64` and `v0id_math.primitive_bytes` imports are accepted. WASI, other host modules, imported memories/tables/globals, unbounded memory, memory64 and shared-memory forms are rejected.

## ABI v2 host imports

Scalar ABI:

```text
v0id_math.primitive_u64(
    tag:u64,
    version:u64,
    a:u64, b:u64, c:u64, d:u64
) -> u64
```

Bounded byte ABI:

```text
v0id_math.primitive_bytes(
    tag:u64,
    version:u64,
    input_ptr:*u8,
    input_len:u32,
    output_ptr:*u8,
    output_capacity:u32
) -> i32 written
```

The WAMR native signature is `(II*~*~)i`, which supplies Wasm buffer address conversion/bounds handling. V0ID additionally validates the complete native input and output pointer+length ranges before copying bytes or invoking a provider. Input is copied into host-owned memory before provider execution, so guest input/output aliasing cannot hand an unchecked Wasm pointer to native crypto code.

A byte call traps if the primitive is undeclared, the ABI type is wrong, input/output limits are exceeded, the output buffer is too small, the provider/cost budget is exhausted, a Wasm pointer range is invalid, or the provider rejects the input.

## Primitive manifests and registry

Each `WasmMathProgram` declares required primitives by:

```text
numeric tag
canonical textual id
version
```

Each local `PrimitiveDescriptor` additionally declares:

```text
abstract cost
experimental flag
ABI kind: u64 | bytes
maximum input bytes
maximum output bytes
```

The registry rejects duplicate tag/version registrations and checks canonical ids. A byte provider cannot be invoked through `primitive_u64`, and vice versa.

## Built-in providers

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

0x7fff0001  v0id.experimental.toy-lwe-affine-u64/v1
            ABI: u64
            EXPERIMENTAL / NO SECURITY CLAIM
```

The toy affine provider still computes only `b = a*s + e mod q`; it is interface plumbing, **not LWE encryption and not a post-quantum primitive**.

### SHA3-256

Input is an arbitrary bounded byte string and output is exactly 32 bytes. The test suite checks the SHA3-256 digest of `"abc"` and exercises the provider through the actual WAMR byte import.

### Optional ML-KEM-768

V0ID does not implement ML-KEM arithmetic. When the linked OpenSSL provider exposes `ML-KEM-768`, the default registry installs an encapsulation-only provider.

Input:

```text
raw ML-KEM-768 public key bytes
```

Output:

```text
u32be ciphertext_length
u32be shared_secret_length
ciphertext[ciphertext_length]
shared_secret[shared_secret_length]
```

There is deliberately no remote MathVM decapsulation provider in this scaffold. When ML-KEM is available, the test suite generates a keypair, encapsulates through the V0ID provider, decapsulates with OpenSSL and requires the secrets to match.

## Resource bounds

Default `SandboxLimits`:

```text
Wasm module bytes         1 MiB
linear memory             16 pages = 1 MiB
Wasm stack                64 KiB
host-managed app heap     disabled
WAMR runtime pool         16 MiB
Wasm instructions         1,000,000
provider calls            4,096
provider cost             1,000,000 abstract units
provider input buffer     256 KiB
provider output buffer    256 KiB
```

The host-managed WAMR app heap is disabled. WAMR inserts that heap into the module's linear-memory allocation; with it enabled, the actually addressable memory can exceed the module-declared page boundary. Keeping it at zero makes the V0ID `max_memory_pages` policy a meaningful hard ceiling for this profile.

Provider byte limits may not exceed the entire linear-memory sandbox cap. Individual providers can impose smaller limits. Native provider work has a separate call/cost budget because it is not represented by Wasm instruction count.

## Runtime-verified V0.4.4 gate

The development host has run the completed ABI-v2 suite:

```text
V0ID MathVM sandbox/provider tests: 16 passed, 0 failed
V0ID MathVM byte-boundary tests:    4 passed, 0 failed
```

The passing boundary gate includes:

```text
valid scalar/byte execution
SHA3-256 known-answer test
ML-KEM-768 encapsulate/decapsulate round trip
undersized output rejection
scalar/byte ABI mismatch rejection
undeclared primitive rejection
provider call budget
instruction budget
module/memory policy rejection
WASI rejection
OOB input pointer+length rejection
OOB output pointer+length rejection
recovery after trapped/rejected jobs
```

The external compiled SHA3 guest also ran successfully:

```text
V0ID MathVM ABI      : v2
module bytes         : 671
result               : 32
provider calls       : 1
provider cost        : 256
```

A UBSan-aware WAMR build also completed the 16-test suite. The separate ASan build is currently blocked by a WAMR 2.4.0 `native stack overflow` trap before the test body; V0ID therefore does **not** claim an ASan-clean run.

## Test commands

```sh
cmake -S . -B build
cmake --build build -j \
  --target v0id-mathvm-tests v0id-mathvm-byte-boundary-tests v0id-mathvm

./build/v0id-mathvm-tests
./build/v0id-mathvm-byte-boundary-tests
```

External scalar guest:

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

External SHA3 byte guest:

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

## What may be transmitted later

A future visible remote MathVM object can contain the ABI version, Wasm bytes, entrypoint, primitive manifest and public resource profile. Authenticated negotiation must eventually bind the agreed VM ABI/provider set/resource profile to prevent substitution or downgrade.

That object is not needed for the encrypted-machine protocol. The encrypted-machine path already carries its program semantics as encrypted transition/state data.

## Primitive-layer status

The generic provider architecture is now intentionally considered complete enough for current research: scalar calls, bounded bytes, explicit provider type, manifests, resource budgets, one always-available standardized byte provider and one optional standardized PQ provider.

Further provider formats should be added only when a real workload needs them. Candidate byte encodings include big integers, mod-q vectors/matrices, polynomials/NTT operands and standardized signature operations whose trust boundary makes sense.

## Non-claims

MathVM still does not provide audited sandbox security, authenticated remote capability negotiation, signatures over Wasm/manifests, canonical Wasm normalization, privacy for a remotely transmitted MathVM program, or a new post-quantum hardness assumption.

ML-KEM security comes from the standardized ML-KEM implementation supplied by OpenSSL; V0ID's contribution here is the bounded provider/orchestration boundary, not a new KEM.
