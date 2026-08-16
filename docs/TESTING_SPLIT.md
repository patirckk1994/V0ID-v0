# V0ID validation split

V0ID uses two normal validation routes plus one explicit slow stress route.

## Route A: small real homomorphic execution

Target:

```text
v0id-test-small-fhe
```

This runs a deliberately tiny two-instruction Boolean program through the real
TFHE-rs CUDA client/evaluator/client seam:

```text
plaintext oracle
    |
trusted client: key generation + encrypted init + encrypted instruction chunk
    |
untrusted evaluator API: cached server key + encrypted state + CUDA execution
    |
encrypted result
    |
trusted client decrypt
    |
compare with plaintext oracle
```

The smoke program uses `XorInput` followed by `XorConst`. It is intentionally
small so changes to serialization, chunk ordering, evaluator session state,
CUDA execution or client decryption can be checked without running full SHA3
homomorphically.

This route validates the expensive cryptographic/execution path, not large-program
coverage.

## Route B: large fast client-side semantics

Target:

```text
v0id-test-large-client
```

This runs the existing full SHA3 program-image tests and round-polymorphism
schedule tests without FHE. It covers large program construction, SHA3/OpenSSL
equivalence, Boolean IR/program-image equivalence, seeded mutation, register
permutation, identity insertion, KMACXOF-backed/private series influence and
polymorphic semantic preservation at ordinary client-side speed.

This route validates large-program semantics and transformations, not the TFHE
implementation.

## Normal combined route

Target:

```text
v0id-test-milkshake
```

It runs Route B and then Route A. The intended regression argument is:

```text
large client-side semantic equivalence
                +
small real homomorphic equivalence
                +
shared BooleanProgramImage / polymorphism / backend boundaries
                =
fast practical implementation coverage
```

This is implementation/regression coverage. It is not a proof that a malicious
remote evaluator honestly executed every requested transition.

## Route C: large homomorphic stress

Target:

```text
v0id-test-large-fhe-stress
```

This retains the full mutated SHA3-512 image through streamed TFHE-rs CUDA. It is
an explicit milestone, profiling and integration stress route. It is not part of
the normal regression loop because thousands of high-level encrypted VM
instructions are deliberately expensive.

## Commands

Configure the GPU build once:

```bash
cmake --preset gpu-fhe
```

Normal combined validation:

```bash
cmake --build --preset gpu-fhe --target v0id-test-milkshake
```

Run each half independently:

```bash
cmake --build --preset gpu-fhe --target v0id-test-large-client
cmake --build --preset gpu-fhe --target v0id-test-small-fhe
```

Explicit full FHE stress only when wanted:

```bash
cmake --build --preset gpu-fhe --target v0id-test-large-fhe-stress
```

The two normal routes intentionally share production representations and backend
APIs rather than maintaining separate test-only cryptographic implementations.
