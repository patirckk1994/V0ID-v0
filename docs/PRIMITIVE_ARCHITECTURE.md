# V0ID Primitive Architecture

> Current implemented/research architecture. This document is intentionally narrower than `PRIMITIVE_FUTURE_ARCHITECTURE.md`.

## Design rule

V0ID follows a **series/pattern first, algorithm later** composition model. A purpose-specific pseudorandom series is derived before a concrete downstream algorithm identity is selected and bound.

The architecture deliberately separates:

- standardized primitive hardness,
- V0ID application key scheduling,
- issuer-private polymorphism,
- semantic-job commitments,
- encrypted execution,
- module synchronization,
- transport framing,
- and future execution proofs.

No one layer is allowed to silently inherit claims from another.

## Current data flow

```text
issuer-private root (RAND_priv_bytes)
          |
          +--------------------+
                               |
standardized ML-KEM-768        |
shared secret + transcript     |
          |                    |
          v                    v
 post-KEM SharedSeriesRoot   issuer-private root
          |                    |
          +---------+----------+
                    |
          SeriesFirstStackContext
                    |
          purpose-specific series
                    |
      algorithm selected/bound later
                    |
       +------------+-------------+
       |                          |
  private stack                shared stack
 layout/morph/quine       app-auth/receipt/etc.
       |                          |
       +------------+-------------+
                    |
             semantic job / TM
                    |
           trusted ProgramMorpher
                    |
            QuineHash512 binding
                    |
            OpenFHE BinFHE job
                    |
            V0IDNET1 / ZeroMQ
                    |
              remote evaluator
                    |
              encrypted result
```

## 1. Entropy and roots

### Issuer-private root

Private polymorphism and private audit material are rooted in a 256-bit issuer-private seed produced through OpenSSL `RAND_priv_bytes()`.

This root must remain unavailable to an evaluator, even when that evaluator is a peer in a shared KEM exchange.

### Post-KEM shared root

A standardized ML-KEM shared secret is combined with a canonical V0ID KEX transcript and expanded through KMACXOF256 into a `SharedSeriesRoot`.

The transcript binds at least:

- KEM id/version,
- machine protocol,
- FHE parameter set,
- session id,
- initiator/responder roles,
- KEM public material,
- KEM ciphertext.

The KEM remains the public-key hardness assumption. V0ID does not claim the series schedule is itself a KEM.

## 2. Whole-stack series-first schedule

`SeriesFirstStackContext` canonically binds the application/job context before purpose material is expanded.

Current bindings include:

- session id,
- job id,
- epoch,
- machine protocol,
- FHE parameter set,
- semantic binding,
- generator binding,
- optional KEX transcript binding,
- optional synchronized module-set binding,
- optional outer-channel binding.

The stack exposes purpose domains such as:

- machine layout,
- polymorphism,
- quine challenge,
- strategy plugin,
- execution integrity,
- application authentication,
- job receipt.

Stage 1 derives a purpose-specific series key without naming the final algorithm.

Stage 2 binds:

- algorithm id,
- algorithm version,
- algorithm-specific context,
- requested output length.

This is the concrete **series first, algorithm later** boundary.

## 3. Polymorphism

The issuer derives private series material and applies `ProgramMorpher` before encryption.

The trusted C++ morpher owns the semantic transformation. Local Wasm may derive private morph material, but it does not receive or rewrite the transition table directly.

Current local Wasm polymorphism modules are intended to remain issuer-local by default.

Private polymorphism material and private audit material are domain-separated.

## 4. Portable modules

V0ID uses Wasm as the portable executable module format and WAMR/MathVM as the sandbox/runtime rather than inventing another bytecode format.

Modules have content-addressed descriptors containing:

- protocol id,
- kind,
- visibility,
- module id/version,
- byte length,
- SHA3-512(content).

Two visibility modes are defined:

- `private_local`: cannot be serialized for synchronization,
- `shared_sync`: may be intentionally sent to peers.

A canonical order-independent shared-module-set digest can be bound into the V0ID stack context.

Receiving a module does **not** authorize execution. WAMR/MathVM still validates the executable module and its resource/ABI constraints.

## 5. Semantic job and quine commitment

Before encrypted execution, the client computes a plaintext SHA3-512/KMAC-based quine commitment over the intended job image.

The current quine context binds:

- public machine shape,
- FHE/crypto profile,
- evaluator session id,
- job id,
- epoch,
- initial state/head/tape,
- issuer semantic-job commitment,
- exact generator implementation commitment,
- issuer-private audit challenge,
- morphed executable image.

The digest slot is canonically zeroed during hashing rather than requiring a literal cryptographic fixed point.

Important limitation:

> QuineHash512 commits to **what the issuer intended to run**. It does not prove the remote evaluator actually executed every requested round.

## 6. Encrypted machine execution

The current remote-machine backend uses OpenFHE BinFHE with a fixed public machine shape.

The evaluator receives encrypted machine material and cached evaluator keys, not the LWE secret key.

The evaluator runs the public fixed-round schedule over encrypted state/program/tape material.

Current profile work has moved the relevant remote path to OpenFHE `STD128Q`.

The universal/TM-style machine is the hidden-program reference backend; local Wasm and MathVM are separate layers with different trust/visibility roles.

## 7. Current remote integrity plumbing

The repository still contains a legacy/toy 32-bit encrypted fingerprint path for execution plumbing.

It must not be confused with PQR integrity or a proof of correct execution.

A malicious evaluator may still be able to compute expected integrity plumbing while skipping useful encrypted rounds. This remains an explicit open soundness problem.

## 8. Transport

The current network transport is V0IDNET1 framing over ZeroMQ.

It is **not TLS**.

OpenSSL is currently used for cryptographic primitives such as RNG, SHA3, KMAC and ML-KEM, not as the socket transport wrapper.

If a future authenticated outer channel such as TLS is added, V0ID may bind a channel exporter/identity into `outer_channel_binding`; the outer channel keeps its own standardized key schedule.

## 9. Current adversarial gates

Implemented/runtime-tested gates currently include:

- series-first KEX composition tests,
- real ML-KEM-768 composition tests,
- whole-stack series-first/algorithm-later tests,
- quine/PQR composition tests,
- exact reduced affine GF(2) recovery audit,
- exact reduced degree<=2 ANF recovery audit,
- bounded Z3 bit-vector attacker harness,
- module synchronization tests.

The exact GF(2)/ANF UNSAT results apply only to the explicitly defined reduced attacker classes.

The bounded bit-vector audit treats solver timeout/`unknown` as **INCONCLUSIVE**, never PASS.

## 10. Explicit non-claims

The current primitive architecture does **not** establish:

- arbitrary-program or full-width symbolic resistance,
- universal post-quantum security,
- peer authentication,
- TLS-equivalent transport security,
- malicious-evaluator execution soundness,
- cheap proof of useful encrypted computation,
- blockchain consensus or monetary validity.

Those belong in future architecture/research layers and must earn their existence separately.
