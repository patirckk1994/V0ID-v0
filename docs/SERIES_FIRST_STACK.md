# V0ID series-first / algorithm-later stack

This layer deliberately separates **purpose selection** from **algorithm
selection**.

```text
issuer-private root                         standardized PQ KEM
        |                                        |
        |                                  shared secret
        |                                        |
        |                           canonical KEX transcript
        |                                        |
        |                                  KMACXOF256
        |                                        |
        |                                 SharedSeriesRoot
        |                                        |
        +------------------+---------------------+
                           |
                    stack context hash
                           |
               purpose-specific series first
                           |
         +---------+-------+-------+---------+
         |         |               |         |
      layout   polymorphism   quine/audit  app auth ...
         |         |               |         |
         +---------+-------+-------+---------+
                           |
                  algorithm selected later
                           |
                    version/context bound
```

## What this layer is

- a domain-separated KMACXOF256 application/session schedule;
- a way to derive independent material for TM layout, polymorphism, quine
  challenge, future execution integrity, strategy plugins, application auth and
  job receipts;
- a post-KEM composition layer when two peers share standardized ML-KEM material;
- a place to bind the exact semantic job, generator implementation, session,
  epoch, compute profile and optional outer-channel identity.

## What this layer is not

It is **not TLS** and does not derive TLS traffic keys.

The current V0ID transport is ZeroMQ framing and is not itself TLS-wrapped. If a
future deployment adds TLS, Noise or another authenticated secure channel, that
channel keeps its own standardized key schedule. A channel exporter/binding may
optionally be included in `SeriesFirstStackContext::outer_channel_binding` so the
V0ID application session is cryptographically attached to the outer channel.

Likewise, ML-KEM remains the key-establishment hardness assumption. The
series-first schedule consumes the KEM shared secret; it does not claim that a
KMAC series generator is itself a public-key KEM.

## Private vs shared roots

The evaluator may know a post-KEM `SharedSeriesRoot`, so it must never be the sole
root of issuer-private polymorphism.

The issuer keeps a separate `RAND_priv_bytes()` root. Private purpose series are
derived from that root and the same stack context. Shared application purposes
may instead derive from the post-KEM shared root.

```text
issuer private root -> private morph/layout/quine strategy
post-KEM shared root -> shared application auth/receipt/etc.
```

The two schedules use distinct KMAC domains.

## Series first, algorithm later

Stage 1 names only a purpose such as `polymorphism` or `application_auth` and
returns a 256-bit purpose series key. It does not name the eventual algorithm.

Stage 2 binds a concrete algorithm id/version plus algorithm-specific public
context and expands the already-derived purpose series into the required bytes.
This prevents accidental stream reuse while keeping algorithm choice downstream
from the series/pattern layer.

A later whole-stack strategy Wasm plugin may select among allowed algorithms, but
trusted C++ must retain invariant checks and allowed-profile policy.

## Portable module synchronization

V0ID uses existing components rather than inventing a second executable format:

- Wasm is the portable module format;
- WAMR is the sandbox/runtime;
- ZeroMQ/V0IDNET1 carries module bytes;
- OpenSSL SHA3-512 gives modules a content address.

The module-sync codec defines:

```text
ModuleDescriptor
    protocol id
    module kind
    visibility
    module id/version
    byte length
    SHA3-512(content)
```

and V0IDNET1 reserves `MODULE_OFFER`, `MODULE_REQUEST`, `MODULE_BLOB` and
`MODULE_READY` message types.

Receiving a module does **not** execute it. Its digest/size/visibility are checked
first, then the appropriate WAMR/MathVM sandbox still has to validate imports,
memory, instruction budget and ABI before execution.

### Visibility rule

`private_local` modules fail closed if code tries to serialize them for network
synchronization. This is the default appropriate policy for the issuer's private
polymorphism strategy.

`shared_sync` modules may be transported and synchronized by exact SHA3-512
identity. This is suitable for public MathVM programs and future shared strategy
modules where both peers are intentionally supposed to possess the same code.

If a user explicitly chooses to publish a polymorphism module it can be described
as `shared_sync`, but doing so changes the concealment model and should never
happen implicitly.

## Current runtime gates

- `v0id-series-first-kex-tests`: transcript and post-KEM schedule composition.
- `v0id-series-first-stack-tests`: purpose-first then algorithm-later whole-stack
  separation and fail-closed context binding.
- `v0id-series-first-mlkem-tests`: real OpenSSL ML-KEM-768 encapsulation /
  decapsulation feeding the series-first schedule; reports `SKIP` when the local
  OpenSSL provider lacks ML-KEM rather than simulating a pass.
- `v0id-module-sync-tests`: content-addressed shared-module encoding, V0IDNET1
  `MODULE_BLOB` framing, tamper rejection and private-module non-export.

These tests do not solve peer authentication, TLS, or malicious-evaluator
execution soundness. Those remain separate layers and must not be inferred from
successful key scheduling or module synchronization.
