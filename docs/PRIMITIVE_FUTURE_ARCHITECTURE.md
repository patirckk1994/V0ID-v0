# V0ID Primitive Future Architecture

> Forward-looking research architecture. Nothing in this file should be read as already implemented or proven unless separately stated in the current architecture/tests.

## Goal

Evolve V0ID from a composition-heavy research prototype into a system where hidden computation is not only confidential and strongly bound, but also **cheaply verifiable against a malicious evaluator**.

The future architecture should preserve the existing rule:

> derive purpose-specific series/patterns first; choose/bind concrete algorithms later.

## 1. Adversarial development order

The next stages should attack the current machine before adding more abstraction.

```text
series structural attacks
        |
polymorphism distinguisher
        |
malicious evaluator harness
        |
execution-bound integrity candidates
        |
cheap verification / proof
        |
only then broader consensus/economic use
```

### 1.1 Stronger series attacker DSL

Extend the bounded oracle-free attacker hierarchy only when each step earns its complexity:

1. XOR/period screens
2. affine GF(2)
3. low-degree ANF
4. bounded bit-vector straight-line programs
5. conditionals/selects
6. bounded register programs
7. bounded loops
8. bounded symbolic machine/TM synthesis

Requirements remain:

- one generic attacker shared across instances,
- no challenge-specific lookup table,
- SAT candidates replayed concretely,
- exact UNSAT closes only the stated bounded class,
- timeout/unknown remains INCONCLUSIVE.

## 2. Polymorphism distinguisher benchmark

Build an empirical benchmark that asks whether evaluator-visible structure leaks the origin or semantic family of a morphed job.

Generate large corpora of independent morphs from multiple base programs and train held-out classifiers using only legitimately visible features.

Possible attack labels:

- source/base program family,
- semantic job family,
- real vs dummy state roles,
- transition-role class,
- whether two jobs share the same origin.

Possible visible features:

- public shape,
- serialized job dimensions,
- ciphertext counts/sizes,
- graph/topology information that remains public,
- message sizes,
- public round/timing structure,
- intentionally visible profile/module identifiers.

Polymorphism should not be retained merely because the transformed program looks different to humans. It should earn its existence through measured reduction in classification/linkability.

## 3. Malicious evaluator harness

Implement evaluator variants that deliberately violate the intended execution while preserving as much protocol correctness as possible.

Required cheating modes:

- skip requested rounds,
- early return,
- replay an earlier result,
- splice state/results from different jobs,
- substitute session/job/profile material,
- compute integrity plumbing while omitting useful work,
- stale evaluator-session reuse,
- partial execution with a syntactically valid result.

For each attack record:

- whether current checks detect it,
- exactly which binding/check detects it,
- attacker cost,
- verifier cost,
- remaining undetected cases.

This harness becomes the regression target for every future execution-proof design.

## 4. Execution-bound integrity

The core future problem is to turn:

```text
"this is the exact job I intended"
```

into:

```text
"this result is cryptographically bound to the requested execution"
```

Candidate experiments may include:

- round-chained commitments,
- challenge-dependent checkpoints,
- transcript accumulators,
- randomized audit positions,
- proof-carrying execution,
- established succinct/verifiable-computation systems where compatible with FHE and confidentiality.

Any candidate must answer:

1. Can the evaluator skip expensive rounds and still pass?
2. Can old proofs be replayed?
3. Can proofs be spliced across jobs/sessions?
4. Is verification materially cheaper than recomputation?
5. Does the proof leak hidden semantics/private polymorphism state?

A custom accumulator that cannot answer those questions is not yet an execution proof.

## 5. Cheap verification layer

A successful future endpoint would resemble:

```text
semantic job / hidden TM
        |
series-first stack + algorithm-later policy
        |
polymorphism + quine binding
        |
FHE execution
        |
execution proof / receipt
        |
cheap deterministic verifier
```

The verifier should consume a compact public statement containing only the fields that are deliberately public/bound, while keeping the hidden program/state private according to the chosen threat model.

## 6. Whole-stack strategy modules

Once the interfaces stabilize, add an optional strategy module controlling allowed policy choices across the semantic/security stack.

Possible responsibilities:

- choose among allowed machine-layout policies,
- choose among allowed polymorphism policies,
- select quine/audit policy,
- select execution-integrity policy,
- select downstream algorithm/profile after purpose-series derivation.

Hard boundary:

> strategy modules choose among trusted policies; they do not bypass canonical encoding, sandbox limits, profile validation, semantic binding, or proof requirements.

Visibility remains explicit:

- `private_local` for issuer-only strategy,
- `shared_sync` for intentionally synchronized public/shared strategy.

## 7. Transport and authentication

Future deployments may add TLS, Noise or another standardized authenticated secure channel.

V0ID should not reimplement such a transport protocol merely because it has a KMAC/series-first schedule.

Instead:

```text
standardized outer channel
        |
channel exporter / binding
        |
SeriesFirstStackContext.outer_channel_binding
```

Peer authentication remains a distinct protocol question from:

- ML-KEM shared-secret establishment,
- FHE secrecy,
- private polymorphism,
- quine commitment,
- execution-proof soundness.

## 8. Module lifecycle and synchronization

Future shared modules may become first-class, content-addressed protocol objects.

Potential lifecycle:

```text
author module
    -> sandbox/ABI validation
    -> SHA3-512 identity
    -> optional policy approval
    -> synchronized by exact content identity
    -> module-set digest bound into session/job
    -> execute only inside assigned sandbox
```

Do not merge content identity with trust. A valid SHA3-512 digest proves which bytes were received, not whether those bytes are a safe/approved strategy.

## 9. Multiple hidden-execution backends

The encrypted TM remains the universal/reference backend, but future implementations may add alternative bounded hidden-compute backends when they earn their existence.

Any backend must preserve a common statement layer for:

- semantic job identity,
- execution/profile identity,
- series-first context,
- module identity where relevant,
- proof/receipt identity.

This allows future proofs and work wrappers to refer to a canonical statement rather than a specific implementation.

## 10. Production hardening gates

Before stronger public claims:

- latest-tree sanitizer/UB passes,
- fuzz all public codecs,
- deterministic serialization across platforms,
- resource-exhaustion tests,
- fail-closed negative tests,
- independent cryptographic review,
- independent FHE/protocol review,
- reproducible adversarial benchmark corpus,
- explicit threat models/security games,
- versioned migration/deprecation policy.

## 11. Explicit research frontier

Still UNCERTAIN until evidence/proofs exist:

- arbitrary/full-width structural attacks,
- future quantum algorithms,
- whether polymorphism materially reduces evaluator classification/linkability,
- malicious-evaluator execution soundness,
- cheap verification of useful encrypted computation,
- production peer authentication/network security.

The point of the future architecture is to make those unknowns testable, not to rename them as solved.
