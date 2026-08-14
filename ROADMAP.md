# V0ID Roadmap

> Status: research prototype. Every layer must earn its existence.
>
> This roadmap separates **runtime-verified properties**, **bounded falsification results**, **open research questions**, and **future wrappers**. Nothing here should be read as a universal security proof.

## 0. Design rules

1. **Series / pattern first, algorithm later.** Purpose-specific pseudorandom series are derived before downstream algorithm identifiers are selected and bound.
2. **Use standardized primitives where they already solve the problem.** OpenSSL supplies SHA3/KMAC/RNG/ML-KEM; OpenFHE supplies BinFHE; WAMR supplies the Wasm sandbox; ZeroMQ supplies current transport framing.
3. **Private and shared state stay distinct.** An evaluator-visible or post-KEM shared root must never become the sole source of issuer-private polymorphism.
4. **Composition claims are narrower than primitive claims.** A good hash, KEM, FHE scheme, or sandbox can still be composed badly.
5. **Timeout / solver UNKNOWN is INCONCLUSIVE, never PASS.**
6. **Commitment is not execution proof.** QuineHash512 commits to the intended job image; it does not prove the evaluator performed every requested round.
7. **The coin remains a wrapper until work is cheaply verifiable.**

## 1. Runtime-verified checkpoint

### Series-first key scheduling

- `v0id-series-first-kex-tests`: **13/13 PASS**
- transcript encoding deterministic
- KEM algorithm, FHE profile, role, session and ciphertext substitutions are bound
- post-KEM shared series root is transcript-bound
- issuer-private polymorphism root is separated from shared KEM material
- downstream labels are domain-separated

### PQR / quine composition

- `v0id-quine-audit-tests`: **14/14 PASS**
- OpenSSL SHA3-512 known-answer test
- semantic job, generator implementation, session/job/epoch, challenge and morphed executable substitutions change the commitment
- exhaustive reduced 10-bit series images were unique in the tested screen
- no exact XOR period found in that reduced family
- reduced avalanche sanity screen showed no gross bias

This is composition evidence, not proof against arbitrary or future attacks.

### Exact symbolic series audit

- `v0id-symbolic-series-audit`: **16/16 PASS**
- exhaustive 8-bit reduced-root family
- affine GF(2) recovery: exact UNSAT for the defined shared attacker class
- degree <= 2 ANF recovery: exact UNSAT for the defined shared attacker class
- one generic oracle-free expression must work across the entire reduced domain

### Bounded bit-vector attacker

- `v0id-bitvector-series-audit`: **currently INCONCLUSIVE at the default 3-step, 4-input, 5-second search**
- Z3 timed out correctly and did not report PASS
- next engineering work: symmetry breaking, per-root-bit decomposition and better CEGIS search before increasing the attacker depth

### Whole-stack series-first schedule

- `v0id-series-first-stack-tests`: **21/21 PASS**
- whole-stack context binding
- purpose series are derived before concrete algorithm identifiers
- session/job/epoch/semantic/generator/KEX/channel/module-set substitutions are bound
- private/shared purpose domains remain separate

### Real ML-KEM composition

- `v0id-series-first-mlkem-tests`: **6/6 PASS**
- real OpenSSL ML-KEM-768 encapsulation/decapsulation
- both peers derive the same post-KEM shared series root
- both peers derive the same application-auth purpose series
- algorithm-later application material agrees
- FHE-profile downgrade and wrong-secret substitutions alter derived material

ML-KEM supplies the public-key hardness. The V0ID schedule is an application KDF layer, not a replacement KEM, peer-authentication protocol, or TLS implementation.

### Portable module synchronization

- `v0id-module-sync-tests`: **12/12 PASS**
- SHA3-512 content identity
- canonical order-independent shared-module-set commitment
- V0IDNET1 `MODULE_BLOB` framing
- content tampering rejected
- duplicate module identities rejected
- private-local modules cannot be serialized or enter the shared-module set

Receiving a module never implies executing it; WAMR/MathVM validation remains a separate gate.

### Hybrid work-token wrapper

- `v0id-work-token-tests`: **19/19 PASS**
- one `WorkEvent` may carry mining work, useful-compute complexity, or both
- hybrid events expose the 2 x 3 payout classification tree
- independent, invariant and combo denominations remain distinct
- all branches retain one common underlying work-event identity
- zero-work and fake-hybrid payout attempts fail closed

The wrapper defines classification only. It does not define issuance, exchange rates, consensus, difficulty or monetary policy.

---

## 2. Immediate next phase: attack the system rather than add wrappers

### 2.1 Finish the bounded bit-vector attacker

Goal: search for a **single generic straight-line breaker** that recovers reduced secret/root information from visible series output.

Current DSL:

- XOR / AND / ADD / NOT
- SHL / SHR / ROTL / ROTR
- shared immediates
- shared program across every reduced-root instance
- no per-challenge oracle table

Next improvements:

- canonical operand ordering for commutative operations
- remove unused operands/immediates from the search
- split secret-bit targets into independent solver jobs
- reject redundant/dead instructions
- CEGIS: synthesize on a subset, replay concretely over all reduced roots, add counterexamples and continue
- only SAT with successful concrete replay is a breaker
- only exact UNSAT for a stated bound closes that bound
- UNKNOWN remains INCONCLUSIVE

Later escalation, only if each level earns the cost:

1. bounded bit-vector SLP
2. selects / conditionals
3. bounded registers
4. bounded loops
5. bounded symbolic machine / TM synthesis

## 3. Polymorphism distinguisher benchmark

Question:

> Does V0ID polymorphism measurably hide structural origin, or does it only make the machine look different to humans?

Build a dataset of many independently morphed instances from several base programs and expose only evaluator-visible metadata.

Candidate labels to attack:

- source/base program family
- semantic job family
- real vs dummy state roles
- whether two jobs share the same origin
- transition-role classes
- public job/profile family

Candidate observable features:

- public state/tape/round dimensions
- graph/topology features that remain visible
- ciphertext counts and serialized sizes
- message/job sizes
- public timing/round structure
- module/profile identifiers intentionally exposed to the evaluator

Success criterion is not “classifier failed once.” Report train/test protocol, held-out jobs, confidence intervals, baselines and feature ablations.

If classification remains high, polymorphism must be changed or narrowed. If classification approaches baseline under a strong held-out test, polymorphism has empirical evidence for its existence.

## 4. Machine-cheating phase: malicious evaluator harness

This is the next major architectural attack surface.

The harness should deliberately implement dishonest evaluator variants against the same client/job interface:

- **skip-round evaluator**: executes fewer than the public round budget
- **early-return evaluator**: returns an otherwise well-formed result immediately
- **replay evaluator**: returns a result from an earlier accepted job
- **splice evaluator**: combines pieces from multiple jobs/sessions
- **substitution evaluator**: swaps session/job/profile/result material
- **partial-work evaluator**: computes integrity/fingerprint plumbing while omitting useful machine work
- **stale-session evaluator**: reuses an old evaluator cache/session where it should not be valid

The purpose is defensive: make cheating reproducible before designing a proof.

For every cheating mode record:

- whether current client-side checks detect it
- which commitment/binding detects it
- which attack still passes
- cost to attacker
- cost to verifier
- exact assumptions required

Expected result today:

- many substitution/replay mistakes should be caught by existing bindings
- **skipping actual encrypted rounds remains an OPEN soundness problem**

## 5. Execution-bound integrity

Goal:

> Bind an accepted result to the actual requested execution, not merely to the intended job image.

Candidate research directions should be implemented as experiments, not security claims:

- round-chained commitments / accumulators
- challenge-dependent checkpoint state
- randomized audit positions where compatible with the threat model
- result receipts bound to job/session/round count
- proof-carrying execution
- established verifiable-computation / succinct-proof systems if they can support the required encrypted computation economically

Any candidate must answer:

1. Can a malicious evaluator skip work and still produce a valid receipt?
2. Can a previous receipt be replayed?
3. Can receipts be spliced across sessions/jobs?
4. Can verification be substantially cheaper than repeating the FHE computation?
5. Does the proof leak hidden program semantics or private polymorphism state?

Until these questions have satisfactory answers, useful compute is not eligible for a consensus-grade monetary claim.

## 6. Transport and peer authentication

Current V0ID transport is V0IDNET1 framing over ZeroMQ. It is not TLS.

Do **not** invent a custom replacement for TLS merely because V0ID has its own series-first KDF.

Future deployment may add a standardized authenticated secure channel such as TLS. If an outer channel exists, bind an exporter/channel-binding value into `SeriesFirstStackContext::outer_channel_binding`.

Peer authentication and transport confidentiality remain separate from application ML-KEM composition, issuer-private polymorphism, FHE secrecy, quine commitments and execution proofs.

## 7. Whole-stack strategy modules

After the interfaces above stabilize, expose an optional portable strategy module for the semantic/security stack.

Potential responsibilities:

- choose among allowed machine-layout policies
- choose among allowed polymorphism policies
- choose quine/audit policy
- choose allowed integrity policy
- choose downstream algorithm/profile **after** purpose-series derivation

Non-negotiable invariant:

> A plugin may select among trusted/allowed policies, but it may not bypass canonical encoding, context binding, sandbox limits, profile validation or execution-proof requirements.

Visibility modes:

- `private_local`: issuer-only; cannot be synchronized
- `shared_sync`: content-addressed, transmitted intentionally, exact module-set identity bound into the stack context

## 8. Coin / blockchain wrapper — freeze until verification catches up

The current coin layer is intentionally only a typed wrapper around accepted work.

A `WorkEvent` can carry mining work, compute complexity, mining algorithm/profile binding, exact compute execution binding, public/hidden contract classification, evidence binding and series-first stack binding.

Hybrid payout classification:

```text
                    WorkEvent
                 /             \
             MINING           COMPUTE
            /  |  \          /  |  \
          MI   MV   MC      CI   CV   CC
```

Interpretation:

- **Independent**: preserves exact algorithm/module/TM identity
- **Invariant**: common denomination independent of exact implementation
- **Combo**: binds both mining and compute dimensions/identities

The three branches are not automatically three units of minted value. Future consensus may choose parallel rewards, one-of-N redemption, weighting or other issuance policy.

Do not build consensus economics until useful-compute proofs become cheap enough to verify.

## 9. Eventual consensus research

Only after execution verification exists:

- define canonical block/work certificate format
- define mining challenge and difficulty
- define useful-compute acceptance proof
- bind compute work to current block challenge to prevent stockpiling/replay
- define normalization units without embedding arbitrary economic exchange rates in the cryptographic wrapper
- define issuance policy over MI/MV/MC/CI/CV/CC
- define double-spend / replay rules around `WorkEventId`
- define public vs hidden smart-contract semantics
- evaluate verifier cost and denial-of-service surface

## 10. Long-term release gates

Before calling V0ID anything stronger than a research prototype:

- repeat sanitizer/UB checks on the latest complete tree
- deterministic serialization tests for all public wire formats
- cross-platform build gates
- fuzz network codecs and module codecs
- negative tests for every fail-closed path
- external cryptographic review
- independent FHE / protocol review
- reproducible benchmark corpus
- explicit threat model and security games
- separate proven, tested, empirical and uncertain claims in documentation

## 11. Things explicitly still UNCERTAIN

- arbitrary/full-width structural recovery attacks
- future quantum algorithms against the composed construction
- whether polymorphism defeats strong real-world distinguishers
- malicious evaluator execution soundness
- cheap proof of useful encrypted computation
- production peer authentication / secure transport
- economically sound work normalization
- consensus and token issuance policy

These are not documentation defects. They are the research frontier.
