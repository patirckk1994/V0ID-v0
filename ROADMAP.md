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
6. **Commitment is not execution proof.** QuineHash512 commits to the intended job image; it does not by itself prove the evaluator performed the requested encrypted execution.
7. **Ledger engineering and compute minting are separate gates.** Canonical transactions, blocks and deterministic state transitions may be built before useful-compute verification is solved. Protocol issuance for useful compute remains disabled until its evidence earns consensus trust.

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

The legacy harness deliberately implements dishonest evaluator variants against the same client/job interface:

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

### Concrete fixed-point failure already reproduced

With one stable morphed transition table, the increment benchmark reaches the same accepted tape after 2 rounds as after 4. The legacy encrypted fingerprint authenticates the encrypted job image but is independent of how many machine rounds actually execute, so a 2/4 early return can preserve both the semantic tape and the fingerprint.

Round receipts were added as one narrow external audit and correctly document their own boundary. They are not the final execution architecture.

### Round-polymorphic repair experiment — implemented, NOT runtime-verified yet

`ProgramMorpher::morph_round_schedule()` now derives a different secret state-label encoding for every round boundary. Round `r`'s transition table consumes boundary-`r` labels and emits boundary-`r+1` labels. The first construction requires `public_state_count >= rounds + 1` and uses a KMAC-seeded secret permutation plus full-cycle stride so each logical state has a distinct public label at every requested boundary.

New targets:

- `v0id-round-morph-schedule-tests` — fast plaintext semantics / boundary-encoding gate
- `v0id-round-morph-fhe-harness` — real BinFHE experiment over the complete encrypted round schedule

`RemoteEncryptedMachine` can now consume either one encrypted transition table or exactly one encrypted table per requested round. The toy FHE self-fingerprint can bind the ordered concatenation of every table in the schedule.

The specific claim being tested is narrow:

```text
2/4 evaluator:
    semantic tape may already equal the 4/4 tape
    hidden machine state remains encoded for boundary 2

4/4 evaluator:
    semantic tape is correct
    hidden machine state is encoded for boundary 4
```

A plain skip-and-stop evaluator should therefore fail the final hidden-state check even at a semantic fixed point.

Do **not** promote this to a general proof of work. A faster equivalent transform of the encrypted hidden representation, a structural distinguisher, or another shortcut remains **UNCERTAIN** until attacked directly.

## 5. Execution-bound integrity

Goal:

> Bind an accepted result to the requested hidden computation strongly enough that useful-compute settlement does not rely on a separable public sidecar.

The current direction is now deliberately closer to the intended V0ID construction:

```text
client semantic machine
        + private series/challenge
        + round-dependent polymorphic representation
        + integrity binding over the complete hidden schedule
                    |
                    v
             encrypted schedule
                    |
                    v
        generic fixed-path BinFHE evaluator
                    |
                    v
       semantic result + hidden final state
                    |
                    v
               client checks
```

The schedule-wide toy fingerprint remains only plumbing; it is not a cryptographic replacement for SHA3/KMAC and it is still visibly implemented as an evaluator circuit. The research target is to make integrity depend on the same hidden representation that useful execution must traverse, rather than asking an unrelated receipt to prove a static machine image did work.

Candidate escalation, only if the round-polymorphic construction fails or leaves an economically meaningful shortcut:

- execution-dependent encrypted accumulators coupled to hidden representation changes
- challenge-dependent checkpoint state
- randomized audit positions where compatible with the threat model
- proof-carrying execution
- established verifiable-computation / succinct-proof systems if they can support the required encrypted computation economically

Any candidate must answer:

1. Can a malicious evaluator obtain the client-accepted hidden final representation while skipping economically meaningful work?
2. Can a previous result/evidence object be replayed?
3. Can evidence be spliced across sessions/jobs?
4. Can verification be substantially cheaper than repeating the FHE computation?
5. Does the evidence leak hidden program semantics, round mappings or private polymorphism state?

Until these questions have satisfactory answers, useful compute is **not eligible for protocol-funded issuance**. User-funded compute settlement may be modeled separately because it transfers existing value rather than creating supply.

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

## 8. Coin / blockchain wrapper — ledger work may proceed; compute issuance stays frozen

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

The three branches are not automatically three units of minted value. Future consensus may choose parallel rewards, one-of-N redemption, weighting or another issuance policy.

### What is now explicitly UNFROZEN

A deterministic ledger skeleton does not depend on solved useful-compute verification and may proceed now:

1. canonical byte encoding and domain-separated hashes
2. transaction IDs and typed transaction envelopes
3. deterministic account/object state transition
4. block header / block body / root calculation
5. nonce and replay rejection
6. `WorkEventId` / proof / nullifier duplicate rejection
7. local multi-block simulator and save/reload tests
8. consensus adapter boundary with no production economic assumptions

This work should begin under `src/chain/` and must not silently import an EVM, staking system, networking stack or monetary policy merely because other chains have them.

### What remains FROZEN

- protocol-funded useful-compute issuance
- a permanent mining:compute exchange rate
- validator/verifier reward multiplication
- public consensus claims based on unverified compute evidence
- production smart-contract semantics

Verification is a validity/dispute function, not an independently Sybil-mintable work axis.

## 9. Blockchain / consensus research

The deterministic chain substrate may now be developed in parallel with execution-soundness research. Public consensus economics remains a later gate.

### First chain milestone — no sockets, no mining, no staking

Build `src/chain/` around deterministic state transition only:

- canonical hash / serialization primitives
- typed transaction families
- `TransactionId`, `BlockId`, `StateRoot`, `WorkEventId`
- account/object balances and nonces
- block header and body roots
- deterministic `apply(block, state) -> state'`
- replay / duplicate / malformed-transition rejection
- persistence and reload
- deterministic tests across repeated executions

No generic `Blockchain` god-class. Keep consensus, state, computation and economics as separate boundaries.

### Second milestone — local consensus adapter / devnet

After the deterministic state machine is stable, attach an established BFT-style ordering/finality boundary for a small research devnet. The application state transition must remain independently testable from consensus.

### Computation lane before minting

Model the lifecycle with reward = 0 first:

```text
job posted
    -> executor assignment / acceptance
    -> encrypted computation
    -> result + execution evidence
    -> accept / dispute / reject
    -> accounting record
```

User-funded job fees may later settle through escrow because they are transfers. Protocol inflation for compute remains disabled until execution evidence is cheap and strong enough.

### Eventual public-economic questions

Only after those earlier boundaries earn promotion:

- canonical block/work certificate format
- mining challenge and difficulty
- useful-compute acceptance evidence
- binding compute work to fresh chain challenges to prevent stockpiling/replay
- normalization units without embedding arbitrary physical equivalence between hashes and FHE work
- bounded epoch issuance policy over mining and compute allocations
- double-spend / replay rules around `WorkEventId`
- public vs hidden smart-contract semantics
- verifier cost and denial-of-service surface

One monetary invariant should survive every later policy experiment:

```text
protocol_issuance(epoch) <= epoch_emission_budget(epoch)
```

Unlimited mining attempts or compute submissions must not imply unlimited token issuance.

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
- general malicious-evaluator execution soundness beyond tested attacks
- whether round-polymorphic hidden-state encoding has an economically cheap shortcut
- cheap proof/evidence of useful encrypted computation
- production peer authentication / secure transport
- economically sound work normalization
- production consensus and token issuance policy

These are not documentation defects. They are the research frontier.
