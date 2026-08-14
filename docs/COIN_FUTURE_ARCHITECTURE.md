# V0ID Coin Future Architecture

> Forward-looking wrapper/consensus architecture. This file is intentionally speculative and separate from the current tested work-token wrapper.

## Goal

Build a future chain where value can be issued from:

- conventional proof-of-work mining,
- useful V0ID computation,
- or a hybrid event containing both,

while preserving both:

- implementation/module-specific value,
- implementation-invariant fungibility.

The chain remains a **wrapper around verified work**. It should not weaken or replace the underlying V0ID primitive.

## 1. High-level future flow

```text
                 block challenge / protocol state
                         |
           +-------------+-------------+
           |                           |
       PoW mining                 useful V0ID job
           |                           |
     mining evidence              hidden/public job
           |                           |
           |                    encrypted execution
           |                           |
           |                    execution proof
           |                           |
           +-------------+-------------+
                         |
                   accepted WorkEvent
                         |
                 payout classification
                         |
              future consensus/ledger
```

A future block may contain pure mining events, pure compute events, or hybrid events.

## 2. Consensus prerequisite: cheap verification

Useful-compute issuance should not become consensus-grade until the network can verify expensive computation substantially more cheaply than repeating it.

Required target:

```text
job + session + execution identity + requested work
                         |
                         v
                  execution proof
                         |
                         v
             cheap deterministic verify
```

The proof system must resist at least:

- skipped rounds,
- early return,
- stale-result replay,
- cross-job splicing,
- module/profile substitution,
- fake complexity claims,
- proof reuse across block challenges.

Without this layer, useful-compute rewards remain experimental accounting.

## 3. Hybrid block challenge

A useful-compute job should eventually be bound to live chain state so precomputed or replayed work cannot be freely stockpiled.

Possible statement shape:

```text
block challenge
+ job id
+ session id
+ semantic/execution binding
+ module-set binding
+ required round/work budget
+ current epoch/height
        |
        v
proof statement
```

The exact challenge construction remains open and should be designed together with the execution-proof system rather than bolted on afterward.

## 4. Module-specific and module-invariant value

The payout tree allows economic pressure to operate at two levels.

### Specific / independent value

A module-, algorithm-, default-stack- or user-TM-specific denomination can preserve exact execution identity.

This can support markets that prefer:

- a stronger audited module,
- a particular computation profile,
- a specific smart-contract implementation,
- a specific PoW profile,
- a particular hidden-compute backend.

### Invariant value

Invariant denominations abstract over exact implementation identity while retaining a consensus-defined work class.

This gives the chain a fungible path even as algorithms/modules evolve.

### Combo value

Hybrid combo denominations bind both mining and useful-compute identities/amounts without forcing the protocol to invent an arbitrary conversion rate between them.

## 5. Artificial-selection layer

Module-specific economics can create selection pressure over implementations:

```text
module/profile quality
        |
measurable security/performance/reliability
        |
user/market preference
        |
usage and fee demand
        |
economic selection pressure
```

However, the chain should not reward labels such as "high grade" by decree.

If implementation quality affects payout/fees later, candidate measurable inputs include:

- verifier cost,
- proof size,
- declared/audited security class,
- resource consumption,
- availability/reliability,
- failure history,
- demand,
- deprecation/upgrade status.

Consensus should select for observable engineering properties, not marketing names.

## 6. Future issuance policy over the 2 x 3 tree

The current wrapper exposes:

```text
                         WorkEvent
                      /             \
                  MINING           COMPUTE
                 /  |  \\          /  |  \
                MI  MV  MC        CI  CV  CC
```

Future consensus may choose among several issuance semantics:

- parallel reward classes,
- one-of-N redemption views,
- weighted issuance,
- deterministic splits,
- market-convertible claims,
- policy-selected subsets.

The architecture should preserve one invariant:

> all payout views derived from the same accepted event remain anchored to one `WorkEventId`, so reclassification cannot silently create new underlying work.

## 7. Mining and compute complexity remain separate dimensions

Do not bake a permanent equation such as:

```text
N hashes == M FHE gates
```

into the cryptographic wrapper.

Future consensus can maintain separate quantities:

- `mining_work`,
- `compute_complexity`,

and apply policy at the economic layer.

This keeps the protocol capable of changing calibration without changing canonical work-event identity semantics.

## 8. Public and hidden smart contracts

The chain should support both execution visibility models.

### Public contract

```text
shared/public module or machine
        |
evaluator knows semantics
        |
execution proof
        |
compute WorkEvent
```

### Hidden contract

```text
issuer-local private strategy / semantic job
        |
polymorphism
        |
encrypted TM/FHE execution
        |
privacy-preserving execution proof
        |
compute WorkEvent
```

Both may use the same work-token wrapper if the proof statement can certify the required execution without violating the chosen confidentiality model.

## 9. Default modules, synchronized modules and user algorithms

Future execution identity should support three broad sources without requiring separate coin systems.

### Default/built-in profiles

Versioned canonical identity for protocol-provided implementations.

### Shared synchronized modules

Content-addressed Wasm descriptors and canonical module-set digest.

### User algorithms / Turing machines

Canonical semantic/execution digest for a bounded user-defined machine/program.

The independent denomination binds the exact identity.

The invariant denomination can abstract over allowed implementations in the same work class.

The combo denomination preserves hybrid mining+compute identity.

## 10. Series-first / algorithm-later compatibility

Future chain policy should not force one permanent algorithm into the V0ID primitive.

A job may first derive a purpose series and later select an allowed algorithm/module/profile.

The resulting exact execution identity can then enter the work claim.

This permits cryptographic agility while preserving deterministic accounting:

```text
series/purpose first
       |
allowed algorithm chosen later
       |
exact execution binding
       |
independent / invariant / combo payout classification
```

## 11. Future block work certificate

A possible future block-level abstraction:

```text
BlockWorkCertificate {
    block_subject;
    accepted_work_events[];
    proof_commitments[];
    mining_summary;
    compute_summary;
    payout_policy_id;
    module_policy_root;
}
```

This is only a conceptual boundary, not a finalized serialization.

The certificate should allow validators to verify every accepted event without re-running the expensive useful computation.

## 12. Module policy and lifecycle

A future chain may need a policy layer distinguishing:

- content identity,
- sandbox validity,
- protocol compatibility,
- economic eligibility,
- deprecation/upgrade status.

Possible lifecycle:

```text
module bytes
  -> content digest
  -> sandbox validation
  -> optional audit/policy approval
  -> eligible work class
  -> job/session binding
  -> execution proof
  -> WorkEvent
```

Content hash alone never means "trusted".

## 13. Difficulty and normalization

Future mining and compute difficulty should be separately observable and adjustable.

Open research questions include:

- how to normalize heterogeneous useful-compute jobs,
- how to prevent users from selecting trivially cheap jobs with inflated declared complexity,
- how to price memory/communication/FHE bootstrapping costs,
- whether normalization should be deterministic from job/profile descriptors,
- how to resist specialized hardware gaming,
- how to update calibration without invalidating historical work.

The cryptographic wrapper should not guess these answers.

## 14. Consensus and network layers still to design

Future coin work eventually needs explicit designs for:

- canonical block format,
- fork choice,
- finality,
- peer discovery,
- mempool,
- transaction format,
- wallet/key format,
- state model,
- supply/issuance schedule,
- fee market,
- difficulty adjustment,
- work-proof validation,
- replay/double-spend rules,
- governance/upgrades,
- module eligibility/deprecation.

These should be added only after the proof boundary is credible.

## 15. Economic attacks to model

Before production claims, simulate or formally analyze:

- payout-tree double accounting,
- module-label gaming,
- fake complexity inflation,
- proof replay,
- module-specific liquidity fragmentation,
- invariant denomination dilution,
- mining/compute subsidy imbalance,
- denial-of-service through expensive verification,
- module cartel/whitelist capture,
- hidden-contract spam,
- stale/deprecated module exploitation.

## 16. Future coin success condition

The useful-compute coin wrapper earns its existence only when the chain can say something substantially stronger than:

```text
"the evaluator says it computed this"
```

The target is:

```text
accepted block challenge
+ exact work statement
+ exact execution/module identity
+ cheap sound proof
        |
        v
canonical WorkEvent
        |
2 x 3 payout classification
        |
consensus-defined issuance
```

Until then, the current tested wrapper should remain frozen and the research effort should stay focused on proving/attacking execution correctness.
