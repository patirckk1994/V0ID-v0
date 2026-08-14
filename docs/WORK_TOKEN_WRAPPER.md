# V0ID hybrid work-token wrapper

This is intentionally a **wrapper around verified work**, not a blockchain or
consensus implementation.

A single accepted `WorkEvent` may contain:

```text
mining_work        > 0 or 0
compute_complexity > 0 or 0
```

so the eventual system can represent pure mining, pure useful computation, or a
hybrid block/job without forcing mining and compute into one premature exchange
rate.

## Payout tree

For a genuinely hybrid event the wrapper exposes six possible payout primitives:

```text
                         one WorkEvent
                      /                \
                  MINING              COMPUTE
                /   |   \            /   |   \
              MI    MV   MC         CI    CV   CC
              |     |    |          |     |    |
       independent invariant combo independent invariant combo
```

Symbols currently returned by the wrapper are:

```text
V0ID-MI   mining independent
V0ID-MV   mining invariant
V0ID-MC   mining combo
V0ID-CI   compute independent
V0ID-CV   compute invariant
V0ID-CC   compute combo
```

These are **candidate payout primitives/classes**, not six automatically minted
units. Every leaf derived from one event carries the same `work_event_id`.
Future consensus may choose parallel rewards, one-of-N redemption, weighted
payout, conversion, or another policy without changing the cryptographic event
identity.

## Meaning of the three flavors

`independent` preserves the exact identity relevant to its axis:

- mining: exact PoW algorithm/profile binding;
- compute: exact module/default-stack/user-Turing-machine execution binding.

`invariant` deliberately ignores the exact implementation identity and groups
work only by its declared mining or compute work class.

`combo` exists only when both `mining_work` and `compute_complexity` are nonzero.
It binds both mining and compute classes and both exact identities. The wrapper
keeps the two quantities separate rather than inventing a conversion formula.
`V0ID-MC` and `V0ID-CC` are distinct classes so a future market/consensus policy
can emphasize the mining or compute side of the same hybrid event if desired.

## Execution identity

`WorkEvent::execution_binding` is deliberately generic:

- synchronized Wasm/module stacks can use `shared_module_set_digest512()`;
- a built-in/default V0ID stack can use a canonical SHA3-512 profile identity;
- a user Turing machine/algorithm can use a canonical SHA3-512 commitment to its
  executable/profile;
- hidden/public contract visibility remains an orthogonal event field.

The coin wrapper does not need to know how the execution was implemented. It only
needs the exact already-agreed identity.

## What remains outside this layer

This code does not define:

- proof-of-work validity or difficulty adjustment;
- how compute complexity is calibrated;
- the exchange rate, if any, between mining work and useful computation;
- execution-proof soundness;
- fees, issuance, supply, UTXO/account state, or consensus;
- whether all six payout branches are rewarded or merely alternative views.

Those decisions should be made only after V0ID has a cheap, sound way to verify
expensive remote computation. The wrapper exists now so later blockchain work can
consume stable identities without contaminating the cryptographic core.
