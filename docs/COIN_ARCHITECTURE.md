# V0ID Coin Architecture

> Current implemented **wrapper** around accepted work. This is not a finished blockchain, consensus protocol, or monetary policy.

## Position in the stack

The coin layer sits above the V0ID computation/security primitive:

```text
V0ID semantic job / user TM / module
                 |
        series-first schedule
                 |
          algorithm later
                 |
        polymorphism + quine
                 |
          encrypted execution
                 |
      accepted execution evidence
                 |
             WorkEvent
                 |
       payout classification
```

Mining enters through a parallel path:

```text
accepted PoW evidence --------+
                              |
accepted useful compute ------+--> WorkEvent --> payout wrapper
```

The wrapper can therefore represent pure mining, pure useful computation, or a hybrid event containing both.

## 1. WorkEvent

`WorkEvent` is the canonical underlying identity shared by all payout representations derived from one accepted event.

A work event contains independent mining and compute dimensions:

```text
mining_work
compute_complexity
```

and corresponding classification/binding material such as:

- mining class,
- compute class,
- block/job/subject binding,
- evidence binding,
- exact mining algorithm/profile binding,
- exact compute execution binding,
- optional series-first stack binding,
- public/hidden contract visibility.

Valid event shapes are:

```text
pure mining:
    mining_work > 0
    compute_complexity = 0

pure compute:
    mining_work = 0
    compute_complexity > 0

hybrid:
    mining_work > 0
    compute_complexity > 0
```

A zero-work event fails closed.

## 2. Execution identity

Useful compute can preserve an exact execution identity without forcing all value to fragment by implementation.

`execution_binding` may identify:

- a canonical shared module-set,
- a built-in/default V0ID implementation/profile,
- a user algorithm,
- a user Turing machine or bounded semantic program.

For synchronized Wasm, the current module layer already provides content-addressed SHA3-512 identities and a canonical module-set digest.

The coin wrapper consumes an execution identity; it does not decide whether a module is trusted or whether the computation proof is valid.

## 3. Series-first binding

Useful-compute events may bind the exact `SeriesFirstStackContext` identity through `series_stack_binding`.

That lets a future ledger distinguish work performed under different:

- sessions,
- jobs,
- epochs,
- semantic bindings,
- generator implementations,
- KEX transcripts,
- synchronized module sets,
- outer-channel bindings.

The coin layer does not own or replace the V0ID key schedule.

## 4. Contract visibility

Visibility is orthogonal to work type and payout flavor.

Current classification supports:

```text
public_semantics
hidden_semantics
not_applicable
```

A hidden compute event is intended to represent work whose plaintext semantics remain concealed by the underlying V0ID execution model.

Visibility changes the canonical work-event identity; it is not merely a UI label.

## 5. Mining dimension

Mining work has its own exact identity and invariant classification path.

A mining event can bind:

- work amount,
- mining class,
- exact PoW algorithm/profile identity,
- current subject/challenge,
- accepted evidence.

The wrapper intentionally defines no specific PoW function, difficulty rule or issuance multiplier.

## 6. Compute dimension

Useful compute can bind:

- normalized compute complexity,
- compute class,
- execution/module/TM identity,
- V0ID series-first context,
- contract visibility,
- accepted evidence.

`compute_complexity` is currently an accounting input, not a consensus-grade proof of work performed.

## 7. 2 x 3 payout tree

For a hybrid event the wrapper exposes six payout classes:

```text
                         WorkEvent
                      /             \
                  MINING           COMPUTE
                 /  |  \\          /  |  \
                MI  MV  MC        CI  CV  CC
```

Current symbolic names:

| Symbol | Meaning |
|---|---|
| `V0ID-MI` | mining independent |
| `V0ID-MV` | mining invariant |
| `V0ID-MC` | mining-side combo |
| `V0ID-CI` | compute independent |
| `V0ID-CV` | compute invariant |
| `V0ID-CC` | compute-side combo |

A pure mining or pure compute event exposes only its independent and invariant leaves. Combo leaves require a real hybrid event.

## 8. Independent flavor

Independent denominations preserve exact implementation identity.

Mining independent binds:

- mining class,
- exact mining algorithm/profile binding.

Compute independent binds:

- compute class,
- exact execution/module/default-stack/user-TM identity.

This gives the system a place for implementation-specific economic selection without requiring the entire currency to become implementation-specific.

## 9. Invariant flavor

Invariant denominations intentionally ignore the exact algorithm/module identity while retaining the work class.

Conceptually:

```text
different accepted implementations
              |
      same normalized work class
              |
        invariant denomination
```

The current wrapper does not define equivalence across different work classes.

## 10. Combo flavor

Combo denominations exist only for hybrid mining+compute events.

They bind both sides of the event:

- mining class and exact mining identity,
- compute class and exact execution identity,
- one common `WorkEventId`.

Mining-combo and compute-combo remain distinct payout classes even though both reference the same hybrid event.

The wrapper does not define a mining-to-compute exchange rate.

## 11. Anti-double-counting identity

Every payout leaf derived from one accepted event shares the same underlying `WorkEventId`.

Therefore:

> multiple payout classifications do not imply multiple independent units of underlying work.

A future ledger can use `WorkEventId` as the common replay/double-accounting anchor while separately deciding how payout classes are issued, redeemed or exchanged.

## 12. Current runtime gate

`v0id-work-token-tests` is currently runtime-verified at **19/19 PASS** for the implemented wrapper behavior, including:

- deterministic hybrid work-event identity,
- full 2 x 3 tree for hybrid events,
- shared underlying work-event identity,
- stable payout symbols,
- independent/invariant identity behavior,
- combo identity behavior,
- pure mining/compute branch restrictions,
- work/complexity/visibility binding,
- zero-work rejection.

## 13. Explicit non-claims

The current coin architecture does **not** define:

- a blockchain,
- consensus,
- block format,
- fork choice,
- mempool,
- wallets,
- supply schedule,
- issuance policy,
- mining difficulty,
- compute normalization,
- mining/compute exchange rate,
- smart-contract state transitions,
- finality,
- useful-compute execution proof.

Those belong to the future architecture and must remain separate from the already-tested wrapper.
