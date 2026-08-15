# Round-polymorphic execution binding

Status: **implemented experiment; build/runtime result not yet reported for this revision**.

This note exists because the previous execution-soundness work exposed an architectural distinction that matters for V0ID.

The original stable-morph path did two separable things on the evaluator:

```text
FHE fingerprint(encrypted morphed program, encrypted input, encrypted nonce)

and separately

for each public round:
    RemoteEncryptedMachine::step()
```

That is useful plumbing, but it permits the concrete fixed-point attack already reproduced by `v0id-malicious-evaluator-harness`: the benchmark reaches the same semantic tape after two rounds as after four, while the static fingerprint still authenticates the same initial machine image.

The intended V0ID direction is stronger: the integrity object should be tied to the same hidden polymorphic representation the useful computation must traverse.

## First repair experiment

`ProgramMorpher::morph_round_schedule()` now builds one secret state-label encoding per round boundary.

For logical state `q`:

```text
boundary 0: q -> pi_0(q)
boundary 1: q -> pi_1(q)
boundary 2: q -> pi_2(q)
...
boundary N: q -> pi_N(q)
```

Round `r` receives a complete fixed-shape transition table whose source labels use `pi_r` and whose next-state labels use `pi_(r+1)`.

Conceptually:

```text
semantic P
    |
    +-- private series / MorphSeed
    |
    v
pi_0, pi_1, ... pi_N
    |
    v
T_0 : pi_0(P-state) -> pi_1(P-next-state)
T_1 : pi_1(P-state) -> pi_2(P-next-state)
...
T_N : ...
```

The evaluator still executes a generic encrypted transition circuit. The plaintext maps are client-only.

The first construction requires:

```text
public_state_count >= rounds + 1
```

and uses a KMAC-seeded secret base permutation plus a full-cycle stride. Therefore each logical state occupies a distinct public label at every requested boundary.

This requirement is deliberately simple for the first falsification experiment; it is not asserted to be the final scaling construction.

## Why this responds to the 2/4 fixed-point bug

For the increment benchmark:

```text
semantic tape after round 2 == semantic tape after round 4
semantic state after round 2 == semantic state after round 4
```

under the original stable representation.

Under the round-polymorphic representation:

```text
round 2 hidden state = pi_2(q_final)
round 4 hidden state = pi_4(q_final)
```

and the construction guarantees these labels differ for the configured schedule.

So a plain skip-and-stop evaluator can still have the right tape after two rounds, but it does **not** have the client-expected boundary-4 hidden state.

That is the precise claim. It is narrower than “proof of arbitrary work.”

## Schedule-wide encrypted self-fingerprint

`toy_fingerprint32_fhe()` already accepts a flat vector of encrypted program bits. The new schedule helper simply canonicalizes and concatenates every round table in order:

```text
T_0 || T_1 || ... || T_(N-1)
```

The client has a matching plaintext reference through:

```cpp
canonical_program_schedule_bits(...)
toy_fingerprint32_plain_schedule(...)
```

Therefore the existing FHE plumbing can authenticate the exact ordered hidden schedule rather than only one stable transition table.

Important: `ToyFingerprint32` is still intentionally **not a cryptographic hash**. It remains a plumbing primitive used before attempting a real Keccak/KMAC circuit under BinFHE. `QuineHash512` remains the standardized SHA3/KMAC client-side commitment layer.

## RemoteEncryptedMachine support

`RemoteEncryptedMachine` now accepts either:

```text
one encrypted transition table
```

or:

```text
shape.rounds concatenated encrypted transition tables
```

In schedule mode, `step()` consumes the next encrypted table on each invocation. Existing single-table callers remain supported.

This is intentionally implemented below the network protocol first. RMJ3/RMR3 still serializes the stable single-table live demo; promoting the schedule to a wire protocol version should happen only after the two new harnesses build and the expensive FHE experiment behaves as expected.

## Test targets

Fast plaintext gate:

```sh
cmake --build build -j --target v0id-round-morph-schedule-tests
./build/v0id-round-morph-schedule-tests
```

It checks:

- one table per requested round,
- one hidden mapping per round boundary,
- complete/valid transition tables,
- no logical-state label reuse across configured boundaries,
- semantic equivalence of the schedule,
- the original 2/4 same-tape condition still exists,
- boundary-2 and boundary-4 hidden states differ,
- deterministic reproduction under the same private seed,
- a changed seed changes the schedule,
- insufficient public state count fails closed.

Real OpenFHE experiment:

```sh
cmake --build build -j --target v0id-round-morph-fhe-harness
./build/v0id-round-morph-fhe-harness
```

This target uses OpenFHE BinFHE `STD128Q`, encrypts the complete four-table schedule, homomorphically fingerprints that schedule, runs an honest 4/4 machine and a malicious 2/4 machine, and compares both semantic tape and decrypted hidden final-state label.

It is expected to be expensive.

## Security boundary

If the FHE harness behaves as intended, it closes this concrete claim:

> A skip-and-stop evaluator cannot rely on a semantic fixed point to make a 2-round encrypted representation equal the client-expected 4-round representation.

It does **not** establish:

- that no faster equivalent transform from boundary 2 to boundary 4 exists,
- that the round mappings cannot be distinguished structurally,
- that the toy fingerprint is cryptographically strong,
- that exact reference-circuit gate count was performed,
- that useful compute is ready for protocol-funded issuance.

Those remain **UNCERTAIN** until attacked.

An evaluator that discovers a genuinely cheaper way to compute the same hidden relation may simply have found a better evaluator. V0ID should target correct, client-bound computation rather than forcing waste for its own sake.

## Relationship to round receipts

Round receipts remain useful as an adversarial scaffold and external audit experiment. They caught the distinction between “a static machine image is authentic” and “the requested execution happened.”

They are not promoted to the final architecture by this change.

The current direction is to make hidden execution state itself change in a client-private, series-derived way across rounds, then bind the complete schedule and final hidden representation.

## Next protocol step

After the fast target is green and the FHE harness is observed end-to-end:

1. define a versioned live remote-machine profile for round schedules,
2. serialize the ordered encrypted table schedule in the job payload,
3. bind the schedule into the client quine/commitment context,
4. require the client to validate the final encrypted/decrypted state encoding in addition to the semantic result,
5. rerun skip/replay/splice/substitution attacks against the live client/server path.

Only then should the old stable-table path be considered legacy for execution-sensitive jobs.

## Blockchain consequence

This repair does not need to block deterministic ledger engineering.

`ROADMAP.md` now separates two gates:

```text
ledger substrate                useful-compute issuance
---------------                 ----------------------
canonical bytes                 stays CLOSED
transactions                    until execution evidence
blocks                          is cheap + strong enough
state transition
replay/nullifiers
local simulator
```

That allows `src/chain/` to start without pretending the computation-economics problem has already been solved.
