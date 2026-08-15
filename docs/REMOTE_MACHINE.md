# V0ID remote-machine protocol: RMS3 + RMJ4/RMR4

V0ID's remote-machine path separates expensive reusable BinFHE evaluator setup from recurring encrypted jobs. The evaluator receives no LWE secret key, private series root, `MorphSeed`, `MorphManifest`, base semantic program, or plaintext tape.

This is experimental research code, not an audited production wire protocol or a complete verifiable-computation scheme.

## Current split

```text
client
  |
  | RMS3 once
  |   evaluator session id
  |   BinFHE context
  |   refresh/bootstrap key
  |   switching key
  v
remote evaluator cache
  |
  | RMJ4 per job
  |   session id
  |   public fixed shape/profile
  |   encrypted program/state/head/tape
  v
fixed-path BinFHE evaluation
  |
  | RMR4
  |   session id/profile
  |   encrypted final state/head/tape
  v
client decrypts/verifies
```

RMS3 remains the evaluator-session format introduced for caching. RMJ4/RMR4 replace RMJ3/RMR3 because the obsolete `ToyFingerprint32` nonce, initial mixer state, mask bank, and returned candidate bank have been removed from the wire rather than carried forever as dead compatibility baggage.

## RMS3 evaluator session

Magic:

```text
V0IDRMS3
```

Payload:

```text
EvaluatorSessionId
primitive id
parameter set
serialized BinFHEContext
serialized refresh/bootstrapping key
serialized switching key
```

The session id is a public 256-bit cache/routing identifier. It is not a secret key and is not yet an authenticated session identity. All-zero identifiers are rejected and the demo keeps a bounded process-local session cache.

The LWE secret key is never part of RMS3.

## Public shape

```cpp
struct PublicMachineShape {
    uint64_t states;
    uint64_t tape_cells;
    uint64_t rounds;
    uint64_t integrity_slots;
};
```

`integrity_slots` is retained as reserved public capacity for later execution-bound integrity work. RMJ4 does not serialize an integrity candidate bank and the current remote demo sets this field to zero.

## Public crypto/profile

The current remote demo advertises:

```text
primitive_id       openfhe-binfhe
parameter_set      STD128Q
machine_protocol   v0id-remote-machine-v4
integrity_profile  quine-sha3-512-client-v1
```

The series generator id/version remains public provenance; the private series and root remain client-side.

The server fails closed on unsupported primitive, parameter set, machine protocol, or integrity profile and requires the job primitive/parameter set to match the referenced cached evaluator session.

## RMJ4 job

Magic:

```text
V0IDRMJ4
```

Payload:

```text
EvaluatorSessionId
PublicMachineShape
CryptoProfileId
serialized independently encrypted zero
encrypted canonical transition bits[]
encrypted one-hot state[]
encrypted one-hot head[]
encrypted tape[]
```

Canonical transition rows are:

```text
for state q
  for read bit 0,1
    next_state_one_hot[states]
    write_one
    move_left
    move_stay
    move_right
```

The evaluator therefore receives encrypted machine semantics under a fixed public shape but no ToyFingerprint nonce, mixer state, private mask bank, or private candidate selection metadata.

## RMR4 result

Magic:

```text
V0IDRMR4
```

Payload:

```text
EvaluatorSessionId
PublicMachineShape
CryptoProfileId
encrypted final one-hot state[]
encrypted final one-hot head[]
encrypted final tape[]
```

Returning state/head as well as tape preserves the state needed for later checkpoint/resume experiments.

## Client-side SHA3 commitment

The client currently computes an issuer-private SHA3-512 quine commitment over the morphed semantic job and its bound context. That commitment is useful for binding the client's intended job image and detecting accidental/local substitution.

It is deliberately **not** presented as proof that a remote evaluator honestly executed every requested round. A hash of the starting object does not prove the transition history.

## Execution-bound integrity

The separate `round_receipt` experiment hashes evaluator-visible encrypted state across actual round boundaries and binds the receipt to session/job/epoch/profile/round count. The malicious-evaluator harness demonstrates the important distinction:

```text
final-output-only check
    can accept a 2/4 fixed-point shortcut

SHA3-512 round receipt
    rejects the tested short/duplicate/replay/splice receipts
```

That remains research, not a general proof of verifiable computation. Adaptive ciphertext transformations and stronger interior-round attacks still need explicit treatment.

`ToyFingerprint32` has been retired rather than upgraded: its useful lesson was the plumbing boundary, while SHA3-based commitments and execution-bound receipts now own the integrity research path.

## What remains private

Neither RMS3 nor RMJ4 contains:

```text
LWE secret key
private polymorphic series
SeriesSeed
MorphSeed
MorphManifest
base semantic state IDs
base_to_morphed mapping
plaintext program transitions
plaintext tape bits
client quine digest
audit challenge
```

The evaluator can still observe public session/profile fields, public dimensions, serialized byte lengths, timing, and execution schedule. Hiding those traces is a separate problem.

## Demo

Build both sides from the same checkout because RMJ4/RMR4 are intentionally wire-incompatible with RMJ3/RMR3:

```sh
cmake -S . -B build
cmake --build build -j --target v0id-remote-machine
```

Evaluator:

```sh
./build/v0id-remote-machine server EVAL tcp://*:7003 1
```

Client:

```sh
./build/v0id-remote-machine client CLIENT tcp://127.0.0.1:7003
```

Expected high-level flow:

```text
client -> server: RMS3 evaluator setup (large, once)
server: BTKeyLoad + cache
server -> client: EVALUATOR_SESSION_READY
client -> server: RMJ4 encrypted machine
server: cached fixed-round evaluation
server -> client: RMR4 encrypted final machine state
client: decrypt result + recheck private SHA3 commitment
```
