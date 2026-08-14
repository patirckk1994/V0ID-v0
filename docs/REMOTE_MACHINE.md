# V0ID V0.4 remote-machine protocol

V0.4 connects the local polymorphic BinFHE machine to the existing ZeroMQ transport. The goal of this stage is narrow: prove that an entire encrypted morphed machine can cross a process/network boundary, execute under a fixed public schedule without the client secret key, and return a result that only the client can interpret and verify with its private morph manifest.

This is experimental research code, not a production wire protocol or audited verifiable-computation scheme.

## Roles

### Client

The client owns:

- semantic plaintext program before outsourcing,
- 256-bit morph seed,
- `MorphManifest`,
- LWE secret key,
- expected plaintext result for tests,
- expected toy self-fingerprint,
- selected integrity candidate index,
- plaintext integrity masks.

The client performs all morph generation and encryption.

### Evaluator

The evaluator receives only evaluator-visible public shape and encrypted/evaluation material. It has no LWE secret key and no `MorphManifest`.

It performs:

- BinFHE context/evaluation-key reconstruction,
- toy self-fingerprint evaluation over encrypted job-image bits,
- all fixed public interpreter rounds,
- masked integrity candidate generation,
- serialization of encrypted final machine state.

## Public shape

`PublicMachineShape` currently contains:

```cpp
struct PublicMachineShape {
    uint64_t states;
    uint64_t tape_cells;
    uint64_t rounds;
    uint64_t integrity_slots;
};
```

The V0.4 demo uses:

```text
states          4
tape_cells      8
rounds          4
integrity_slots 4
alphabet        binary, implied by the interpreter
```

The wire codec rejects shapes above explicit research limits before allocating the corresponding ciphertext vectors.

## EXECUTE_JOB payload

The V0.4 payload has magic `V0IDRMJ1` followed by public shape and length-framed binary OpenFHE objects.

Conceptually:

```text
V0IDRMJ1
PublicMachineShape

serialized BinFHEContext
serialized refresh/bootstrapping key
serialized switching key
serialized independently encrypted zero

encrypted canonical transition bits[]
encrypted one-hot state[]
encrypted one-hot head[]
encrypted tape[]

encrypted nonce[32]
independently encrypted toy-fingerprint initial state[32]
encrypted integrity mask[slot][32]
```

Canonical transition rows are laid out as:

```text
for state q
  for read bit 0,1
    next_state_one_hot[states]
    write_one
    move_left
    move_stay
    move_right
```

Thus the public encrypted program-bit count is:

```text
states * 2 * (states + 4)
```

For four public states this is 64 encrypted transition bits.

## What is deliberately absent

The V0.4 job format has no field for:

```text
LWE secret key
morph seed
MorphManifest
base semantic state IDs
base_to_morphed mapping
privileged dummy-state metadata
selected integrity output slot
plaintext integrity masks
plaintext program transitions
plaintext tape bits
```

The evaluator can of course see public dimensions, serialized byte lengths, timing and its own execution schedule.

## Evaluator execution

The evaluator reconstructs the BinFHE context and loads only the refresh/switching evaluation keys.

It computes the toy fingerprint over:

```text
encrypted morphed transition bits
+
encrypted initial tape
+
encrypted nonce
```

using the client-supplied independently encrypted mixer initialization bits.

It masks the resulting encrypted digest once for every public integrity slot, then runs the machine for exactly `shape.rounds` rounds.

No host-language branch is taken on encrypted next-state, write or movement semantics.

The fixed evaluator loop remains structurally:

```text
for each public round
  for each tape cell
    for each public state
      for read bit 0,1
        encrypted active test
        encrypted next-state selection
        encrypted write selection
        encrypted movement selection
```

## JOB_RESULT payload

The result has magic `V0IDRMR1` and repeats the public shape, followed by:

```text
encrypted final one-hot state[]
encrypted final one-hot head[]
encrypted final tape[]
masked encrypted integrity candidate[slot][32]
```

Returning final state and head as well as tape is intentional: it preserves enough encrypted machine state for a future checkpoint/resume protocol.

The V0.4 demo client decrypts the final tape and expects:

```text
00001101 -> 00001110
```

It then uses its private manifest to select exactly one returned integrity candidate, decrypts it, removes the corresponding private mask and compares it to the client-side expected toy fingerprint.

## Current placement boundary

V0.4 transfers the tape in logical order. It does not send the local prototype's KMAC remap key to the evaluator and does not yet model peer-local physical storage.

The intended V0.5 composition is:

```text
semantic/logical cell
    -> compiler relocation
    -> epoch remap
    -> peer selection
    -> peer-local slot
```

with `STORE_SLOT`, `FETCH_SLOT` and `SLOT_VALUE` carrying opaque ciphertext storage objects.

The existing remap mechanism is not claimed to be ORAM. Once remote storage exists, access order, message sizes and timing become explicit correlation surfaces and should be logged from the evaluator-visible perspective for adversarial testing.

## Integrity limitation

`ToyFingerprint32` is not a cryptographic hash and the current evaluator executes it as a recognizable dedicated circuit.

It currently proves plumbing for:

- FHE evaluation over the encrypted morphed job image,
- client-private integrity placement metadata,
- fixed-size returned candidate banks,
- remote transport of the entire check path.

It does **not** yet prove that every requested remote execution step was performed honestly. The next integrity stages must bind to evolving/final machine state and eventually hide/interleave integrity work so that a malicious evaluator cannot trivially identify the check circuit from execution behavior.

## Demo

Build:

```sh
cmake -S . -B build
cmake --build build -j
```

Evaluator:

```sh
./build/v0id-remote-machine server EVAL tcp://*:7003 1
```

Client:

```sh
./build/v0id-remote-machine client CLIENT tcp://127.0.0.1:7003
```

The server prints public round progress. The client/server socket timeout is one hour because BinFHE evaluation is intentionally expensive at this stage.
