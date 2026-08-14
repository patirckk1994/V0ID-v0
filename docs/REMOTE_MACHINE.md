# V0ID V0.4-V0.4.3 remote-machine protocol

V0.4 connected the local polymorphic BinFHE machine to the ZeroMQ transport and proved that an entire encrypted morphed machine can cross a process/network boundary, execute under a fixed public schedule without the client secret key, and return a result that only the client can interpret and verify with its private morph manifest.

V0.4.1 added a private series-first derivation stage on the client and bounded public crypto/profile identifiers. V0.4.3 separates expensive evaluator setup from per-job ciphertexts so BinFHE context/bootstrap material can be installed once and reused across jobs in the same evaluator process.

This is experimental research code, not a production wire protocol or audited verifiable-computation scheme.

## Roles

### Client

The client owns:

- semantic plaintext program before outsourcing,
- private 256-bit `SeriesSeed`,
- private derived polymorphic series,
- derived `MorphSeed`,
- `MorphManifest`,
- LWE secret key,
- expected plaintext result for tests,
- expected toy self-fingerprint,
- selected integrity candidate index,
- plaintext integrity masks.

The client performs all series generation, morph generation, key generation and encryption.

### Evaluator

The evaluator receives evaluator-visible public shape/profile information, reusable evaluation material and encrypted job material. It has no LWE secret key, private series, series seed or `MorphManifest`.

V0.4.3 keeps a bounded process-local cache of loaded evaluator sessions. The demo currently permits four cached sessions. Sessions are not persisted to disk and disappear when the evaluator process exits.

## Why V0.4.3 exists

The proven V0.4 run sent roughly 551 MB in one job request while returning roughly 666 KB. The dominant cost was not the tiny encrypted machine description itself but serialized BinFHE context/bootstrap material being resent with every request.

RMJ3 therefore changes:

```text
old RMJ2 job
    context
    refresh/bootstrap key
    switching key
    encrypted machine

into

RMS3 evaluator-session install (once)
    context
    refresh/bootstrap key
    switching key

RMJ3 job (repeated)
    evaluator session id
    encrypted machine only
```

The first job in a fresh evaluator process still pays the evaluator-setup transfer. Subsequent jobs referencing the same cached session do not resend it.

This is an engineering optimization, not a new cryptographic security claim.

## Evaluator session ID

`EvaluatorSessionId` is a fresh 256-bit public identifier generated independently of `SeriesSeed`.

```cpp
using EvaluatorSessionId = std::array<uint8_t, 32>;
```

It is routing/cache state, not a secret and not currently an authenticated session identifier. An all-zero identifier is rejected. The demo rejects duplicate installed IDs and caps the process-local cache at four sessions.

Future authenticated negotiation must bind the session ID, primitive, parameter set and job profile to the authenticated peer/session transcript.

## INSTALL_EVALUATOR_SESSION / RMS3

The transport adds:

```text
INSTALL_EVALUATOR_SESSION
EVALUATOR_SESSION_READY
```

The setup payload magic is `V0IDRMS3`:

```text
V0IDRMS3
EvaluatorSessionId
primitive id
parameter set
serialized BinFHEContext
serialized refresh/bootstrapping key
serialized switching key
```

For the current demo:

```text
primitive     openfhe-binfhe
parameter set STD128
```

The evaluator deserializes the context and keys once, calls `BTKeyLoad`, and retains the loaded `BinFHEContext` plus evaluation-key objects in the bounded process-local session cache.

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

The demo uses four public states, eight tape cells, four rounds and four integrity slots.

## Public crypto/profile ID

The job still carries:

```cpp
struct CryptoProfileId {
    std::string primitive_id;
    std::string parameter_set;
    std::string machine_protocol;
    std::string integrity_profile;
    std::string series_generator_id;
    uint64_t series_generator_version;
};
```

The V0.4.3 demo advertises:

```text
openfhe-binfhe
STD128
v0id-remote-machine-v3
toy-fingerprint32-v1
v0id-series-kmac-v1 / 1
```

The server fails closed on unsupported primitive, parameter-set, machine-protocol or integrity-profile identifiers. It additionally requires the job primitive/parameter set to match the cached evaluator session referenced by the job.

The series generator itself executes only on the client; its id/version is public provenance metadata for future correlation tests and capability negotiation.

The server echoes the complete profile and evaluator session ID in the result and the client requires exact matches.

This is not yet an authenticated negotiation protocol. There is no suite-selection handshake or downgrade protection yet.

## EXECUTE_JOB / RMJ3

The per-job payload magic is `V0IDRMJ3`:

```text
V0IDRMJ3
EvaluatorSessionId
PublicMachineShape
CryptoProfileId
serialized independently encrypted zero

encrypted canonical transition bits[]
encrypted one-hot state[]
encrypted one-hot head[]
encrypted tape[]

encrypted nonce[32]
independently encrypted toy-fingerprint initial state[32]
encrypted integrity mask[slot][32]
```

Notably absent from RMJ3:

```text
serialized BinFHEContext
refresh/bootstrap key
switching key
```

Those live in RMS3 setup and are reused from the evaluator cache.

Canonical transition rows remain:

```text
for state q
  for read bit 0,1
    next_state_one_hot[states]
    write_one
    move_left
    move_stay
    move_right
```

The public encrypted program-bit count is `states * 2 * (states + 4)`. For four public states this is 64 encrypted transition bits.

## What is deliberately absent

Neither RMS3 nor RMJ3 contains:

```text
LWE secret key
private polymorphic series
SeriesSeed
series private manifest
MorphSeed
MorphManifest
base semantic state IDs
base_to_morphed mapping
privileged dummy-state metadata
selected integrity output slot
plaintext integrity masks
plaintext program transitions
plaintext tape bits
```

The evaluator can still observe public session/profile strings, public dimensions, serialized byte lengths, timing and its execution schedule.

## Series-first client stage

Before `ProgramMorpher`, the default client runs:

```text
input + private SeriesSeed + epoch
             |
             v
    v0id-series-kmac-v1
             |
      private 64-byte series
             |
      derived MorphSeed
             |
             v
        ProgramMorpher
```

Neither the private series nor its seed is serialized into RMS3 or RMJ3. Only the generator id/version is public in the job profile.

Custom trusted local generators can implement `PolymorphicSeriesGenerator` or use `FunctionalSeriesGenerator`. This is not a peer-supplied executable plugin mechanism.

## Evaluator execution

For `INSTALL_EVALUATOR_SESSION`, the evaluator reconstructs the BinFHE context, loads refresh/switching evaluation keys and caches that loaded evaluator state.

For each RMJ3 job, it looks up the cache entry, verifies the job's primitive/parameter set matches the cached session, deserializes only the per-job ciphertexts, computes the toy fingerprint over encrypted morphed transition bits + encrypted initial tape + encrypted nonce, masks a candidate for every public slot, then runs exactly `shape.rounds` interpreter rounds.

No host-language branch is taken on encrypted next-state, write or movement semantics.

## JOB_RESULT / RMR3

The result magic is `V0IDRMR3`:

```text
V0IDRMR3
EvaluatorSessionId
PublicMachineShape
CryptoProfileId

encrypted final one-hot state[]
encrypted final one-hot head[]
encrypted final tape[]
masked encrypted integrity candidate[slot][32]
```

Returning state and head as well as tape preserves enough encrypted state for future checkpoint/resume.

The client requires the returned evaluator-session ID and profile to match what it sent, decrypts the final tape and expects:

```text
00001101 -> 00001110
```

It then uses its private manifest to select one returned integrity candidate, decrypts it, removes the private mask and compares it with the expected toy fingerprint.

## Status

The V0.4 RMJ1/RMR1 path was executed successfully across two local processes: the remote evaluator completed all four encrypted rounds, the client recovered `00001110`, and its private self-check verified while the server received neither the LWE secret key nor `MorphManifest`.

The V0.4.1 series/profile code and V0.4.3 RMS3/RMJ3/RMR3 evaluator-session cache are implemented but need a local rebuild/runtime regression against the installed OpenFHE build before being marked runtime-verified.

The client now prints:

```text
session setup bytes
context bytes
refresh key bytes
switching key bytes
RMJ3 per-job bytes
```

so the actual recurring bandwidth reduction can be measured directly rather than inferred from the old ~551 MB request.

## Placement boundary

The remote machine still transfers tape in logical order. Distributed physical placement remains a later stage:

```text
semantic/logical cell
    -> compiler relocation
    -> epoch remap
    -> peer selection
    -> peer-local slot
```

`STORE_SLOT`, `FETCH_SLOT` and `SLOT_VALUE` will eventually carry opaque ciphertext storage objects. The existing remap is not claimed to be ORAM.

## Integrity limitation

`ToyFingerprint32` is not a cryptographic hash and remains a recognizable dedicated circuit. It proves FHE/integrity plumbing, not honest execution of every requested step. Later work must bind integrity to evolving/final state and hide/interleave integrity computation more effectively.

## Demo

```sh
cmake -S . -B build
cmake --build build -j --target v0id-remote-machine
```

Evaluator (the count is completed/attempted `EXECUTE_JOB` messages; session installation does not consume it):

```sh
./build/v0id-remote-machine server EVAL tcp://*:7003 1
```

Client:

```sh
./build/v0id-remote-machine client CLIENT tcp://127.0.0.1:7003
```

Expected flow:

```text
client: generate BinFHE keys
client -> server: RMS3 evaluator setup (large, once)
server: BTKeyLoad + cache
server -> client: EVALUATOR_SESSION_READY
client -> server: RMJ3 encrypted machine (no context/bootstrap keys)
server: cached evaluation + four fixed rounds
server -> client: RMR3 encrypted result
client: decrypt 00001110 + verify private self-check
```

The client/server timeout is one hour because BinFHE evaluation is intentionally expensive at this stage.
