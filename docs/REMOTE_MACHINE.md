# V0ID V0.4/V0.4.1 remote-machine protocol

V0.4 connected the local polymorphic BinFHE machine to the ZeroMQ transport and proved that an entire encrypted morphed machine can cross a process/network boundary, execute under a fixed public schedule without the client secret key, and return a result that only the client can interpret and verify with its private morph manifest.

V0.4.1 adds a private series-first derivation stage on the client and bounded public crypto/profile identifiers to the wire format.

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

The client performs all series generation, morph generation and encryption.

### Evaluator

The evaluator receives only evaluator-visible public shape/profile information and encrypted/evaluation material. It has no LWE secret key, private series, series seed or `MorphManifest`.

It performs:

- public profile validation,
- BinFHE context/evaluation-key reconstruction,
- toy self-fingerprint evaluation over encrypted job-image bits,
- all fixed public interpreter rounds,
- masked integrity candidate generation,
- serialization of encrypted final machine state.

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

V0.4.1 carries:

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

The default demo advertises:

```text
openfhe-binfhe
STD128
v0id-remote-machine-v2
toy-fingerprint32-v1
v0id-series-kmac-v1 / 1
```

The server fails closed on unsupported primitive, parameter-set, machine-protocol or integrity-profile identifiers. The series generator itself executes only on the client; its id/version is public provenance metadata for future correlation tests and capability negotiation.

The server echoes the complete profile in the result and the client requires an exact match.

This is not yet an authenticated negotiation protocol. There is no suite-selection handshake or downgrade protection yet.

## EXECUTE_JOB payload

The V0.4.1 payload magic is `V0IDRMJ2`:

```text
V0IDRMJ2
PublicMachineShape
CryptoProfileId

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

The evaluator can still observe public profile strings, public dimensions, serialized byte lengths, timing and its execution schedule.

## Series-first client stage

Before `ProgramMorpher`, the default client now runs:

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

Neither the private series nor its seed is serialized into `EXECUTE_JOB`. Only the generator id/version is public.

Custom trusted local generators can implement `PolymorphicSeriesGenerator` or use `FunctionalSeriesGenerator`. This is not a peer-supplied executable plugin mechanism.

## Evaluator execution

The evaluator reconstructs the BinFHE context and loads only refresh/switching evaluation keys. It computes the toy fingerprint over encrypted morphed transition bits + encrypted initial tape + encrypted nonce, masks a candidate for every public slot, then runs exactly `shape.rounds` interpreter rounds.

No host-language branch is taken on encrypted next-state, write or movement semantics.

## JOB_RESULT payload

The V0.4.1 result magic is `V0IDRMR2`:

```text
V0IDRMR2
PublicMachineShape
CryptoProfileId

encrypted final one-hot state[]
encrypted final one-hot head[]
encrypted final tape[]
masked encrypted integrity candidate[slot][32]
```

Returning state and head as well as tape preserves enough encrypted state for future checkpoint/resume.

The client decrypts the final tape and expects:

```text
00001101 -> 00001110
```

It then uses its private manifest to select one returned integrity candidate, decrypts it, removes the private mask and compares it with the expected toy fingerprint.

## Proven V0.4 result and V0.4.1 status

The V0.4 RMJ1/RMR1 path was executed successfully across two local processes: the remote evaluator completed all four encrypted rounds, the client recovered `00001110`, and its private self-check verified while the server received neither the LWE secret key nor `MorphManifest`.

That run also exposed the first major cloud engineering bottleneck: the request was roughly 551 MB because BinFHE context/bootstrap material was included per job, while the encrypted result was roughly 666 KB.

V0.4.1 keeps the same computation but changes the wire format to RMJ2/RMR2 and derives the morph from a private series first. It still needs compiler/runtime validation against the installed OpenFHE build.

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

Evaluator:

```sh
./build/v0id-remote-machine server EVAL tcp://*:7003 1
```

Client:

```sh
./build/v0id-remote-machine client CLIENT tcp://127.0.0.1:7003
```

The server prints public profile and round progress. The client/server timeout is one hour because BinFHE evaluation is intentionally expensive at this stage.
