# V0ID Protocol Specification

> **Status:** research protocol specification for the implementation on `agent/sha3-boolean-ir`.
>
> This document describes what the current code does. It deliberately separates implemented confidentiality/authentication/binding properties from execution-soundness claims that are still open research.

![V0ID protocol flow](flowchart.png)

## 1. Scope

V0ID currently combines five distinct layers:

1. **private series and polymorphism** on the trusted client;
2. a **canonical Boolean program image** and encrypted virtual-machine representation;
3. **TFHE-rs CUDA client/evaluator separation** with the TFHE `ClientKey` retained by the client;
4. **V0IDNET1 multipart transport over ZeroMQ CURVE**, with client authorization through ZAP;
5. client-side decryption and semantic comparison, plus separate integrity/execution-soundness research components.

The current cloud protocol is a research service boundary. It is not a claim of production-audited cryptography and it is not an execution proof.

## 2. Trust model

### 2.1 Trusted client

The client is trusted with:

- semantic program/job input;
- plaintext input words;
- the private 256-bit series root (`SeriesSeed`);
- private derived polymorphic series and morph seed;
- the TFHE `ClientKey`;
- client CURVE secret key;
- the pinned evaluator CURVE public key;
- final result decryption and semantic verification.

### 2.2 Untrusted evaluator

The evaluator is allowed to receive:

- the evaluator/server CURVE secret key for its own endpoint;
- an allowlist of authorized client CURVE public keys;
- the TFHE compressed server key;
- encrypted initial machine state;
- encrypted instruction chunks;
- public protocol shape metadata such as instruction counts, output counts, job id and epoch;
- evaluator-visible timing, frame sizes and session activity.

The evaluator is **not** supposed to receive:

- the TFHE `ClientKey`;
- plaintext program instructions;
- plaintext input words;
- the private series root;
- the private generated series;
- the private morph seed or private generator manifest.

### 2.3 Current security boundary

The implemented cloud path provides:

- authenticated and encrypted transport using standard ZeroMQ CURVE;
- static client authorization using ZeroMQ ZAP;
- server-key pinning by the client;
- application binding of the authenticated ZAP `User-Id` to the V0ID `peer_id`;
- per-session binding to authenticated user id + `job_id` + `epoch` + random 128-bit TFHE session id;
- bounded, contiguous encrypted-instruction streaming;
- replay/reorder/gap rejection at both the network/session layer and Rust TFHE chunk layer;
- fail-closed parsing for malformed lengths, trailing metadata and oversized protocol objects.

It does **not** prove that a malicious evaluator performed every requested expensive homomorphic transition. Commitment, authenticated transport and contiguous chunk accounting are not a general proof of execution.

## 3. End-to-end protocol flow

```text
TRUSTED CLIENT
    semantic input
       |
       +--> PolymorphicSeriesGenerator
       |       KMACXOF256 v2 / Wasm / trusted custom C++
       |       -> private DerivedSeries
       |       -> private MorphSeed
       |
       +--> ProgramMorpher
       |       -> morphed Boolean program image
       |
       +--> TFHE client preparation
       |       -> ClientKey                [CLIENT ONLY]
       |       -> compressed ServerKey     [SEND ONCE]
       |       -> encrypted init state     [SEND ONCE]
       |
       +--> encrypt contiguous instruction chunks
               |
               v
        ZeroMQ CURVE + ZAP
        V0IDNET1 multipart framing
               |
               v
UNTRUSTED GPU EVALUATOR
    authenticate client CURVE public key
    derive application User-Id through ZAP
    require User-Id == envelope.peer_id
    install cached TFHE GPU session
    require job/epoch/session/order bindings
    execute encrypted chunks on CUDA
    select encrypted outputs
               |
               v
        encrypted result frame
               |
               v
TRUSTED CLIENT
    verify reply bindings
    decrypt with ClientKey
    compare with expected semantic result
```

## 4. Private series / polymorphism layer

### 4.1 Architecture invariant

The polymorphism engine depends on the generator interface, not directly on KMACXOF256:

```text
            PolymorphicSeriesGenerator
                       |
          +------------+-------------+
          |            |             |
     KMACXOF256       Wasm       custom C++
          |            |             |
          +------------+-------------+
                       |
                  DerivedSeries
                       |
                  ProgramMorpher
```

`ProgramMorpher -> KMACXOF256` is intentionally not the dependency direction.

### 4.2 Built-in profile

The built-in generator profile is:

```text
v0id-series-kmacxof256-v2
```

It uses OpenSSL 3 `KMAC-256` in XOF mode and domain-separates at least these derivations:

```text
V0ID private polymorphic series v2
V0ID trusted ProgramMorpher seed v2
V0ID private series provenance v2
```

The root is 256 bits and is generated with a private RNG path. The generated series length is a local generator parameter, not a fixed network-protocol requirement.

### 4.3 Generator substitution

Current substitution paths are:

- `KmacSeriesGenerator` — built-in KMACXOF256 implementation;
- `FunctionalSeriesGenerator` — trusted process-local callback;
- `WasmSeriesGenerator` — bounded client-local WAMR guest with no general host access.

Remote evaluators do not receive or execute the client's generator module.

## 5. Boolean program / encrypted VM layer

The current encrypted Boolean program representation uses a bounded register machine. The SHA3 program image uses 60 registers:

```text
0..24   state lanes
25..29  C lanes
30..34  D lanes
35..59  B lanes
```

Current instruction operations are:

```text
Xor2
Xor5
XorRot1
RotCopy
Chi
XorInput
XorConst
```

Encrypted instruction fields include the opcode and register/input/rotate/immediate selectors. The evaluator follows a fixed encrypted-selection path rather than branching in C++ on plaintext secret instruction fields.

The current SHA3 image is 2064 canonical round instructions plus absorb operations; polymorphic mutation can add identity operations and alter representation without changing intended semantics.

## 6. Outer network envelope: V0IDNET1

### 6.1 Envelope magic/version

```text
magic   = "V0IDNET1"       // 8 bytes
version = 1                 // u8
```

### 6.2 Binary envelope layout

All integer fields below are encoded big-endian by the current implementation.

```text
offset  size  field
0       8     magic = V0IDNET1
8       1     network version = 1
9       1     MessageType
10      2     reserved = 0
12      8     epoch (u64)
20      4     peer_id length (u32)
24      4     job_id length (u32)
28      4     payload length (u32)
32      N     peer_id bytes
...     M     job_id bytes
...     P     payload bytes
```

The decoder requires the remaining byte count to equal the three advertised variable-length fields exactly.

### 6.3 Relevant message type numbers

The enum currently assigns:

```text
14  INSTALL_TFHE_SESSION
15  TFHE_SESSION_READY
16  TFHE_INSTRUCTION_CHUNK
17  TFHE_CHUNK_READY
18  TFHE_JOB_FINISH
19  TFHE_JOB_RESULT
255 ERROR
```

Other V0IDNET1 message types exist for the older peer/demo/session/module paths; the authenticated TFHE cloud path uses the types above.

### 6.4 Multipart shape

Frame 0 is always the encoded V0ID `Envelope`.

Additional frames carry large opaque key/ciphertext objects so hundreds of MiB are not concatenated into another monolithic serialization.

The legacy transport and CURVE transport cap V0ID multipart payload frames at 16.

## 7. Authenticated transport: ZeroMQ CURVE + ZAP

### 7.1 Server

The evaluator configures a ZeroMQ CURVE server socket and an in-process ZAP handler.

The server has:

- a CURVE server secret key;
- a static allowlist mapping client CURVE public keys to stable application user ids;
- ZAP domain `v0id.tfhe.cloud.v1`.

A client public key that is not allowlisted is rejected by ZAP.

### 7.2 Client

The client configures:

- its CURVE public key;
- its CURVE secret key;
- the evaluator CURVE public key as the pinned `ZMQ_CURVE_SERVERKEY`.

The client public/secret pair is validated as a matching pair by the transport code.

### 7.3 Application identity binding

For received authenticated messages, the server extracts ZeroMQ message metadata:

```text
User-Id
```

The application requires:

```text
envelope.peer_id == authenticated_user_id
```

The `peer_id` field by itself is therefore not treated as authentication.

### 7.4 Current key model

The current demo uses static local key files:

```text
<prefix>.public   0644
<prefix>.secret   0600
```

Current protocol does not yet define PKI, automatic discovery, key rotation, revocation distribution or delegated authorization.

## 8. TFHE cloud metadata protocol

### 8.1 Metadata magic/version

The typed TFHE metadata carried inside `Envelope.payload` uses:

```text
magic    = "V0TFHE01"   // 8 bytes
version  = 1             // u32 big-endian
```

This version is distinct from both the outer `V0IDNET1` version and the Rust opaque-object codec version.

### 8.2 Common metadata prefix

```text
8 bytes   magic = V0TFHE01
4 bytes   protocol_version = 1
1 byte    payload kind
3 bytes   reserved = 0
16 bytes  nonzero random session_id
```

Payload kinds:

```text
1  install
2  chunk
3  ack
4  finish
5  result
```

### 8.3 INSTALL_TFHE_SESSION

Envelope type:

```text
INSTALL_TFHE_SESSION (14)
```

Metadata after the common prefix:

```text
u64 total_instruction_count
u32 output_word_count
u64 server_key_frame_length
u64 encrypted_init_frame_length
```

Multipart frames:

```text
frame 0  V0ID Envelope + TFHE install metadata
frame 1  compressed TFHE server key
frame 2  encrypted initial machine state
```

The evaluator creates and caches a `TfheCudaServerSession` from those two opaque frames.

### 8.4 TFHE_SESSION_READY

Envelope type:

```text
TFHE_SESSION_READY (15)
```

Metadata after the common prefix:

```text
u64 completed_instruction_count
```

For a newly installed session the completed count must be zero.

No blob frames are allowed.

### 8.5 TFHE_INSTRUCTION_CHUNK

Envelope type:

```text
TFHE_INSTRUCTION_CHUNK (16)
```

Metadata after the common prefix:

```text
u64 start_instruction
u32 instruction_count
u64 total_instruction_count
u64 encrypted_chunk_frame_length
```

Multipart frames:

```text
frame 0  V0ID Envelope + chunk metadata
frame 1  encrypted instruction chunk
```

The current C++ client normally chunks at:

```text
32 instructions/chunk
```

while the wire and Rust side permit at most:

```text
64 instructions/chunk
```

### 8.6 TFHE_CHUNK_READY

Envelope type:

```text
TFHE_CHUNK_READY (17)
```

Metadata after the common prefix:

```text
u64 completed_instruction_count
```

No blob frames are allowed.

### 8.7 TFHE_JOB_FINISH

Envelope type:

```text
TFHE_JOB_FINISH (18)
```

Metadata after the common prefix:

```text
u64 expected_instruction_count
u32 expected_output_word_count
```

No blob frames are allowed.

The evaluator refuses to finish until its cached completed count equals the installed expected instruction count.

### 8.8 TFHE_JOB_RESULT

Envelope type:

```text
TFHE_JOB_RESULT (19)
```

Metadata after the common prefix:

```text
u64 completed_instruction_count
u64 encrypted_result_frame_length
```

Multipart frames:

```text
frame 0  V0ID Envelope + result metadata
frame 1  encrypted TFHE result
```

### 8.9 ERROR

Application protocol failures use:

```text
MessageType::error (255)
```

The current demo places a human-readable error string in the V0ID envelope payload.

## 9. TFHE opaque-object codec

The outer cloud metadata protocol is version 1. The Rust TFHE serialization boundary currently has its own internal protocol version:

```text
CLOUD_PROTOCOL_VERSION = 2
```

Opaque-object magics are:

```text
V0IDCK02  client key envelope       [client local]
V0IDSK02  server key envelope       [evaluator visible]
V0IDCI02  encrypted cloud init      [evaluator visible]
V0IDCC02  encrypted chunk           [evaluator visible]
V0IDCR02  encrypted result          [returned to client]
```

The current Rust side uses bounded Serde/bincode serialization for TFHE-rs key/ciphertext objects, with:

- fixed-int encoding;
- trailing-byte rejection;
- explicit magic/version checks;
- size/shape bounds;
- FFI panic containment.

This remains research serialization. Hostile public deployment should move toward TFHE-rs safe/conformant serialization or an equivalently strict validated representation.

## 10. Session state machine

### 10.1 Session identity

A live server session is bound to:

```text
authenticated_user_id
job_id
epoch
random 128-bit nonzero session_id
```

### 10.2 Install transition

```text
ABSENT
  |
  | INSTALL_TFHE_SESSION
  v
INSTALLED / completed = 0
```

Duplicate session ids are rejected.

### 10.3 Chunk transition

For every chunk the server requires:

```text
authenticated_user_id == installed user
job_id                == installed job
epoch                 == installed epoch
start_instruction      == completed_instruction_count
total_instruction_count == installed total
instruction_count      <= remaining instruction budget
```

After successful encrypted execution:

```text
completed += instruction_count
```

The Rust encrypted-chunk envelope independently verifies contiguous ordering against its own cached `completed_instruction_count`.

### 10.4 Finish transition

The server requires:

```text
finish.expected_instruction_count == installed total
finish.expected_output_word_count == installed outputs
completed_instruction_count == installed total
```

It then selects encrypted outputs, serializes the encrypted result and destroys/releases the completed evaluator session.

## 11. Protocol limits

Current constants:

```text
maximum total instructions       65,536
maximum instructions per chunk       64
normal C++ chunk size                 32
maximum output words                  64
maximum opaque frame             512 MiB
maximum V0ID multipart frames         16
maximum cached TFHE sessions           4
TFHE session idle TTL          30 minutes
cloud demo socket timeout        1 hour
```

The Rust side separately bounds input words at 4096.

## 12. Client/evaluator TFHE split

### 12.1 Client preparation

The client calls the TFHE preparation boundary with plaintext semantic shape/input and receives:

```text
TfheCudaPreparedSession
    client_key_blob       PRIVATE / client only
    server_key_blob       send once to evaluator
    encrypted_init_blob   send once to evaluator
    instruction_count     public shape
    output_word_count     public shape
```

### 12.2 Evaluator session

The evaluator caches:

```text
CudaServerKey
encrypted registers
encrypted inputs
encrypted output selectors
expected instruction count
completed instruction count
```

The evaluator API has no TFHE `ClientKey` parameter.

### 12.3 Chunk execution

Each encrypted chunk is decrypted by nobody. The evaluator deserializes ciphertext objects, installs/sets the CUDA server key and homomorphically evaluates the encrypted instruction representation.

### 12.4 Result

The evaluator returns encrypted output ciphertexts. Only the client decodes/decrypts those outputs with the retained `ClientKey`.

## 13. Logging / observability

The cloud demo now streams progress instead of printing only after expensive calls return.

Server logs include:

- request arrival and message type;
- authenticated user / claimed peer / job / epoch;
- GPU evaluator installation start and elapsed time;
- encrypted chunk start/count/size;
- live TFHE CUDA execution progress from the existing progress callback;
- chunk completion timing;
- encrypted output-selection progress;
- result construction timing;
- return to waiting state.

Client logs include key-generation, client-encryption and other available TFHE progress stages.

These logs expose public operational metadata and are not intended to hide timing/size side channels.

## 14. Integrity components versus execution proof

V0ID contains separate integrity research including SHA3/KMAC commitments, canonical self-images, quine binding, round receipts and malicious-evaluator harnesses.

Important distinction:

```text
commitment to intended job != proof that every requested transition executed
```

Current authenticated cloud transport proves/binds who sent messages and enforces session/order consistency. It does not make the remote evaluator honest.

A final-output-only check can fail to detect skipped work when the semantic computation has fixed points or equivalent shortcuts. Round-receipt and round-polymorphic experiments are bounded falsification tools, not a universal proof system.

## 15. Current test surfaces

Cheap protocol/authentication tests:

```bash
cmake --build --preset gpu-fhe --target v0id-test-curve-transport
cmake --build --preset gpu-fhe --target v0id-test-tfhe-cloud-codec
```

Tiny real TFHE CUDA smoke path:

```bash
cmake --build --preset gpu-fhe --target v0id-test-small-fhe
```

Combined fast-large + tiny-homomorphic validation:

```bash
cmake --build --preset gpu-fhe --target v0id-test-milkshake
```

Real two-process authenticated cloud executable:

```bash
cmake --build --preset gpu-fhe --target v0id-tfhe-cloud
```

The cloud smoke program currently uses a one-instruction encrypted program specifically so the trust/network/GPU boundary can be tested without waiting for the full SHA3 stress workload.

## 16. Explicit non-claims

The current protocol does not claim:

- malicious-evaluator execution soundness;
- zero knowledge beyond the confidentiality properties supplied by the actual FHE/transport composition;
- hidden traffic shape or timing;
- anonymous clients;
- decentralized evaluator discovery;
- Sybil resistance;
- automatic key rotation or PKI;
- durable evaluator-session recovery;
- multi-worker scheduling fairness;
- consensus acceptance of useful compute;
- protocol-funded compute issuance;
- a formal proof that polymorphism prevents classification or shortcut attacks.

These boundaries are intentional and are tracked in `protocol-architecture-planned.md` and `ROADMAP.md`.
