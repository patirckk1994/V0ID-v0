# V0ID TFHE-rs CUDA cloud boundary

Status: streamed TFHE trust split plus bounded ZeroMQ multipart transport with CURVE channel authentication and a ZAP client-key allowlist. This is still a research service boundary, not production-audited cryptography.

## Goal

The CUDA stress path originally kept all roles inside one Rust function. The first cloud split separated client key generation/encryption, evaluator-only CUDA execution and client decryption, but serialized the complete encrypted SHA3 image as one object.

The owner runtime measurement for that first split was approximately:

```text
client key        31,316 bytes
server key       241,254,809 bytes
encrypted job  2,501,584,840 bytes
```

That proved the trust split but also proved a monolithic encrypted-program blob is the wrong transport shape.

The current boundary keeps the server key and encrypted machine state resident in one evaluator session, streams bounded encrypted instruction chunks, and authenticates the network peers with standard ZeroMQ CURVE rather than inventing a V0ID transport cipher.

```text
TRUSTED CLIENT
    CURVE client keypair
    pinned evaluator CURVE public key
    TFHE ClientKey

    prepare TFHE session
        plaintext inputs + public shape
        -> private ClientKey blob
        -> CompressedServerKey blob
        -> encrypted init blob

ZERO MQ CURVE + ZAP
    encrypted/authenticated channel
    frame 0: small V0ID envelope + typed TFHE metadata
    frame N: bounded opaque key/ciphertext objects

UNTRUSTED EVALUATOR
    CURVE server secret key
    ZAP allowlist: client public key -> authenticated User-Id

    install TFHE session
        server key + encrypted init
        -> GPU server key cached in process
        -> encrypted registers/inputs kept resident
        -> session bound to authenticated User-Id + job + epoch

TRUSTED CLIENT
    encrypt next instruction range
        private ClientKey + plaintext instruction range
        -> encrypted instruction chunk

UNTRUSTED EVALUATOR
    evaluate chunk
        encrypted chunk only
        -> reject wrong auth identity/session/job/epoch/order/count
        -> advance resident encrypted registers

UNTRUSTED EVALUATOR
    finish
        -> encrypted output result
        -> release completed evaluator session

TRUSTED CLIENT
    decrypt
        private ClientKey + encrypted result
        -> plaintext output words
```

The evaluator APIs have no `ClientKey` parameter and receive no plaintext instruction, image or input arguments.

## Authenticated transport

`src/net/curve_peer_transport.*` adds a separate secure transport instead of changing the legacy V0ID peer transport.

The cloud path uses:

```text
ZeroMQ CURVE
    confidentiality + client/server public-key authentication

ZeroMQ ZAP
    evaluator allowlist
    client CURVE public key -> stable User-Id

V0ID cloud session
    authenticated User-Id + job_id + epoch + random session id
```

The evaluator starts an in-process ZAP handler before binding its CURVE server socket. Only configured client public keys receive a `200` ZAP response. The ZAP User-Id is then read from the received ZeroMQ message metadata and exposed as `MultipartEnvelope::authenticated_user_id`.

For every TFHE cloud request the evaluator requires:

```text
envelope.peer_id == authenticated_user_id
```

The installed TFHE session stores that authenticated User-Id. Every later chunk and finish request must arrive with the same authenticated identity in addition to matching the job and epoch.

The client pins the evaluator CURVE public key. It also checks the V0ID reply `peer_id`, `job_id` and `epoch` against the expected server/job context. The transport public key is the cryptographic server authentication; the reply peer id is an additional protocol binding.

This is currently a static key/allowlist model. Key distribution, rotation, revocation lists and a larger PKI are deliberately not invented yet.

## Key handling

The cloud demo has a local key generator:

```bash
./build-gpu/v0id-tfhe-cloud keygen server
./build-gpu/v0id-tfhe-cloud keygen client-a
```

Each command creates:

```text
<prefix>.public    public Z85 CURVE key
<prefix>.secret    secret Z85 CURVE key
```

The generator uses exclusive file creation so it refuses to overwrite an existing keypair. Generated secret files use mode `0600`; public files use `0644`. Secret keys are passed to the demo by file path rather than copied into process command-line arguments.

The transport validates Z85 key shape, checks that client public and secret keys form the same CURVE keypair, and fails if linked libzmq has no CURVE support.

## Network protocol

`src/net/tfhe_cloud_codec.*` defines protocol version 1 with random nonzero 128-bit session ids and these message types:

```text
INSTALL_TFHE_SESSION
TFHE_SESSION_READY
TFHE_INSTRUCTION_CHUNK
TFHE_CHUNK_READY
TFHE_JOB_FINISH
TFHE_JOB_RESULT
```

The V0ID envelope carries `peer_id`, `job_id` and `epoch`. The typed TFHE metadata carries session id plus explicit instruction/output counters. Large opaque objects are separate ZeroMQ multipart frames rather than being concatenated into a second giant serialization.

The current frame shapes are:

```text
INSTALL_TFHE_SESSION
    metadata:
        session id
        total instruction count
        output word count
        server-key frame length
        encrypted-init frame length
    frame 1: compressed server key
    frame 2: encrypted init

TFHE_INSTRUCTION_CHUNK
    metadata:
        session id
        start instruction
        instruction count
        total instruction count
        encrypted-chunk frame length
    frame 1: encrypted instruction chunk

TFHE_JOB_FINISH
    metadata:
        session id
        expected instruction count
        expected output word count

TFHE_JOB_RESULT
    metadata:
        session id
        completed instruction count
        encrypted-result frame length
    frame 1: encrypted result
```

Limits are checked before evaluator work:

```text
maximum instructions          65536
maximum instructions/chunk       64
maximum outputs                  64
maximum opaque frame       512 MiB
maximum cached sessions           4
session idle TTL          30 minutes
```

## Ordering and fail-closed behavior

Every chunk binds:

```text
start_instruction
instruction_count
total_instruction_count
encrypted chunk
```

The network session requires:

```text
authenticated_user_id == installed authenticated user
job_id                == installed job
 epoch                  == installed epoch
start_instruction      == completed_instruction_count
total_instruction_count == installed total
chunk_count             <= remaining instructions
```

The Rust encrypted-chunk envelope independently requires contiguous ordering as well. A repeated, reordered, skipped, identity-switched or over-budget transport chunk therefore fails before the session advances.

Malformed oversized multipart messages are drained before rejection so an authenticated protocol error does not leave the ZeroMQ REQ/REP socket halfway through a message.

This is authenticated transport/order integrity. It is **not** a proof that a malicious evaluator honestly performed the expensive FHE computation.

## C++ / Rust boundary

`src/fhe/gpu_fhe_backend.*` exposes:

```text
prepare_boolean_program_image_tfhe_cuda_client(...)
encrypt_boolean_program_chunk_tfhe_cuda_client(...)
TfheCudaServerSession(...)
TfheCudaServerSession::evaluate_chunk(...)
TfheCudaServerSession::finish(...)
decrypt_boolean_program_image_tfhe_cuda_client(...)
```

`TfheCudaPreparedSession` contains:

```text
client_key_blob       PRIVATE / client only
server_key_blob       evaluator-visible, once per session
encrypted_init_blob   evaluator-visible, once per session
instruction_count     public shape metadata
output_word_count     public shape metadata
```

The Rust sidecar still uses bounded Serde/bincode objects internally because TFHE-rs implements serialization for its key/ciphertext types. It adds fixed-int encoding, trailing-byte rejection, explicit magic/version checks, size/shape limits and panic containment at the C ABI.

Raw Serde remains a research scaffold. Before accepting hostile public jobs as a production service, move toward TFHE-rs safe/conformant serialization or an equally validated representation.

## Build and tests

Build the cloud target with the GPU preset:

```bash
cmake --preset gpu-fhe
cmake --build --preset gpu-fhe --target v0id-tfhe-cloud
```

Cheap network tests do not execute FHE:

```bash
cmake --build --preset gpu-fhe --target v0id-test-tfhe-cloud-codec
cmake --build --preset gpu-fhe --target v0id-test-curve-transport
```

The CURVE transport regression generates temporary in-memory keypairs, starts a local CURVE/ZAP server, connects an authorized client and requires the application-visible ZAP User-Id to match the allowlisted public key identity.

## Authenticated two-process TFHE smoke test

Generate evaluator and client transport keys once:

```bash
./build-gpu/v0id-tfhe-cloud keygen server
./build-gpu/v0id-tfhe-cloud keygen client-a
```

Evaluator terminal:

```bash
CUDA_MODULE_LOADING=EAGER \
./build-gpu/v0id-tfhe-cloud \
server gpu-node tcp://*:7788 \
server.secret client-a.public client-a 1
```

Client terminal:

```bash
CUDA_MODULE_LOADING=EAGER \
./build-gpu/v0id-tfhe-cloud \
client client-a tcp://127.0.0.1:7788 \
client-a.public client-a.secret server.public gpu-node
```

The smoke client intentionally uses one encrypted instruction so this checks the actual authenticated networked FHE boundary without turning every cloud regression into the full SHA3 stress run.

Expected trust properties are:

```text
client authenticates evaluator CURVE public key : YES
evaluator authorizes client CURVE public key     : YES
session bound to ZAP authenticated User-Id       : YES
channel encrypted by CURVE                       : YES
TFHE ClientKey sent                              : NO
plaintext program sent                           : NO
plaintext inputs sent                            : NO
```

## What is still deliberately missing

- execution-class padding for register/input/instruction/output buckets
- multi-worker scheduling and queue admission beyond local session cap/TTL
- key rotation/revocation/discovery beyond static CURVE public-key allowlists
- persistence or checkpoint/resume
- execution proof / malicious-evaluator soundness
- protocol-funded useful-compute issuance

The next cloud-infrastructure milestone is explicit execution classes, followed by multi-job scheduling. The separate research milestone remains execution soundness; neither should be conflated with ciphertext confidentiality or transport authentication.
