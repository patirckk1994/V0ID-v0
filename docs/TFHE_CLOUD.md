# V0ID TFHE-rs CUDA cloud boundary

Status: streamed TFHE trust split plus a bounded ZeroMQ multipart protocol scaffold. This is not yet an authenticated public service and is not production-audited cryptography.

## Goal

The CUDA stress path originally kept all roles inside one Rust function. The first cloud split separated client key generation/encryption, evaluator-only CUDA execution and client decryption, but serialized the complete encrypted SHA3 image as one object.

The owner runtime measurement for that first split was approximately:

```text
client key        31,316 bytes
server key       241,254,809 bytes
encrypted job  2,501,584,840 bytes
```

That proved the trust split but also proved a monolithic encrypted-program blob is the wrong transport shape.

The current boundary keeps the server key and encrypted machine state resident in one evaluator session and streams bounded encrypted instruction chunks.

```text
TRUSTED CLIENT
    prepare session
        plaintext inputs + public shape
        -> private ClientKey blob
        -> CompressedServerKey blob
        -> encrypted init blob

ZERO MQ MULTIPART
    frame 0: small V0ID envelope + typed TFHE metadata
    frame N: bounded opaque key/ciphertext objects

UNTRUSTED EVALUATOR
    install session
        server key + encrypted init
        -> GPU server key cached in process
        -> encrypted registers/inputs kept resident

TRUSTED CLIENT
    encrypt next instruction range
        private ClientKey + plaintext instruction range
        -> encrypted instruction chunk

UNTRUSTED EVALUATOR
    evaluate chunk
        encrypted chunk only
        -> reject wrong session/job/epoch/order/count
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

The server binds an installed session to the request `peer_id`, `job_id` and `epoch`, and requires every subsequent chunk/finish request to match. `peer_id` is currently only protocol metadata: without channel authentication it is not proof of remote identity.

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
start_instruction == completed_instruction_count
total_instruction_count == installed total
chunk_count <= remaining instructions
```

The Rust encrypted-chunk envelope independently requires contiguous ordering as well. A repeated, reordered, skipped or over-budget transport chunk therefore fails before the session advances.

This is transport/order integrity. It is **not** a proof that a malicious evaluator honestly performed the expensive FHE computation.

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

## Build and local two-process smoke test

Build the cloud target with the GPU preset:

```bash
cmake --preset gpu-fhe
cmake --build --preset gpu-fhe --target v0id-tfhe-cloud
```

Run the cheap codec-only regression test:

```bash
cmake --build --preset gpu-fhe --target v0id-test-tfhe-cloud-codec
```

Then use two terminals for the real one-instruction TFHE network smoke test.

Evaluator terminal:

```bash
CUDA_MODULE_LOADING=EAGER \
./build-gpu/v0id-tfhe-cloud server gpu-node tcp://*:7788 1
```

Client terminal:

```bash
CUDA_MODULE_LOADING=EAGER \
./build-gpu/v0id-tfhe-cloud client client-a tcp://127.0.0.1:7788
```

The smoke client intentionally uses one encrypted instruction so this checks the actual networked FHE boundary without turning every cloud regression into the full SHA3 stress run.

## What is still deliberately missing

- authenticated peer/channel binding (use a standard authenticated transport; do not invent a custom TLS replacement)
- execution-class padding for register/input/instruction/output buckets
- persistence or checkpoint/resume
- multi-worker scheduling and admission control beyond the local session cap/TTL
- execution proof / malicious-evaluator soundness
- protocol-funded useful-compute issuance

The next cloud-security milestone should be authenticated channel/session binding plus explicit execution classes. The next research milestone remains execution soundness; neither should be conflated with ciphertext confidentiality.
