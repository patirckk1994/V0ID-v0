# V0ID TFHE-rs CUDA cloud boundary

Status: serialized, streamed trust-boundary scaffold. This is not yet a network protocol and is not production-audited cryptography.

## Goal

The CUDA stress path originally kept all roles inside one Rust function. The first cloud split separated client key generation/encryption, evaluator-only CUDA execution and client decryption, but serialized the complete encrypted SHA3 image as one object.

The owner runtime measurement for that first split was approximately:

```text
client key        31,316 bytes
server key       241,254,809 bytes
encrypted job  2,501,584,840 bytes
```

That proved the trust split but also proved a monolithic encrypted-program blob is the wrong transport shape.

The current v2 boundary keeps the server key and encrypted machine state resident in one evaluator session and streams bounded encrypted instruction chunks.

```text
TRUSTED CLIENT
    client_prepare_session
        plaintext inputs + public shape
        -> private ClientKey blob
        -> CompressedServerKey blob
        -> encrypted init blob

UNTRUSTED EVALUATOR
    server_session_new
        server key + encrypted init
        -> GPU server key cached in process
        -> encrypted registers/inputs kept resident

TRUSTED CLIENT
    client_encrypt_chunk
        private ClientKey + next plaintext instruction range
        -> encrypted instruction chunk

UNTRUSTED EVALUATOR
    server_session_eval_chunk
        encrypted chunk only
        -> reject replay/reorder/gaps
        -> advance resident encrypted registers

UNTRUSTED EVALUATOR
    server_session_finish
        -> encrypted output result

TRUSTED CLIENT
    client_decrypt
        private ClientKey + encrypted result
        -> plaintext output words
```

The evaluator APIs have no `ClientKey` parameter and receive no plaintext instruction, image or input arguments.

## Streaming shape

The C++ adapter currently uses 32 encrypted instructions per chunk. Rust accepts at most 64 instructions per chunk.

Every chunk binds:

```text
start_instruction
total_instruction_count
encrypted instructions[]
```

The evaluator requires `start_instruction == completed_instruction_count` and requires the advertised total to equal the session total. A repeated, reordered or skipped transport chunk therefore fails closed before execution. This is protocol ordering integrity, not a proof that a malicious evaluator honestly performed the expensive FHE work.

The evaluator session owns:

```text
CudaServerKey
encrypted registers
encrypted inputs
encrypted output selectors
expected instruction count
completed instruction count
```

The server key is decompressed to CUDA once when the session is installed. Before a chunk or final output selection, that cached GPU key is selected as the TFHE-rs thread-local server key.

## C++ boundary

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
encrypted_init_blob   evaluator-visible, once per job/session
instruction_count     public shape metadata
output_word_count     public shape metadata
```

The convenience `evaluate_boolean_program_image_tfhe_cuda(...)` now traverses this same streamed seam in one process.

## Serialization boundary

The Rust sidecar currently uses Serde/bincode because TFHE-rs implements serialization for its key and ciphertext types. V0ID adds:

- 512 MiB maximum per serialized object,
- fixed-int bincode encoding,
- trailing-byte rejection,
- explicit magic/version checks,
- register/input/instruction/output limits,
- maximum 64 instructions per transport chunk,
- contiguous chunk-order validation,
- panic containment at every C ABI entry point.

The per-object ceiling is intentionally back below the temporary 8 GiB monolithic-test value now that no job needs to fit in one blob.

Raw Serde remains a research scaffold. Before accepting hostile public jobs as a production service, the format should move toward TFHE-rs safe/conformant serialization or an equally validated representation.

## What is not implemented yet

- ZeroMQ transport for session/init/chunk/result messages
- authenticated peer/channel binding
- public execution-class padding (register/input/instruction/output buckets)
- bounded evaluator session table / expiry / quotas
- persistence or checkpoint/resume
- execution proof / protocol-funded useful-compute issuance

## Next minimal milestone

Carry the already-separated objects over the existing transport:

```text
INSTALL_TFHE_SESSION
    session id
    compressed server key
    encrypted init

TFHE_INSTRUCTION_CHUNK
    session id
    job id
    start instruction
    encrypted chunk

TFHE_JOB_FINISH
    session id
    job id

TFHE_JOB_RESULT
    session id
    job id
    encrypted result
```

The client key remains outside every evaluator message. Network transport should preserve this exact trust split rather than reintroducing plaintext program handling in the server process.
