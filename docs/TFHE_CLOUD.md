# V0ID TFHE-rs CUDA cloud boundary

Status: first serialized trust-boundary scaffold. This is not yet a network protocol and is not production-audited cryptography.

## Goal

The CUDA stress path originally kept all roles inside one Rust function:

```text
plaintext program/input
    -> ClientKey generation
    -> encryption
    -> GPU evaluation
    -> decryption
```

That proved the encrypted VM and CUDA backend work, but it did not model an untrusted remote evaluator because the same function still owned the client secret key and plaintext program.

The current sidecar splits those roles into three serialized APIs:

```text
TRUSTED CLIENT
    v0id_tfhe_cuda_client_prepare
        plaintext compact program + input
        -> private serialized ClientKey
        -> serialized CompressedServerKey
        -> serialized encrypted job

UNTRUSTED EVALUATOR
    v0id_tfhe_cuda_server_evaluate
        CompressedServerKey + encrypted job
        -> decompress server key to GPU
        -> fixed-path encrypted VM execution
        -> serialized encrypted result

TRUSTED CLIENT
    v0id_tfhe_cuda_client_decrypt
        private ClientKey + encrypted result
        -> plaintext output words
```

The evaluator API has no `ClientKey` parameter and receives no plaintext instruction/image/input arguments.

## C++ boundary

`src/fhe/gpu_fhe_backend.*` exposes:

```text
prepare_boolean_program_image_tfhe_cuda_client(...)
evaluate_boolean_program_image_tfhe_cuda_server(...)
decrypt_boolean_program_image_tfhe_cuda_client(...)
```

`TfheCudaPreparedJob` contains:

```text
client_key_blob       PRIVATE / client only
server_key_blob       evaluator-visible
encrypted_job_blob    evaluator-visible
output_word_count     public shape metadata
```

The existing `evaluate_boolean_program_image_tfhe_cuda(...)` convenience function now traverses this same serialized split in one process. It is retained as a differential/stress helper, not as the production trust boundary.

## Serialization boundary

The Rust sidecar uses Serde/bincode because TFHE-rs implements serialization for its key and ciphertext types. V0ID additionally applies:

- a 2 GiB maximum serialized object size,
- fixed-int bincode encoding,
- trailing-byte rejection,
- explicit cloud protocol version checks,
- register-count/output-count validation,
- panic containment at every C ABI entry point.

This is only a first defensive envelope. Raw Serde does not provide TFHE-rs safe-serialization type/version/conformance validation. Before accepting hostile public jobs as a production service, the wire format should move to per-object TFHE safe serialization/conformance checks or an equally strong validated representation.

## Current execution shape

The serialized encrypted job currently contains the complete encrypted compact program image, encrypted inputs, encrypted zero, and encrypted output selectors. That is intentionally simple and proves the trust split, but it may be large.

The earlier local CUDA path encrypted one instruction immediately before execution. The cloud scaffold instead materializes the encrypted image so it can cross a process/network boundary. Streaming/chunked encrypted instruction transport can be added later if measurements justify it; it should not change the client/evaluator trust split.

## What is not implemented yet

- ZeroMQ transport for the TFHE blobs
- authenticated peer/channel binding
- evaluator session caching for the TFHE server key
- fixed execution-class padding (register/input/instruction/output buckets)
- chunked/streamed encrypted instruction jobs
- persistence or checkpoint/resume
- execution proof / protocol-funded useful-compute issuance

## Next minimal milestone

Reuse the existing remote-session pattern:

```text
INSTALL_TFHE_EVALUATOR_SESSION
    session id
    compressed server key

EXECUTE_TFHE_JOB
    session id
    job id
    execution class
    encrypted job blob

TFHE_JOB_RESULT
    session id
    job id
    encrypted result blob
```

The client key remains outside every evaluator message. The next network implementation should transport these already-defined blobs rather than reintroducing plaintext program handling in the server process.
