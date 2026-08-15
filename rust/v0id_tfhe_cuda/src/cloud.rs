use super::*;

use bincode::Options;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::ptr;

const CLOUD_PROTOCOL_VERSION: u32 = 1;
const MAX_SERIALIZED_BLOB_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_INPUT_WORDS: usize = 4096;
const MAX_INSTRUCTIONS: usize = 65536;
const MAX_OUTPUT_WORDS: usize = 64;

const CLIENT_KEY_MAGIC: [u8; 8] = *b"V0IDCK01";
const SERVER_KEY_MAGIC: [u8; 8] = *b"V0IDSK01";
const JOB_MAGIC: [u8; 8] = *b"V0IDCJ01";
const RESULT_MAGIC: [u8; 8] = *b"V0IDCR01";

#[repr(C)]
pub struct V0idTfheBlob {
    pub data: *mut u8,
    pub len: usize,
}

#[derive(Serialize, Deserialize)]
struct ClientKeyEnvelope {
    magic: [u8; 8],
    protocol_version: u32,
    key: ClientKey,
}

#[derive(Serialize, Deserialize)]
struct ServerKeyEnvelope {
    magic: [u8; 8],
    protocol_version: u32,
    key: CompressedServerKey,
}

#[derive(Serialize, Deserialize)]
struct EncryptedCloudJob {
    magic: [u8; 8],
    protocol_version: u32,
    register_count: u32,
    encrypted_zero: FheUint64,
    inputs: Vec<FheUint64>,
    instructions: Vec<EncInstruction>,
    output_registers: Vec<FheUint8>,
}

#[derive(Serialize, Deserialize)]
struct EncryptedCloudResult {
    magic: [u8; 8],
    protocol_version: u32,
    outputs: Vec<FheUint64>,
}

fn codec() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_SERIALIZED_BLOB_BYTES)
        .reject_trailing_bytes()
}

fn encode<T: Serialize>(value: &T, what: &str) -> Result<Vec<u8>, String> {
    codec()
        .serialize(value)
        .map_err(|e| format!("failed to serialize {what}: {e}"))
}

fn decode<T: DeserializeOwned>(bytes: &[u8], what: &str) -> Result<T, String> {
    if bytes.len() as u64 > MAX_SERIALIZED_BLOB_BYTES {
        return Err(format!("{what} exceeds V0ID TFHE cloud blob limit"));
    }
    codec()
        .deserialize(bytes)
        .map_err(|e| format!("failed to deserialize {what}: {e}"))
}

fn owned_blob(bytes: Vec<u8>) -> V0idTfheBlob {
    if bytes.is_empty() {
        return V0idTfheBlob {
            data: ptr::null_mut(),
            len: 0,
        };
    }

    let boxed = bytes.into_boxed_slice();
    let len = boxed.len();
    let raw = Box::into_raw(boxed);
    V0idTfheBlob {
        data: raw as *mut u8,
        len,
    }
}

unsafe fn input_blob<'a>(data: *const u8, len: usize, what: &str) -> Result<&'a [u8], String> {
    if len == 0 {
        return Err(format!("{what} is empty"));
    }
    if data.is_null() {
        return Err(format!("{what} pointer is null"));
    }
    if len as u64 > MAX_SERIALIZED_BLOB_BYTES {
        return Err(format!("{what} exceeds V0ID TFHE cloud blob limit"));
    }
    Ok(slice::from_raw_parts(data, len))
}

fn require_version_and_magic(
    actual_magic: [u8; 8],
    expected_magic: [u8; 8],
    version: u32,
    what: &str,
) -> Result<(), String> {
    if actual_magic != expected_magic {
        return Err(format!("bad V0ID TFHE {what} magic"));
    }
    if version != CLOUD_PROTOCOL_VERSION {
        return Err(format!("unsupported V0ID TFHE {what} version"));
    }
    Ok(())
}

fn ffi_status(result: std::thread::Result<Result<(), String>>) -> i32 {
    match result {
        Ok(Ok(())) => {
            set_error("");
            0
        }
        Ok(Err(message)) => {
            set_error(message);
            1
        }
        Err(_) => {
            set_error("TFHE CUDA cloud boundary panicked");
            2
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn v0id_tfhe_cuda_blob_free(blob: *mut V0idTfheBlob) {
    if blob.is_null() {
        return;
    }

    let blob = &mut *blob;
    if !blob.data.is_null() && blob.len != 0 {
        let slice_ptr = ptr::slice_from_raw_parts_mut(blob.data, blob.len);
        drop(Box::from_raw(slice_ptr));
    }
    blob.data = ptr::null_mut();
    blob.len = 0;
}

#[no_mangle]
pub unsafe extern "C" fn v0id_tfhe_cuda_client_prepare(
    instructions: *const V0idTfheInstruction,
    instruction_count: usize,
    register_count: usize,
    input_words: *const u64,
    input_word_count: usize,
    output_registers: *const u32,
    output_register_count: usize,
    client_key_out: *mut V0idTfheBlob,
    server_key_out: *mut V0idTfheBlob,
    encrypted_job_out: *mut V0idTfheBlob,
    progress_cb: ProgressFn,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if instructions.is_null() || output_registers.is_null() {
            return Err("TFHE CUDA client prepare received a null required pointer".into());
        }
        if input_word_count != 0 && input_words.is_null() {
            return Err("TFHE CUDA client prepare received null input words".into());
        }
        if client_key_out.is_null() || server_key_out.is_null() || encrypted_job_out.is_null() {
            return Err("TFHE CUDA client prepare received null blob output".into());
        }
        if register_count == 0 || register_count > 64 {
            return Err("TFHE CUDA register count must be in [1,64]".into());
        }
        if instruction_count == 0 || instruction_count > MAX_INSTRUCTIONS {
            return Err("TFHE CUDA instruction count outside cloud limit".into());
        }
        if input_word_count > MAX_INPUT_WORDS {
            return Err("TFHE CUDA input word count outside cloud limit".into());
        }
        if output_register_count == 0 || output_register_count > MAX_OUTPUT_WORDS {
            return Err("TFHE CUDA output count outside cloud limit".into());
        }

        let instructions = slice::from_raw_parts(instructions, instruction_count);
        let inputs = if input_word_count == 0 {
            &[][..]
        } else {
            slice::from_raw_parts(input_words, input_word_count)
        };
        let outputs = slice::from_raw_parts(output_registers, output_register_count);
        if outputs.iter().any(|&r| r as usize >= register_count) {
            return Err("TFHE CUDA output register is out of range".into());
        }

        progress(progress_cb, STAGE_KEYGEN, 0, 1);
        let config = ConfigBuilder::default().build();
        let client_key = ClientKey::generate(config);
        let compressed_server_key = CompressedServerKey::new(&client_key);
        progress(progress_cb, STAGE_KEYGEN, 1, 1);

        let encryption_total = inputs.len() + instructions.len() + outputs.len() + 1;
        let mut encrypted_count = 0usize;
        progress(progress_cb, STAGE_ENCRYPT_INPUTS, 0, encryption_total);

        let mut encrypted_inputs = Vec::with_capacity(inputs.len());
        for &word in inputs {
            encrypted_inputs.push(FheUint64::encrypt(word, &client_key));
            encrypted_count += 1;
            progress(progress_cb, STAGE_ENCRYPT_INPUTS, encrypted_count, encryption_total);
        }

        let encrypted_zero = FheUint64::encrypt(0u64, &client_key);
        encrypted_count += 1;
        progress(progress_cb, STAGE_ENCRYPT_INPUTS, encrypted_count, encryption_total);

        let mut encrypted_instructions = Vec::with_capacity(instructions.len());
        for clear in instructions {
            encrypted_instructions.push(encrypt_instruction(clear, &client_key));
            encrypted_count += 1;
            progress(progress_cb, STAGE_ENCRYPT_INPUTS, encrypted_count, encryption_total);
        }

        let mut encrypted_outputs = Vec::with_capacity(outputs.len());
        for &reg in outputs {
            encrypted_outputs.push(FheUint8::encrypt(reg as u8, &client_key));
            encrypted_count += 1;
            progress(progress_cb, STAGE_ENCRYPT_INPUTS, encrypted_count, encryption_total);
        }

        let client_key_envelope = ClientKeyEnvelope {
            magic: CLIENT_KEY_MAGIC,
            protocol_version: CLOUD_PROTOCOL_VERSION,
            key: client_key,
        };
        let server_key_envelope = ServerKeyEnvelope {
            magic: SERVER_KEY_MAGIC,
            protocol_version: CLOUD_PROTOCOL_VERSION,
            key: compressed_server_key,
        };
        let job = EncryptedCloudJob {
            magic: JOB_MAGIC,
            protocol_version: CLOUD_PROTOCOL_VERSION,
            register_count: register_count as u32,
            encrypted_zero,
            inputs: encrypted_inputs,
            instructions: encrypted_instructions,
            output_registers: encrypted_outputs,
        };

        let client_key_bytes = encode(&client_key_envelope, "TFHE client key envelope")?;
        let server_key_bytes = encode(&server_key_envelope, "TFHE server key envelope")?;
        let encrypted_job_bytes = encode(&job, "TFHE encrypted cloud job")?;

        *client_key_out = owned_blob(client_key_bytes);
        *server_key_out = owned_blob(server_key_bytes);
        *encrypted_job_out = owned_blob(encrypted_job_bytes);
        Ok(())
    }));

    ffi_status(result)
}

#[no_mangle]
pub unsafe extern "C" fn v0id_tfhe_cuda_server_evaluate(
    server_key_data: *const u8,
    server_key_len: usize,
    encrypted_job_data: *const u8,
    encrypted_job_len: usize,
    encrypted_result_out: *mut V0idTfheBlob,
    progress_cb: ProgressFn,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if encrypted_result_out.is_null() {
            return Err("TFHE CUDA server evaluate received null result output".into());
        }

        let server_key_bytes = input_blob(server_key_data, server_key_len, "TFHE server key blob")?;
        let encrypted_job_bytes =
            input_blob(encrypted_job_data, encrypted_job_len, "TFHE encrypted job blob")?;

        let server_key_envelope: ServerKeyEnvelope =
            decode(server_key_bytes, "TFHE server key envelope")?;
        require_version_and_magic(
            server_key_envelope.magic,
            SERVER_KEY_MAGIC,
            server_key_envelope.protocol_version,
            "server key",
        )?;
        let job: EncryptedCloudJob = decode(encrypted_job_bytes, "TFHE encrypted cloud job")?;
        require_version_and_magic(job.magic, JOB_MAGIC, job.protocol_version, "cloud job")?;

        let register_count = job.register_count as usize;
        if register_count == 0 || register_count > 64 {
            return Err("TFHE cloud job register count outside [1,64]".into());
        }
        if job.inputs.len() > MAX_INPUT_WORDS {
            return Err("TFHE cloud job input count outside limit".into());
        }
        if job.instructions.is_empty() || job.instructions.len() > MAX_INSTRUCTIONS {
            return Err("TFHE cloud job instruction count outside limit".into());
        }
        if job.output_registers.is_empty() || job.output_registers.len() > MAX_OUTPUT_WORDS {
            return Err("TFHE cloud job output count outside limit".into());
        }

        // The evaluator has only the public/evaluation key material. No ClientKey
        // is deserialized or accepted by this API. Conversion to the GPU server
        // key happens entirely on the evaluator side.
        let gpu_key = server_key_envelope.key.decompress_to_gpu();
        set_server_key(gpu_key);

        let mut registers = vec![job.encrypted_zero; register_count];
        progress(progress_cb, STAGE_EXECUTE, 0, job.instructions.len());
        for (index, instruction) in job.instructions.iter().enumerate() {
            execute_instruction(instruction, &mut registers, &job.inputs);
            progress(progress_cb, STAGE_EXECUTE, index + 1, job.instructions.len());
        }

        progress(progress_cb, STAGE_OUTPUT, 0, job.output_registers.len());
        let mut outputs = Vec::with_capacity(job.output_registers.len());
        for (index, selector) in job.output_registers.iter().enumerate() {
            outputs.push(select_register(selector, &registers));
            progress(progress_cb, STAGE_OUTPUT, index + 1, job.output_registers.len());
        }

        let result = EncryptedCloudResult {
            magic: RESULT_MAGIC,
            protocol_version: CLOUD_PROTOCOL_VERSION,
            outputs,
        };
        *encrypted_result_out = owned_blob(encode(&result, "TFHE encrypted cloud result")?);
        Ok(())
    }));

    ffi_status(result)
}

#[no_mangle]
pub unsafe extern "C" fn v0id_tfhe_cuda_client_decrypt(
    client_key_data: *const u8,
    client_key_len: usize,
    encrypted_result_data: *const u8,
    encrypted_result_len: usize,
    output_words: *mut u64,
    output_word_capacity: usize,
    output_word_count: *mut usize,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if output_words.is_null() || output_word_count.is_null() {
            return Err("TFHE CUDA client decrypt received null output pointer".into());
        }
        if output_word_capacity == 0 || output_word_capacity > MAX_OUTPUT_WORDS {
            return Err("TFHE CUDA client output capacity outside cloud limit".into());
        }

        let client_key_bytes = input_blob(client_key_data, client_key_len, "TFHE client key blob")?;
        let encrypted_result_bytes =
            input_blob(encrypted_result_data, encrypted_result_len, "TFHE encrypted result blob")?;

        let client_key_envelope: ClientKeyEnvelope =
            decode(client_key_bytes, "TFHE client key envelope")?;
        require_version_and_magic(
            client_key_envelope.magic,
            CLIENT_KEY_MAGIC,
            client_key_envelope.protocol_version,
            "client key",
        )?;
        let result: EncryptedCloudResult =
            decode(encrypted_result_bytes, "TFHE encrypted cloud result")?;
        require_version_and_magic(result.magic, RESULT_MAGIC, result.protocol_version, "cloud result")?;
        if result.outputs.is_empty() || result.outputs.len() > MAX_OUTPUT_WORDS {
            return Err("TFHE CUDA result output count outside cloud limit".into());
        }
        if result.outputs.len() > output_word_capacity {
            return Err("TFHE CUDA client output buffer is too small".into());
        }

        let out = slice::from_raw_parts_mut(output_words, output_word_capacity);
        for (index, value) in result.outputs.iter().enumerate() {
            out[index] = value.decrypt(&client_key_envelope.key);
        }
        *output_word_count = result.outputs.len();
        Ok(())
    }));

    ffi_status(result)
}
