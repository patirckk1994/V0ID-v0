use super::*;

use bincode::Options;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::ptr;

const CLOUD_PROTOCOL_VERSION: u32 = 2;
const MAX_SERIALIZED_BLOB_BYTES: u64 = 512 * 1024 * 1024;
const MAX_INPUT_WORDS: usize = 4096;
const MAX_INSTRUCTIONS: usize = 65536;
const MAX_CHUNK_INSTRUCTIONS: usize = 64;
const MAX_OUTPUT_WORDS: usize = 64;

const CLIENT_KEY_MAGIC: [u8; 8] = *b"V0IDCK02";
const SERVER_KEY_MAGIC: [u8; 8] = *b"V0IDSK02";
const INIT_MAGIC: [u8; 8] = *b"V0IDCI02";
const CHUNK_MAGIC: [u8; 8] = *b"V0IDCC02";
const RESULT_MAGIC: [u8; 8] = *b"V0IDCR02";

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
struct EncryptedCloudInit {
    magic: [u8; 8],
    protocol_version: u32,
    register_count: u32,
    expected_instruction_count: u64,
    encrypted_zero: FheUint64,
    inputs: Vec<FheUint64>,
    output_registers: Vec<FheUint8>,
}

#[derive(Serialize, Deserialize)]
struct EncryptedInstructionChunk {
    magic: [u8; 8],
    protocol_version: u32,
    start_instruction: u64,
    total_instruction_count: u64,
    instructions: Vec<EncInstruction>,
}

#[derive(Serialize, Deserialize)]
struct EncryptedCloudResult {
    magic: [u8; 8],
    protocol_version: u32,
    completed_instruction_count: u64,
    outputs: Vec<FheUint64>,
}

pub struct V0idTfheServerSession {
    gpu_key: tfhe::CudaServerKey,
    registers: Vec<FheUint64>,
    inputs: Vec<FheUint64>,
    output_registers: Vec<FheUint8>,
    expected_instruction_count: usize,
    completed_instruction_count: usize,
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

fn decode_client_key(bytes: &[u8]) -> Result<ClientKey, String> {
    let envelope: ClientKeyEnvelope = decode(bytes, "TFHE client key envelope")?;
    require_version_and_magic(
        envelope.magic,
        CLIENT_KEY_MAGIC,
        envelope.protocol_version,
        "client key",
    )?;
    Ok(envelope.key)
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
pub unsafe extern "C" fn v0id_tfhe_cuda_client_prepare_session(
    register_count: usize,
    expected_instruction_count: usize,
    input_words: *const u64,
    input_word_count: usize,
    output_registers: *const u32,
    output_register_count: usize,
    client_key_out: *mut V0idTfheBlob,
    server_key_out: *mut V0idTfheBlob,
    encrypted_init_out: *mut V0idTfheBlob,
    progress_cb: ProgressFn,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if output_registers.is_null() {
            return Err("TFHE CUDA client prepare received null output selectors".into());
        }
        if input_word_count != 0 && input_words.is_null() {
            return Err("TFHE CUDA client prepare received null input words".into());
        }
        if client_key_out.is_null() || server_key_out.is_null() || encrypted_init_out.is_null() {
            return Err("TFHE CUDA client prepare received null blob output".into());
        }
        if register_count == 0 || register_count > 64 {
            return Err("TFHE CUDA register count must be in [1,64]".into());
        }
        if expected_instruction_count == 0 || expected_instruction_count > MAX_INSTRUCTIONS {
            return Err("TFHE CUDA instruction count outside cloud limit".into());
        }
        if input_word_count > MAX_INPUT_WORDS {
            return Err("TFHE CUDA input word count outside cloud limit".into());
        }
        if output_register_count == 0 || output_register_count > MAX_OUTPUT_WORDS {
            return Err("TFHE CUDA output count outside cloud limit".into());
        }

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

        let encryption_total = inputs.len() + outputs.len() + 1;
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
        let init = EncryptedCloudInit {
            magic: INIT_MAGIC,
            protocol_version: CLOUD_PROTOCOL_VERSION,
            register_count: register_count as u32,
            expected_instruction_count: expected_instruction_count as u64,
            encrypted_zero,
            inputs: encrypted_inputs,
            output_registers: encrypted_outputs,
        };

        *client_key_out = owned_blob(encode(&client_key_envelope, "TFHE client key envelope")?);
        *server_key_out = owned_blob(encode(&server_key_envelope, "TFHE server key envelope")?);
        *encrypted_init_out = owned_blob(encode(&init, "TFHE encrypted cloud init")?);
        Ok(())
    }));

    ffi_status(result)
}

#[no_mangle]
pub unsafe extern "C" fn v0id_tfhe_cuda_client_encrypt_chunk(
    client_key_data: *const u8,
    client_key_len: usize,
    instructions: *const V0idTfheInstruction,
    instruction_count: usize,
    start_instruction: usize,
    total_instruction_count: usize,
    encrypted_chunk_out: *mut V0idTfheBlob,
    progress_cb: ProgressFn,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if instructions.is_null() || encrypted_chunk_out.is_null() {
            return Err("TFHE CUDA chunk encryption received null required pointer".into());
        }
        if instruction_count == 0 || instruction_count > MAX_CHUNK_INSTRUCTIONS {
            return Err("TFHE CUDA chunk instruction count outside cloud limit".into());
        }
        if total_instruction_count == 0 || total_instruction_count > MAX_INSTRUCTIONS {
            return Err("TFHE CUDA total instruction count outside cloud limit".into());
        }
        if start_instruction > total_instruction_count ||
            instruction_count > total_instruction_count - start_instruction {
            return Err("TFHE CUDA chunk range exceeds total instruction count".into());
        }

        let client_key_bytes = input_blob(client_key_data, client_key_len, "TFHE client key blob")?;
        let client_key = decode_client_key(client_key_bytes)?;
        let clear = slice::from_raw_parts(instructions, instruction_count);

        progress(progress_cb, STAGE_ENCRYPT_INPUTS, start_instruction, total_instruction_count);
        let mut encrypted = Vec::with_capacity(clear.len());
        for (index, instruction) in clear.iter().enumerate() {
            encrypted.push(encrypt_instruction(instruction, &client_key));
            progress(
                progress_cb,
                STAGE_ENCRYPT_INPUTS,
                start_instruction + index + 1,
                total_instruction_count,
            );
        }

        let chunk = EncryptedInstructionChunk {
            magic: CHUNK_MAGIC,
            protocol_version: CLOUD_PROTOCOL_VERSION,
            start_instruction: start_instruction as u64,
            total_instruction_count: total_instruction_count as u64,
            instructions: encrypted,
        };
        *encrypted_chunk_out = owned_blob(encode(&chunk, "TFHE encrypted instruction chunk")?);
        Ok(())
    }));

    ffi_status(result)
}

#[no_mangle]
pub unsafe extern "C" fn v0id_tfhe_cuda_server_session_new(
    server_key_data: *const u8,
    server_key_len: usize,
    encrypted_init_data: *const u8,
    encrypted_init_len: usize,
    session_out: *mut *mut V0idTfheServerSession,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if session_out.is_null() {
            return Err("TFHE CUDA server session received null output handle".into());
        }
        *session_out = ptr::null_mut();

        let server_key_bytes = input_blob(server_key_data, server_key_len, "TFHE server key blob")?;
        let init_bytes = input_blob(encrypted_init_data, encrypted_init_len, "TFHE encrypted init blob")?;

        let server_key_envelope: ServerKeyEnvelope =
            decode(server_key_bytes, "TFHE server key envelope")?;
        require_version_and_magic(
            server_key_envelope.magic,
            SERVER_KEY_MAGIC,
            server_key_envelope.protocol_version,
            "server key",
        )?;
        let init: EncryptedCloudInit = decode(init_bytes, "TFHE encrypted cloud init")?;
        require_version_and_magic(init.magic, INIT_MAGIC, init.protocol_version, "cloud init")?;

        let register_count = init.register_count as usize;
        let expected_instruction_count = init.expected_instruction_count as usize;
        if register_count == 0 || register_count > 64 {
            return Err("TFHE cloud init register count outside [1,64]".into());
        }
        if expected_instruction_count == 0 || expected_instruction_count > MAX_INSTRUCTIONS {
            return Err("TFHE cloud init instruction count outside limit".into());
        }
        if init.inputs.len() > MAX_INPUT_WORDS {
            return Err("TFHE cloud init input count outside limit".into());
        }
        if init.output_registers.is_empty() || init.output_registers.len() > MAX_OUTPUT_WORDS {
            return Err("TFHE cloud init output count outside limit".into());
        }

        let gpu_key = server_key_envelope.key.decompress_to_gpu();
        set_server_key(gpu_key.clone());
        let registers = vec![init.encrypted_zero; register_count];

        let session = V0idTfheServerSession {
            gpu_key,
            registers,
            inputs: init.inputs,
            output_registers: init.output_registers,
            expected_instruction_count,
            completed_instruction_count: 0,
        };
        *session_out = Box::into_raw(Box::new(session));
        Ok(())
    }));

    ffi_status(result)
}

#[no_mangle]
pub unsafe extern "C" fn v0id_tfhe_cuda_server_session_eval_chunk(
    session: *mut V0idTfheServerSession,
    encrypted_chunk_data: *const u8,
    encrypted_chunk_len: usize,
    progress_cb: ProgressFn,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if session.is_null() {
            return Err("TFHE CUDA evaluator received null server session".into());
        }
        let session = &mut *session;
        let chunk_bytes = input_blob(
            encrypted_chunk_data,
            encrypted_chunk_len,
            "TFHE encrypted instruction chunk",
        )?;
        let chunk: EncryptedInstructionChunk =
            decode(chunk_bytes, "TFHE encrypted instruction chunk")?;
        require_version_and_magic(chunk.magic, CHUNK_MAGIC, chunk.protocol_version, "instruction chunk")?;

        if chunk.instructions.is_empty() || chunk.instructions.len() > MAX_CHUNK_INSTRUCTIONS {
            return Err("TFHE cloud chunk instruction count outside limit".into());
        }
        if chunk.total_instruction_count as usize != session.expected_instruction_count {
            return Err("TFHE cloud chunk total instruction count mismatches session".into());
        }
        if chunk.start_instruction as usize != session.completed_instruction_count {
            return Err("TFHE cloud chunk is replayed, reordered, or skips instructions".into());
        }
        if chunk.instructions.len() >
            session.expected_instruction_count - session.completed_instruction_count {
            return Err("TFHE cloud chunk exceeds remaining instruction budget".into());
        }

        set_server_key(session.gpu_key.clone());
        progress(
            progress_cb,
            STAGE_EXECUTE,
            session.completed_instruction_count,
            session.expected_instruction_count,
        );
        for instruction in &chunk.instructions {
            execute_instruction(instruction, &mut session.registers, &session.inputs);
            session.completed_instruction_count += 1;
            progress(
                progress_cb,
                STAGE_EXECUTE,
                session.completed_instruction_count,
                session.expected_instruction_count,
            );
        }
        Ok(())
    }));

    ffi_status(result)
}

#[no_mangle]
pub unsafe extern "C" fn v0id_tfhe_cuda_server_session_finish(
    session: *mut V0idTfheServerSession,
    encrypted_result_out: *mut V0idTfheBlob,
    progress_cb: ProgressFn,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if session.is_null() || encrypted_result_out.is_null() {
            return Err("TFHE CUDA server finish received null required pointer".into());
        }
        let session = &mut *session;
        if session.completed_instruction_count != session.expected_instruction_count {
            return Err("TFHE CUDA server finish called before all instruction chunks executed".into());
        }

        set_server_key(session.gpu_key.clone());
        progress(progress_cb, STAGE_OUTPUT, 0, session.output_registers.len());
        let mut outputs = Vec::with_capacity(session.output_registers.len());
        for (index, selector) in session.output_registers.iter().enumerate() {
            outputs.push(select_register(selector, &session.registers));
            progress(progress_cb, STAGE_OUTPUT, index + 1, session.output_registers.len());
        }

        let result = EncryptedCloudResult {
            magic: RESULT_MAGIC,
            protocol_version: CLOUD_PROTOCOL_VERSION,
            completed_instruction_count: session.completed_instruction_count as u64,
            outputs,
        };
        *encrypted_result_out = owned_blob(encode(&result, "TFHE encrypted cloud result")?);
        Ok(())
    }));

    ffi_status(result)
}

#[no_mangle]
pub unsafe extern "C" fn v0id_tfhe_cuda_server_session_free(
    session: *mut V0idTfheServerSession,
) {
    if session.is_null() {
        return;
    }
    tfhe::unset_server_key();
    drop(Box::from_raw(session));
}

#[no_mangle]
pub unsafe extern "C" fn v0id_tfhe_cuda_client_decrypt(
    client_key_data: *const u8,
    client_key_len: usize,
    encrypted_result_data: *const u8,
    encrypted_result_len: usize,
    expected_instruction_count: usize,
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
        if expected_instruction_count == 0 || expected_instruction_count > MAX_INSTRUCTIONS {
            return Err("TFHE CUDA client expected instruction count outside cloud limit".into());
        }

        let client_key_bytes = input_blob(client_key_data, client_key_len, "TFHE client key blob")?;
        let encrypted_result_bytes =
            input_blob(encrypted_result_data, encrypted_result_len, "TFHE encrypted result blob")?;

        let client_key = decode_client_key(client_key_bytes)?;
        let result: EncryptedCloudResult =
            decode(encrypted_result_bytes, "TFHE encrypted cloud result")?;
        require_version_and_magic(result.magic, RESULT_MAGIC, result.protocol_version, "cloud result")?;
        if result.completed_instruction_count as usize != expected_instruction_count {
            return Err("TFHE CUDA result instruction count mismatches requested execution".into());
        }
        if result.outputs.is_empty() || result.outputs.len() > MAX_OUTPUT_WORDS {
            return Err("TFHE CUDA result output count outside cloud limit".into());
        }
        if result.outputs.len() > output_word_capacity {
            return Err("TFHE CUDA client output buffer is too small".into());
        }

        let out = slice::from_raw_parts_mut(output_words, output_word_capacity);
        for (index, value) in result.outputs.iter().enumerate() {
            out[index] = value.decrypt(&client_key);
        }
        *output_word_count = result.outputs.len();
        Ok(())
    }));

    ffi_status(result)
}
