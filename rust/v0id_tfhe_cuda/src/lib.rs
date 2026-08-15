use std::cmp::min;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::slice;
use std::sync::{Mutex, OnceLock};

use tfhe::prelude::*;
use tfhe::{
    set_server_key, ClientKey, CompressedServerKey, ConfigBuilder, FheUint16,
    FheUint64, FheUint8,
};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct V0idTfheInstruction {
    pub op: u32,
    pub dst: u32,
    pub a: u32,
    pub b: u32,
    pub c: u32,
    pub d: u32,
    pub e: u32,
    pub input_index: u32,
    pub rotate: u32,
    pub immediate: u64,
}

pub type ProgressFn = Option<extern "C" fn(stage: u32, current: u64, total: u64)>;

const STAGE_KEYGEN: u32 = 1;
const STAGE_ENCRYPT_INPUTS: u32 = 2;
const STAGE_EXECUTE: u32 = 3;
const STAGE_OUTPUT: u32 = 4;

static LAST_ERROR: OnceLock<Mutex<String>> = OnceLock::new();

fn set_error(message: impl Into<String>) {
    let lock = LAST_ERROR.get_or_init(|| Mutex::new(String::new()));
    if let Ok(mut out) = lock.lock() {
        *out = message.into();
    }
}

fn progress(cb: ProgressFn, stage: u32, current: usize, total: usize) {
    if let Some(cb) = cb {
        cb(stage, current as u64, total as u64);
    }
}

struct EncInstruction {
    op: FheUint8,
    dst: FheUint8,
    a: FheUint8,
    b: FheUint8,
    c: FheUint8,
    d: FheUint8,
    e: FheUint8,
    input_index: FheUint16,
    rotate: FheUint8,
    immediate: FheUint64,
}

fn encrypt_instruction(clear: &V0idTfheInstruction, ck: &ClientKey) -> EncInstruction {
    EncInstruction {
        op: FheUint8::encrypt(clear.op as u8, ck),
        dst: FheUint8::encrypt(clear.dst as u8, ck),
        a: FheUint8::encrypt(clear.a as u8, ck),
        b: FheUint8::encrypt(clear.b as u8, ck),
        c: FheUint8::encrypt(clear.c as u8, ck),
        d: FheUint8::encrypt(clear.d as u8, ck),
        e: FheUint8::encrypt(clear.e as u8, ck),
        input_index: FheUint16::encrypt(clear.input_index as u16, ck),
        rotate: FheUint8::encrypt(clear.rotate as u8, ck),
        immediate: FheUint64::encrypt(clear.immediate, ck),
    }
}

fn select_register(id: &FheUint8, registers: &[FheUint64]) -> FheUint64 {
    let mut out = FheUint64::try_encrypt_trivial(0u64).expect("trivial zero");
    for (index, value) in registers.iter().enumerate() {
        let selected = id.eq(index as u8);
        out = selected.select(value, &out);
    }
    out
}

fn select_input(id: &FheUint16, inputs: &[FheUint64]) -> FheUint64 {
    let mut out = FheUint64::try_encrypt_trivial(0u64).expect("trivial zero");
    for (index, value) in inputs.iter().enumerate() {
        let selected = id.eq(index as u16);
        out = selected.select(value, &out);
    }
    out
}

fn execute_instruction(ins: &EncInstruction,
                       registers: &mut [FheUint64],
                       inputs: &[FheUint64]) {
    let a = select_register(&ins.a, registers);
    let b = select_register(&ins.b, registers);
    let c = select_register(&ins.c, registers);
    let d = select_register(&ins.d, registers);
    let e = select_register(&ins.e, registers);
    let input = select_input(&ins.input_index, inputs);

    let xor2 = &a ^ &b;
    let xor5 = (((&a ^ &b) ^ &c) ^ &d) ^ &e;
    let xor_rot1 = &a ^ b.rotate_left(1u8);
    let encrypted_rotate: FheUint64 = ins.rotate.clone().cast_into();
    let rot_copy = a.rotate_left(&encrypted_rotate);
    let chi = &a ^ ((!&b) & &c);
    let xor_input = &a ^ &input;
    let xor_const = &a ^ &ins.immediate;

    let candidates = [
        xor2,
        xor5,
        xor_rot1,
        rot_copy,
        chi,
        xor_input,
        xor_const,
    ];

    let mut selected_value =
        FheUint64::try_encrypt_trivial(0u64).expect("trivial zero");
    let mut valid = ins.op.eq(0u8);
    selected_value = valid.select(&candidates[0], &selected_value);

    for op in 1u8..=6u8 {
        let selector = ins.op.eq(op);
        valid = &valid | &selector;
        selected_value = selector.select(&candidates[op as usize], &selected_value);
    }

    for (index, register) in registers.iter_mut().enumerate() {
        let destination = ins.dst.eq(index as u8);
        let write = &valid & &destination;
        *register = write.select(&selected_value, register);
    }
}

fn run_program(instructions: &[V0idTfheInstruction],
               register_count: usize,
               input_words: &[u64],
               output_registers: &[u32],
               output_words: &mut [u64],
               cb: ProgressFn) -> Result<(), String> {
    if register_count == 0 || register_count > 64 {
        return Err("TFHE CUDA register count must be in [1,64]".into());
    }
    if instructions.is_empty() {
        return Err("TFHE CUDA program has no instructions".into());
    }
    if output_registers.is_empty() || output_words.len() < output_registers.len() {
        return Err("TFHE CUDA output buffer is too small".into());
    }
    if output_registers.iter().any(|&r| r as usize >= register_count) {
        return Err("TFHE CUDA output register is out of range".into());
    }

    progress(cb, STAGE_KEYGEN, 0, 1);
    let config = ConfigBuilder::default().build();
    let client_key = ClientKey::generate(config);
    let compressed_server_key = CompressedServerKey::new(&client_key);
    let gpu_key = compressed_server_key.decompress_to_gpu();
    progress(cb, STAGE_KEYGEN, 1, 1);

    progress(cb, STAGE_ENCRYPT_INPUTS, 0, input_words.len());
    let encrypted_inputs: Vec<FheUint64> = input_words
        .iter()
        .enumerate()
        .map(|(i, &word)| {
            let encrypted = FheUint64::encrypt(word, &client_key);
            progress(cb, STAGE_ENCRYPT_INPUTS, i + 1, input_words.len());
            encrypted
        })
        .collect();

    let encrypted_zero = FheUint64::encrypt(0u64, &client_key);
    let mut registers = vec![encrypted_zero; register_count];

    // From this point forward the operations use the CUDA server key. Program
    // fields are encrypted client-side immediately before execution and the
    // evaluator never branches on their plaintext values.
    set_server_key(gpu_key);

    progress(cb, STAGE_EXECUTE, 0, instructions.len());
    for (index, clear) in instructions.iter().enumerate() {
        let encrypted = encrypt_instruction(clear, &client_key);
        execute_instruction(&encrypted, &mut registers, &encrypted_inputs);
        progress(cb, STAGE_EXECUTE, index + 1, instructions.len());
    }

    progress(cb, STAGE_OUTPUT, 0, output_registers.len());
    for (i, &reg) in output_registers.iter().enumerate() {
        // Keep output-register identity encrypted as well: encrypt the selector
        // and use the same oblivious register scan used by ordinary operands.
        let encrypted_reg = FheUint8::encrypt(reg as u8, &client_key);
        let selected = select_register(&encrypted_reg, &registers);
        output_words[i] = selected.decrypt(&client_key);
        progress(cb, STAGE_OUTPUT, i + 1, output_registers.len());
    }
    Ok(())
}

#[no_mangle]
pub unsafe extern "C" fn v0id_tfhe_cuda_run_program(
    instructions: *const V0idTfheInstruction,
    instruction_count: usize,
    register_count: usize,
    input_words: *const u64,
    input_word_count: usize,
    output_registers: *const u32,
    output_register_count: usize,
    output_words: *mut u64,
    output_word_capacity: usize,
    progress_cb: ProgressFn,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if instructions.is_null() || output_registers.is_null() || output_words.is_null() {
            return Err("TFHE CUDA bridge received a null required pointer".to_string());
        }
        if input_word_count != 0 && input_words.is_null() {
            return Err("TFHE CUDA bridge received null input words".to_string());
        }

        let instructions = slice::from_raw_parts(instructions, instruction_count);
        let inputs = if input_word_count == 0 {
            &[][..]
        } else {
            slice::from_raw_parts(input_words, input_word_count)
        };
        let outputs = slice::from_raw_parts(output_registers, output_register_count);
        let output_buffer = slice::from_raw_parts_mut(output_words, output_word_capacity);
        run_program(
            instructions,
            register_count,
            inputs,
            outputs,
            output_buffer,
            progress_cb,
        )
    }));

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
            set_error("TFHE CUDA backend panicked");
            2
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn v0id_tfhe_cuda_last_error(buffer: *mut u8, capacity: usize) -> usize {
    let message = LAST_ERROR
        .get_or_init(|| Mutex::new(String::new()))
        .lock()
        .map(|s| s.clone())
        .unwrap_or_else(|_| "TFHE CUDA error mutex poisoned".to_string());
    let bytes = message.as_bytes();
    if !buffer.is_null() && capacity != 0 {
        let count = min(bytes.len(), capacity.saturating_sub(1));
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), buffer, count);
        *buffer.add(count) = 0;
    }
    bytes.len()
}
