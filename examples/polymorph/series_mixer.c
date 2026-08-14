#include <stdint.h>
#include <stddef.h>

// Demonstration-only local polymorphism guest.
//
// This mixer is deliberately NOT presented as a cryptographic PRF/KDF. Its job
// is to exercise the portable client-only Wasm ABI: private seed + semantic
// input + epoch -> bounded series/MorphSeed/private manifest. Production/research
// strategies can replace this module without changing ProgramMorpher.

#define SCRATCH_BYTES (600u * 1024u)
#define SERIES_BYTES 64u
#define MANIFEST_BYTES 16u
#define ENVELOPE_BYTES (44u + SERIES_BYTES + MANIFEST_BYTES)

static uint8_t scratch[SCRATCH_BYTES];

static uint64_t mix_byte(uint64_t state, uint8_t byte) {
    state ^= (uint64_t)byte + 0x9e3779b97f4a7c15ULL + (state << 6) + (state >> 2);
    state ^= state >> 12;
    state ^= state << 25;
    state ^= state >> 27;
    return state * 0x2545f4914f6cdd1dULL;
}

static uint8_t next_byte(uint64_t *state) {
    *state ^= *state >> 12;
    *state ^= *state << 25;
    *state ^= *state >> 27;
    *state *= 0x2545f4914f6cdd1dULL;
    return (uint8_t)(*state >> 56);
}

uint32_t v0id_buffer_base(void) {
    return (uint32_t)(uintptr_t)scratch;
}

int32_t v0id_polymorph(uint32_t seed_ptr,
                       uint32_t input_ptr,
                       uint32_t input_len,
                       uint64_t epoch,
                       uint32_t output_ptr,
                       uint32_t output_capacity) {
    if (output_capacity < ENVELOPE_BYTES)
        return -1;

    const uint8_t *seed = (const uint8_t *)(uintptr_t)seed_ptr;
    const uint8_t *input = (const uint8_t *)(uintptr_t)input_ptr;
    uint8_t *out = (uint8_t *)(uintptr_t)output_ptr;

    uint64_t state = 0x6a09e667f3bcc909ULL ^ epoch;
    for (uint32_t i = 0; i < 32; ++i)
        state = mix_byte(state, seed[i]);
    for (uint32_t i = 0; i < input_len; ++i)
        state = mix_byte(state, input[i]);

    out[0] = 'V';
    out[1] = '0';
    out[2] = 'P';
    out[3] = '1';

    // u32be lengths
    out[4] = 0;
    out[5] = 0;
    out[6] = 0;
    out[7] = SERIES_BYTES;
    out[8] = 0;
    out[9] = 0;
    out[10] = 0;
    out[11] = MANIFEST_BYTES;

    // 32-byte MorphSeed.
    for (uint32_t i = 0; i < 32; ++i)
        out[12 + i] = next_byte(&state);

    // Private series.
    for (uint32_t i = 0; i < SERIES_BYTES; ++i)
        out[44 + i] = next_byte(&state);

    // Client-only private manifest/provenance bytes.
    for (uint32_t i = 0; i < MANIFEST_BYTES; ++i)
        out[44 + SERIES_BYTES + i] = next_byte(&state);

    return (int32_t)ENVELOPE_BYTES;
}
