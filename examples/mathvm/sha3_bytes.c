typedef unsigned long long u64;
typedef unsigned int u32;
typedef unsigned char u8;

#define V0ID_PRIMITIVE_SHA3_256_BYTES 0x00020001ULL

__attribute__((import_module("v0id_math"), import_name("primitive_bytes")))
extern int primitive_bytes(u64 tag,
                           u64 version,
                           const u8* input,
                           u32 input_len,
                           u8* output,
                           u32 output_capacity);

__attribute__((export_name("v0id_main")))
u64 v0id_main(void) {
    static const u8 input[3] = {'a', 'b', 'c'};
    static const u8 expected[32] = {
        0x3a, 0x98, 0x5d, 0xa7, 0x4f, 0xe2, 0x25, 0xb2,
        0x04, 0x5c, 0x17, 0x2d, 0x6b, 0xd3, 0x90, 0xbd,
        0x85, 0x5f, 0x08, 0x6e, 0x3e, 0x9d, 0x52, 0x5b,
        0x46, 0xbf, 0xe2, 0x45, 0x11, 0x43, 0x15, 0x32,
    };

    u8 digest[32];
    const int written = primitive_bytes(
        V0ID_PRIMITIVE_SHA3_256_BYTES,
        1,
        input,
        (u32)sizeof(input),
        digest,
        (u32)sizeof(digest));
    if (written != (int)sizeof(digest))
        return 0;

    u8 difference = 0;
    for (u32 i = 0; i < (u32)sizeof(digest); ++i)
        difference |= (u8)(digest[i] ^ expected[i]);

    return difference == 0 ? (u64)sizeof(digest) : 0;
}
