// Minimal V0ID MathVM guest. Build as bare wasm32 with no WASI/libc.
// The module contains only mathematical composition. Heavy/cryptographic
// primitives stay installed locally on the evaluator and are reached through
// one allowlisted V0ID host import.

typedef unsigned long long u64;

__attribute__((import_module("v0id_math"), import_name("primitive_u64")))
extern u64 primitive_u64(u64 primitive_tag,
                         u64 primitive_version,
                         u64 a,
                         u64 b,
                         u64 c,
                         u64 d);

#define V0ID_ADD_MOD_U64          0x00010001ULL
#define V0ID_MUL_MOD_U64          0x00010002ULL
#define V0ID_TOY_LWE_AFFINE_U64   0x7fff0001ULL

__attribute__((export_name("v0id_main")))
u64 v0id_main(void) {
    // 13 + 29 mod 97 = 42
    const u64 x = primitive_u64(V0ID_ADD_MOD_U64, 1, 13, 29, 97, 0);

    // Interface test only: 5*7 + 3 mod 12289 = 38.
    // This scalar relation is deliberately NOT a real LWE construction.
    const u64 toy = primitive_u64(V0ID_TOY_LWE_AFFINE_U64,
                                  1, 5, 7, 3, 12289);

    // 42 * 38 mod 65537 = 1596
    return primitive_u64(V0ID_MUL_MOD_U64, 1, x, toy, 65537, 0);
}
