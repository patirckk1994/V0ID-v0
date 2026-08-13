# V0ID

Tiny research prototype for an exact encrypted, runtime-programmable Turing-machine interpreter.

Current V0:

- **Encryption-lite:** OpenFHE BinFHE (`STD128`) exact Boolean gates; no approximate arithmetic.
- **UTM-lite:** one interpreter executes a runtime-supplied transition table over encrypted one-hot state, encrypted one-hot head and encrypted tape. The demo is bounded to 8 cells, so this is a bounded universal-interpreter prototype rather than a claim of an infinite physical tape.
- **Remap-lite:** OpenSSL 3 `KMAC-256` derives an epoch-specific exact bijection from logical tape cells to physical slots. The demo changes epochs mid-computation by moving ciphertexts only; it never decrypts the intermediate tape.
- **P2P-lite:** physical slots are ready to be partitioned into peer/local coordinates; socket transport and OpenFHE ciphertext serialization are deliberately deferred until this local encrypted machine builds and runs.

Correctness and exact encrypted state semantics are invariants; speed and memory are expendable. Experimental research code, not audited production cryptography.

## Dependencies

- C++20 compiler
- CMake
- OpenFHE installed with its CMake package (`OpenFHEConfig.cmake`)
- OpenSSL >= 3 with `KMAC-256`

## Build

```sh
cmake -S . -B build
cmake --build build -j
./build/v0id
```

The demo encrypts `00001101` (13), executes a runtime-loaded binary-increment transition program, remaps the physical encrypted tape between the two useful machine steps, and decrypts only the final tape. Expected:

```text
input : 00001101
output: 00001110
OK: exact encrypted transition + mid-run remap without intermediate decryption
```

If CMake/compiler complains about a missing package, target, include path, or OpenFHE API, report the exact error and installation layout. V0 intentionally uses installed libraries instead of vendoring them.
