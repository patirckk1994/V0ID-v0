# V0ID

Tiny research prototype for an exact encrypted, runtime-programmable Turing-machine interpreter.

Current V0.1:

- **Encryption-lite:** OpenFHE BinFHE (`STD128`) exact Boolean gates; no approximate arithmetic.
- **Encrypted program:** transition semantics are encrypted as one-hot next-state selectors plus encrypted write/move selectors. Two different programs with the same public shape execute through the same evaluator control flow.
- **UTM-lite:** one fixed interpreter executes encrypted transition tables over encrypted one-hot state, encrypted one-hot head and encrypted tape. The demo is bounded to 8 cells, so this is a bounded universal-interpreter prototype rather than a claim of an infinite physical tape.
- **Fixed work schedule:** the demo executes a public fixed number of interpreter rounds rather than terminating based on secret program semantics.
- **Remap-lite:** OpenSSL 3 `KMAC-256` derives an epoch-specific exact bijection from logical tape cells to physical slots. The demo changes epochs mid-computation by moving ciphertexts only; it never decrypts the intermediate tape.
- **P2P-lite:** physical slots are ready to be partitioned into peer/local coordinates; socket transport and OpenFHE ciphertext serialization are deliberately deferred until the local encrypted machine semantics are stable.

Correctness and exact encrypted state semantics are invariants; speed and memory are expendable. Experimental research code, not audited production cryptography.

## What is hidden vs public

The current local prototype encrypts:

- tape bits,
- active state,
- head position,
- transition next-state choice,
- transition write bit,
- transition movement choice.

The evaluator still learns public shape information such as tape length, number of states, binary alphabet, and fixed round count. The local demo also performs client-side encryption and final decryption in one process; a future network version should serialize only the encrypted program/state to an evaluator that never receives the secret key.

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

The demo encrypts `00001101` (13), then encrypts two different transition programs with the same public shape:

1. binary increment,
2. binary decrement.

Both run through the same fixed evaluator path for four rounds, with a ciphertext-only tape remap after the first round. Only the final tape is decrypted.

Expected logical results:

```text
input           : 00001101
encrypted inc output: 00001110
encrypted dec output: 00001100
OK: same fixed evaluator executed two encrypted transition tables
    + exact encrypted state/tape semantics
    + ciphertext-only epoch remap
```

## Next research milestones

Likely next steps:

- encrypted halted/no-op semantics with a fixed public work budget,
- canonical encrypted machine-image fingerprint/self-check,
- ciphertext serialization,
- mapping physical slots to `(peer_id, local_slot)`,
- probabilistic audit/integrity experiments before heavier verifiable-computation machinery.

If CMake/compiler complains about a missing package, target, include path, or OpenFHE API, report the exact error and installation layout. V0 intentionally uses installed libraries instead of vendoring them.
