# V0ID client-only Wasm polymorphism

V0.4.5 adds a second implementation of `PolymorphicSeriesGenerator`: `WasmSeriesGenerator`.

Its purpose is narrow. A client may run a private, locally chosen WebAssembly strategy to derive bounded polymorphism material without recompiling V0ID. The Wasm is **not** transmitted to the evaluator and it does **not** receive or rewrite the machine transition table.

```text
semantic input + private SeriesSeed + epoch
                    |
                    v
             polymorphism.wasm
          (local WAMR sandbox only)
                    |
                    v
      series + MorphSeed + private manifest
                    |
                    v
           trusted C++ validation
                    |
                    v
              ProgramMorpher
                    |
                    v
             morphed machine
                    |
                    v
                  BinFHE
```

This keeps the security boundary explicit:

- Wasm chooses/derives private morph material.
- trusted C++ owns state permutation, dummy-state insertion, transition rewriting and integrity-placement metadata;
- the remote evaluator receives neither the Wasm module, `SeriesSeed`, derived series, `MorphSeed` nor `MorphManifest`.

## Why the Wasm does not rewrite `Program` directly

V0.4.5 deliberately does **not** pass a serialized transition table into arbitrary Wasm and accept a replacement machine back.

That would force the first plugin ABI to validate every semantic invariant of an arbitrary transformed machine. The narrower interface already gives us programmable polymorphism strategies while preserving one trusted implementation of the transformation itself.

If a future experiment demonstrates a reason to move graph rewriting into Wasm, that can be added behind a separate validator and ABI version rather than silently widening this one.

## Sandbox profile

The local polymorphism runtime reuses the pinned WAMR 2.4.0 classic interpreter build but has a stricter host surface than MathVM:

```text
Wasm imports             forbidden (zero imports)
WASI                     unavailable
filesystem/network       unavailable
clock/random host API    unavailable
native providers         unavailable
start function           forbidden
AOT/JIT                  unavailable
threads/shared memory    unavailable
instruction metering     enabled
host-managed app heap    disabled
```

The seed is the plugin's private entropy input. There is intentionally no host RNG import: equal `(module, seed, input, epoch)` should produce equal derived material so the layer is reproducible and testable.

V0ID pre-validates the raw Wasm module before loading it. The module must declare exactly one ordinary Wasm32 linear memory with an explicit maximum at or below the configured page cap. Imported memory, memory64/shared forms and start functions are rejected.

## Guest ABI

A module must export:

```text
v0id_buffer_base() -> i32
```

The returned offset identifies a guest-reserved scratch region. V0ID validates the complete seed/input/output layout against the instantiated linear memory before copying anything.

The module must also export:

```text
v0id_polymorph(
    seed_ptr:i32,
    input_ptr:i32,
    input_len:i32,
    epoch:i64,
    output_ptr:i32,
    output_capacity:i32
) -> i32 written
```

V0ID places the 32-byte `SeriesSeed` and semantic input into non-overlapping guest memory, zeroes the bounded output region, executes the function under an instruction limit and then validates the returned byte count and envelope.

## V0P1 output envelope

The guest returns exactly:

```text
4 bytes   "V0P1"
4 bytes   u32be series_length
4 bytes   u32be private_manifest_length
32 bytes  MorphSeed
N bytes   private series
M bytes   private manifest
```

The host requires an exact envelope length, a non-empty bounded series and a bounded private manifest before constructing `DerivedSeries`.

The envelope never becomes a network object in V0.4.5. It is a private host/guest boundary only.

## Default local limits

```text
Wasm module              <= 1 MiB
linear memory            <= 16 pages / 1 MiB
Wasm stack               <= 64 KiB
WAMR runtime pool        <= 16 MiB
Wasm instructions        <= 500,000
semantic input           <= 256 KiB
V0P1 output              <= 256 KiB
private series           <= 128 KiB
private manifest         <= 64 KiB
host-managed app heap    disabled
```

The configured worst-case `SeriesSeed + input + output` layout must fit inside the linear-memory cap.

## Self-contained test gate

`v0id-wasm-polymorph-tests` builds its own tiny Wasm binaries in memory, so it does not require a wasm32 compiler. The suite covers:

- deterministic same seed/input/epoch;
- changed epoch changes derived material;
- changed semantic input changes the private series;
- canonical V0P1 parsing;
- a Wasm-derived `MorphSeed` passed through trusted `ProgramMorpher` preserves the demo program's semantics;
- all host imports rejected;
- malformed output rejected;
- infinite guest stopped by the instruction budget;
- excessive memory declaration rejected;
- excessive semantic input rejected.

Build/run:

```sh
cmake -S . -B build
cmake --build build -j --target v0id-wasm-polymorph-tests
./build/v0id-wasm-polymorph-tests
```

**Status:** implementation added in V0.4.5; local runtime verification is pending until this gate is run on the development host.

## External Wasm guest

`examples/polymorph/series_mixer.c` is a deliberately simple deterministic demonstration mixer. It is **not** claimed to be a cryptographic PRF/KDF or a new security primitive. It exists to prove that an independently compiled external Wasm strategy can drive the local polymorphism ABI.

Compile:

```sh
clang --target=wasm32 -O2 -nostdlib \
  -Wl,--no-entry \
  -Wl,--export=v0id_buffer_base \
  -Wl,--export=v0id_polymorph \
  -Wl,--initial-memory=1048576 \
  -Wl,--max-memory=1048576 \
  examples/polymorph/series_mixer.c \
  -o build/series_mixer.wasm
```

Run it through the local demo:

```sh
cmake --build build -j --target v0id-wasm-polymorph-demo
./build/v0id-wasm-polymorph-demo build/series_mixer.wasm
```

The demo derives a private series/MorphSeed, hands the seed to trusted `ProgramMorpher`, and checks that the morphed four-state increment machine still maps `13 -> 14` in plaintext.

## Non-claims

This layer provides sandboxed programmability for client-side polymorphism. It does not establish that polymorphism improves security, that a particular plugin is cryptographically strong, or that structural role inference is prevented.

Those remain measurable research questions. A useful next experiment is to compare evaluator-visible structural/trace classifiers across unmorphed, built-in KMAC-morphed and Wasm-strategy-morphed jobs. If classifiers perform no worse without the new layer, the extra polymorphism machinery has not earned a security claim.
