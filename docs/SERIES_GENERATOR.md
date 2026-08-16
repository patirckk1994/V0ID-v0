# V0ID series-first polymorphism

The client-side `PolymorphicSeriesGenerator` layer sits in front of `ProgramMorpher`. The generator is deliberately replaceable: KMACXOF256 is the built-in private-series implementation, not a hard-coded dependency of the polymorphism engine.

The purpose remains experimental: make the "series first, algorithm/representation later" idea a concrete object that can be generated, replaced, measured and attacked without pretending the conjecture is already a cryptographic theorem.

## Current pipeline

```text
semantic input
    + private SeriesSeed (256 bits)
    + epoch
          |
          v
PolymorphicSeriesGenerator
   |                  |                     |
   |                  |                     +--> FunctionalSeriesGenerator
   |                  +--> WasmSeriesGenerator (client-only WAMR)
   +--> KmacSeriesGenerator (KMACXOF256 v2 built-in)
          |
          +--> private derived series
          +--> private series manifest/provenance
          +--> derived MorphSeed
                    |
                    v
               ProgramMorpher
                    |
                    v
             morphed program image
                    |
                    v
                  FHE
                    |
                    v
            remote fixed evaluator
```

The private `SeriesSeed`, generated series, derived `MorphSeed`, private manifest and morph manifest are client-local material and are not evaluator inputs.

## Built-in KMACXOF256 generator

The built-in profile is:

```text
v0id-series-kmacxof256-v2
```

It uses OpenSSL 3 `KMAC-256` with XOF mode enabled to expand an issuer-only 256-bit root into an arbitrary-length private series. The output length is a local generator parameter rather than a protocol assumption.

Separate customization strings/domain labels derive:

```text
V0ID private polymorphic series v2
V0ID trusted ProgramMorpher seed v2
V0ID private series provenance v2
```

The separation prevents series bytes, morpher material and private provenance from being treated as interchangeable output from one undifferentiated stream.

This gives the built-in schedule a standardized keyed PRF/XOF base. It does **not** establish that arbitrary generated series are intrinsically quantum-hard, information-theoretically hidden, or a new post-quantum primitive.

## Generator interface is the architecture

Consumers depend on the abstract interface:

```cpp
class PolymorphicSeriesGenerator {
public:
    virtual ~PolymorphicSeriesGenerator() = default;

    virtual SeriesProfile profile() const = 0;
    virtual DerivedSeries derive(
        const std::vector<std::uint8_t>& input,
        const SeriesSeed& seed,
        std::uint64_t epoch) const = 0;
};
```

`ProgramMorpher` must not call KMACXOF256 directly. The intended dependency direction is:

```text
PolymorphicSeriesGenerator
          |
   +------+------+----------------+
   |             |                |
KMACXOF256      Wasm          custom C++
   |             |                |
   +-------------+----------------+
                 |
           DerivedSeries
                 |
           ProgramMorpher
```

This keeps the cryptographic/default generator replaceable without rewriting the morphing engine.

## Trusted C++ callback generator

`FunctionalSeriesGenerator` accepts a trusted local C++ callback:

```cpp
v0id::polymorph::SeriesProfile profile{
    "my-series-generator",
    1,
    {}
};

v0id::polymorph::FunctionalSeriesGenerator generator(
    profile,
    [](const std::vector<std::uint8_t>& input,
       const v0id::polymorph::SeriesSeed& seed,
       std::uint64_t epoch) {
        v0id::polymorph::DerivedSeries out;
        // Fill out.series, out.morph_seed and optionally private_manifest.
        return out;
    });
```

This is trusted process-local code, not a network plugin loader.

## Wasm generator

`WasmSeriesGenerator` lets the client use a portable local Wasm strategy without recompiling the core polymorphism engine.

The Wasm receives only private `SeriesSeed`, semantic input and epoch through bounded guest linear memory. It returns a canonical `V0P1` envelope containing:

```text
private series
32-byte MorphSeed
private manifest
```

It does not receive `Program`, does not rewrite transition rules and has zero host imports. Trusted C++ validates the envelope and passes only the resulting morph material into `ProgramMorpher`.

This is deliberately narrower than a general plugin system. See `docs/POLYMORPH_WASM.md` for the ABI and sandbox policy.

## Public profile metadata

A remote protocol may carry a bounded `series_generator_id` and `series_generator_version` as provenance/interoperability metadata. That public profile does **not** contain the private series or private root and must not be treated as enough information to reproduce client polymorphism.

A private Wasm/custom strategy may intentionally expose only a coarse profile identifier if revealing exact implementation identity would defeat the intended privacy policy. Any future authenticated suite negotiation should bind that policy explicitly and prevent downgrade.

## Tests

`v0id-round-morph-schedule-tests` now checks that:

- the built-in profile is `v0id-series-kmacxof256-v2`;
- requested KMACXOF256 series lengths are honored;
- longer XOF output preserves the shorter-output prefix for the same root/input/epoch;
- identical root/input/epoch reproduces the same private series, morph seed and manifest;
- changing the private root, semantic input or epoch changes the private series;
- a `FunctionalSeriesGenerator` can replace KMACXOF256 through the same abstract interface without changing `ProgramMorpher`.

## Research questions

This layer provides a concrete place to measure:

- how much diversity a generator actually induces in morphed machine images;
- which input/program properties survive into evaluator-visible traces;
- whether a classifier can correlate jobs produced from the same semantic program under different private series;
- whether KMACXOF256, Wasm and custom strategies measurably change structural-role inference;
- which generator metadata must be public for interoperability;
- whether any candidate generated-relation family admits a meaningful hardness statement beyond the assumptions of the standard primitives used inside its generator.

The most important criterion is empirical/formal usefulness: if a classifier performs the same with and without a polymorphism layer, that layer has not earned a security claim.

## Why programmable generators stay local

The local callback/Wasm seams exist to make client-side strategies replaceable while keeping the remote attack surface unchanged.

```text
local private generator  -> programmable private derivation
trusted ProgramMorpher   -> semantic machine rewrite
FHE                      -> hidden values/program representation
remote evaluator         -> fixed encrypted execution
```

No native plugin, generator Wasm, private root or private derived series is accepted from an evaluator.