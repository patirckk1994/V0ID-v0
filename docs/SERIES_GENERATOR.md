# V0ID series-first polymorphism

V0.4.1 introduced a client-side `PolymorphicSeriesGenerator` layer in front of `ProgramMorpher`. V0.4.5 adds a sandboxed local Wasm implementation of that interface.

The purpose remains experimental: make the "series first, algorithm/representation later" idea a concrete object that can be generated, replaced, measured and attacked without pretending the conjecture is already a cryptographic theorem.

## Current pipeline

```text
semantic input
    + private SeriesSeed (256 bits)
    + epoch
          |
          v
PolymorphicSeriesGenerator
   |                  |
   |                  +--> WasmSeriesGenerator (client-only WAMR)
   +--> KmacSeriesGenerator
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
                  BinFHE
                    |
                    v
            remote fixed evaluator
```

The private series, `SeriesSeed`, derived `MorphSeed`, private series manifest and `MorphManifest` are not sent to the remote evaluator.

## Built-in KMAC generator

`v0id-series-kmac-v1` uses OpenSSL 3 KMAC-256 under separate domain strings to derive a byte series, morph seed and small client-only provenance token. The current remote demo uses a 64-byte private series.

This inherits ordinary assumptions from the cryptographic primitive it uses. It does **not** establish that arbitrary generated series are intrinsically quantum-hard, information-theoretically hidden or a new post-quantum primitive.

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

## V0.4.5 Wasm generator

`WasmSeriesGenerator` lets the client use a portable local Wasm strategy without recompiling V0ID.

The Wasm receives only private `SeriesSeed`, semantic input and epoch through bounded guest linear memory. It returns a canonical `V0P1` envelope containing:

```text
private series
32-byte MorphSeed
private manifest
```

It does **not** receive `Program`, does not rewrite transition rules and has zero host imports. Trusted C++ validates the envelope and passes only the resulting morph material into `ProgramMorpher`.

This is deliberately narrower than a general plugin system. See `docs/POLYMORPH_WASM.md` for the ABI and sandbox policy.

## Public profile identifier

The current remote-machine wire format uses RMS3/RMJ3/RMR3 and carries a bounded public `CryptoProfileId`, including:

```text
primitive_id              openfhe-binfhe
parameter_set             STD128
machine_protocol          v0id-remote-machine-v3
integrity_profile         toy-fingerprint32-v1
series_generator_id       <client-selected public provenance id>
series_generator_version  <version>
```

The evaluator does not execute the series generator. Its public id/version is provenance metadata and is echoed back so the client can require an exact profile match.

A future client using a private Wasm strategy may intentionally expose only a coarse public profile id rather than a module hash if revealing exact strategy identity would defeat the point of client-private polymorphism. That policy has not yet been standardized.

There is not yet an authenticated suite handshake or downgrade protection.

## Research questions

This layer provides a concrete place to measure:

- how much diversity a generator actually induces in morphed machine images;
- which input/program properties survive into evaluator-visible traces;
- whether a classifier can correlate jobs produced from the same semantic program under different private series;
- whether the KMAC and Wasm strategies measurably change structural-role inference;
- which generator metadata must be public for interoperability;
- whether any candidate generated-relation family admits a meaningful hardness statement beyond the assumptions of the standard primitives used inside its generator.

The most important criterion is empirical/formal usefulness: if a classifier performs the same with and without a polymorphism layer, that layer has not earned a security claim.

## Why the Wasm layer stays local

The local Wasm layer exists to make client-side strategies replaceable while keeping the remote attack surface unchanged.

```text
local Wasm strategy     -> programmable private derivation
trusted ProgramMorpher  -> semantic machine rewrite
BinFHE                   -> hidden values/program representation
remote evaluator         -> fixed encrypted execution
```

No `.so`, `.dll`, native machine-code plugin or polymorphism Wasm is accepted from an evaluator.
