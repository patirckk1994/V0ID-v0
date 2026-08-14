# V0ID series-first polymorphism

V0.4.1 adds a client-side `PolymorphicSeriesGenerator` layer in front of the existing `ProgramMorpher`.

The immediate purpose is experimental: make the "series first, algorithm/representation later" idea a concrete object that can be generated, replaced, measured and attacked without pretending the conjecture is already a cryptographic theorem.

## Current pipeline

```text
semantic input
    |
    v
private SeriesSeed (256 bits) + epoch
    |
    v
PolymorphicSeriesGenerator
    |
    +--> private derived series
    +--> private series manifest/provenance token
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

The built-in generator is `v0id-series-kmac-v1`. It uses OpenSSL 3 KMAC-256 under separate domain strings to derive a byte series and then a morph seed. The current demo uses a 64-byte private series.

The private series, `SeriesSeed`, derived morph seed, private series manifest and `MorphManifest` are not sent to the remote evaluator.

## User-injected patterns

`PolymorphicSeriesGenerator` is an abstract interface. `FunctionalSeriesGenerator` additionally accepts a trusted local C++ callback:

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
        // User-controlled local derivation goes here.
        // Fill out.series and out.morph_seed.
        return out;
    });
```

This is intentionally **not** a network plugin loader. An evaluator cannot send a `.so`, `.dll` or arbitrary executable crypto implementation for the client to load. User-injected patterns are trusted local application code.

A later plugin/registry layer can expose locally installed implementations by identifier after there are multiple real implementations worth negotiating.

## Public profile identifier

The remote-machine wire format is versioned to `V0IDRMJ2` / `V0IDRMR2` and carries a bounded public `CryptoProfileId`:

```text
primitive_id              openfhe-binfhe
parameter_set             STD128
machine_protocol          v0id-remote-machine-v2
integrity_profile         toy-fingerprint32-v1
series_generator_id       v0id-series-kmac-v1
series_generator_version  1
```

The server fails closed when the execution primitive, parameter set, machine protocol or integrity profile is unsupported. The series generator runs entirely client-side, so its public id/version is currently provenance metadata rather than server-executable functionality. The server echoes the profile in the result and the client requires an exact match.

This is a precursor to capability negotiation, not negotiation itself. There is not yet an authenticated suite handshake or downgrade protection.

## Research questions

The new layer gives V0ID a concrete place to test questions such as:

- How much diversity does a series generator actually induce in morphed machine images?
- Which properties of the input survive into evaluator-visible traces?
- Can a classifier correlate two jobs produced from the same semantic program but different private series?
- Do user-defined generators improve or worsen that distinguishability?
- What information about a generator must be public for interoperability, and what can remain client-private?
- Is there any useful formal hardness statement about a family of derived series, rather than merely about the standard cryptographic primitive used to generate them?

The last question is deliberately open. The current KMAC generator inherits ordinary assumptions from the primitives it uses; it does **not** establish that arbitrary data series are intrinsically quantum-hard, information-theoretically hidden, or a new post-quantum primitive.

## Why series before plugin negotiation

A large crypto plugin protocol would currently standardize abstractions before V0ID has enough interchangeable implementations to know which abstractions matter.

The intended order is:

```text
1. series generator abstraction + one concrete generator
2. correlation/diversity experiments
3. second genuinely different generator/profile
4. authenticated capability negotiation
5. optional local plugin ABI/registry
```

Identifiers are included now so later protocol work can evolve without changing the conceptual boundary between trusted local derivation and untrusted remote evaluation.
