# V0ID PQR composition audit

This document treats the V0ID security architecture as a **composition**, not as
an independent checklist of strong primitives. A post-quantum KEM, a strong
hash, a private series generator and an FHE scheme can still compose badly.

The target architecture is intentionally series-first:

```text
issuer-private 256-bit root (RAND_priv_bytes)
              |
              v
        KMACXOF256 series schedule
              |
       +------+------+------------------+
       |             |                  |
       v             v                  v
 private series   morph material   private audit challenge
       |             |                  |
       +-------> ProgramMorpher <-------+
                     |
                     v
               morphed program
                     |
        +------------+-------------+
        |                          |
        v                          v
  BinFHE STD128Q              QuineHash512
        |                  SHA3-512/KMAC256
        |                          |
        +------------+-------------+
                     |
                     v
                  RMJ3 job
```

A later key exchange has a second, deliberately distinct schedule:

```text
standardized PQ KEM shared secret
           + complete handshake transcript
                       |
                       v
                  KMACXOF256
                       |
                 SharedSeriesRoot
                       |
          labeled downstream material
```

The shared KEM root is **not** the sole root of private polymorphism when the
remote evaluator is a KEM peer. Otherwise that peer could reproduce the morph
schedule. An issuer-private root is separately bound to the KEM transcript and
job/epoch before it drives polymorphism.

## Standard components used

- OpenSSL `RAND_priv_bytes()` for issuer-private roots.
- OpenSSL KMAC-256 in XOF mode (KMACXOF256 construction) for series expansion.
- OpenSSL KMAC-256 with domain separation for private audit challenges.
- OpenSSL SHA3-512 for the plaintext quine commitment and transcript hashes.
- OpenFHE `STD128Q` for the remote BinFHE quantum-security profile.
- Optional Microsoft Z3 audit target for symbolic Boolean-relation synthesis.

The repository does not claim that these choices prove the entire V0ID
composition post-quantum secure. They remove avoidable custom-primitive risk and
make the remaining research questions explicit.

## Composition seams and current status

### Private entropy -> series schedule

**Closed by construction, pending runtime regression.**

Production private series roots are generated with `RAND_priv_bytes()` and never
sent to the evaluator. Public evaluator-session identifiers use `RAND_bytes()` so
public routing values do not expose output from the private DRBG stream.

The built-in generator uses separate KMACXOF256 customization strings for:

- private series bytes,
- trusted `ProgramMorpher` seed material,
- private provenance material.

A downstream value must not be silently reused in another role.

### Series generator -> ProgramMorpher

**Partially closed.**

Trusted C++ still owns the state permutation, transition rewriting, dummy-state
padding and invariant checks. A local Wasm generator can derive morph material
but does not directly construct an unchecked machine.

For the quine commitment, the exact Wasm module bytes are hashed into the
private generator binding. The same advertised plugin id/version with different
code therefore produces a different commitment.

Remaining uncertainty: an intentionally malicious local plugin can still choose
bad morph material. Security-critical audit challenges are therefore keyed from
the issuer-private root, not solely from plugin-controlled output.

### Semantic job -> morphed executable

**Bound, not proven equivalent cryptographically.**

`semantic_job_hash512()` commits to the issuer's base program, initial state,
head, tape and round count. `QuineHash512` separately commits to the morphed
program and includes the semantic binding.

This detects substitution at the commitment layer. Semantic equivalence is still
established by trusted transformation logic and differential tests, not by the
hash itself.

### Quine self-reference

**Fixed-point hole avoided.**

The quine is defined as:

```text
SHA3-512(canonical object with 64-byte digest field represented as all-zero)
```

No equation of the form `Q = H(object containing Q)` is solved. The design does
not rely on the existence, uniqueness or hardness of cryptographic fixed points.

### Canonical encoding / field ambiguity

**Closed by explicit length-delimited encoding in the current implementation.**

The quine commits to domain/version, crypto profile, public shape, session id,
job id, epoch, initial state/head/tape, semantic binding, generator binding,
256-bit private challenge and canonical transition table.

Regression tests change each seam independently and require a different digest.

### Parameter downgrade

**Closed for the current RMJ3 demo profile.**

The remote-machine client and server require `STD128Q`. The evaluator-session
profile and per-job profile must match. The quine also commits to the parameter
profile, so `STD128Q -> STD128` changes the commitment.

Any future negotiation layer must preserve this fail-closed behavior.

### Key exchange -> series-first schedule

**Scaffolded and regression-tested; real network KEM integration still open.**

The schedule hashes the KEM id/version, machine protocol, FHE parameter set,
session id, initiator/responder roles, KEM public material and KEM ciphertext.
The standardized KEM shared secret plus this transcript hash derive the shared
series root with KMACXOF256.

Changing the KEM, peer roles, session, ciphertext, shared secret or FHE profile
must change derived material.

The KEM remains the hardness assumption. Series-first scheduling is a key
composition/KDF layer, not a replacement for ML-KEM.

### Shared series -> algorithms later

**Closed against accidental stream reuse by labels.**

Every downstream algorithm requests material using a distinct label and context.
For example transport authentication and another session purpose must not consume
an interchangeable byte stream.

Algorithm-specific key-length and misuse requirements remain the responsibility
of that algorithm's adapter.

### Static quine -> honest execution

**OPEN / UNCERTAIN.**

A SHA3-512 quine commitment says which job image the issuer intended and binds
all relevant local layers. It does **not** prove that an untrusted evaluator ran
all required encrypted rounds.

The existing 32-bit FHE fingerprint remains explicit test plumbing and is not a
PQR integrity primitive. Replacing it with a 512-bit client-side commitment does
not magically make the evaluator prove SHA3 computation.

Closing this seam requires an execution-bound mechanism: for example a sound
verifiable-computation proof, or a rigorously analyzed hidden challenge protocol.
An evolving accumulator may be useful plumbing but should not be called a proof
without a soundness argument.

### Observable execution structure

**OPEN / EMPIRICAL.**

FHE hides values, not necessarily all evaluator-visible correlation. Timing,
bootstrapping patterns, message sizes and repeated structural roles may leak job
lineage. Polymorphism needs an evaluator-visible trace distinguisher benchmark.
If morphing does not reduce classifier advantage, that layer has not earned its
existence.

### Quantum structural attacks on series output

**Falsification gates present; universal claim impossible.**

`v0id-quine-audit-tests` exhaustively screens a reduced private-root domain for
an exact XOR period and checks coarse avalanche behavior.

`v0id-symbolic-series-audit`, when Z3 is installed, asks whether one shared
oracle-free affine or quadratic Boolean expression can recover reduced private
root bits from series-output bits over the complete reduced domain.

An `UNSAT` result closes that **defined attacker language on that reduced model**.
It is not a proof that no arbitrary Turing machine, hidden-subgroup algorithm or
future quantum algorithm can attack the full construction.

## Oracle-free symbolic attacker rule

A useful synthesized breaker must generalize across many/all instances of a
reduced model. It may use a fixed instruction set and universal constants such
as Boolean `0/1`, but it must not contain a table of challenge-specific answers
or select a different program per challenge.

The eventual research harness can expand the DSL in stages:

```text
level 0: XOR / NOT / permutations
level 1: affine GF(2)
level 2: low-degree ANF / AND
level 3: add / rotate / shift / bit-vector arithmetic
level 4: bounded loops / small straight-line programs
level 5: bounded Turing-machine/program synthesis
```

For each level the desired result is either:

```text
SAT   -> a generic candidate breaker exists; analyze/fix immediately
UNSAT -> this bounded attacker class is closed for the specified reduced model
```

A breaker must then be validated on fresh widths/seeds/jobs before it is treated
as a real structural attack.

## What cannot honestly be marked "closed"

No finite benchmark or solver run can prove that no possible future algorithm
or arbitrary Turing machine breaks a computational cryptosystem. Unknown quantum
algorithms remain an irreducible uncertainty.

The practical objective is therefore:

1. rely on standardized primitives where possible;
2. bind every composition seam explicitly;
3. make downgrade/substitution/reuse fail closed;
4. enumerate known attack languages and produce falsification gates;
5. keep the genuinely undecidable/unknown remainder labeled **UNCERTAIN** rather
   than laundering it into a security claim.

That is the strongest defensible meaning of "leave no specific hole open" for
this research architecture.
