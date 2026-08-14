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
- Exact bit-packed Gaussian elimination for the affine/degree-2 GF(2) audit.
- Optional Microsoft Z3 only for the bounded bit-vector attacker language where
  general SMT solving earns its cost.

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

### Quantum/structural attacks on series output

**Falsification gates present; universal claim impossible.**

`v0id-quine-audit-tests` exhaustively screens a reduced private-root domain for
an exact XOR period and checks coarse avalanche behavior.

`v0id-symbolic-series-audit` does **not** use Z3. It exactly solves the affine
GF(2) and degree<=2 ANF recovery systems with bit-packed Gaussian elimination over
the complete 8-bit reduced-root domain. `UNSAT` there is exact for that specified
attacker class rather than a timeout or failed heuristic search.

`v0id-bitvector-series-audit` is the next attacker language and uses Z3 plus a
CEGIS loop. One shared bounded 8-bit straight-line program is synthesized across
the reduced family. The current DSL contains:

```text
XOR  AND  ADD  NOT
SHL  SHR  ROTL ROTR
XORI ADDI ANDI
```

Z3 may select source registers, shared 8-bit immediates, the observed output bit
and the target secret-root bit. The program is the same for every reduced root;
there is no per-root lookup table. Candidate programs are validated against all
256 reduced roots. Counterexamples are fed back to the solver.

The bit-vector audit is deliberately tri-state:

```text
UNSAT   -> this bounded attacker class is closed for the constrained subset;
           therefore no full-domain breaker in that class can exist
SAT     -> print the candidate and validate it against all 256 roots
UNKNOWN -> INCONCLUSIVE; timeout/interruption is never accepted as PASS
```

A validated SAT program is a structural cryptanalytic lead and should be analyzed
and then tested on independent wider reduced families. An UNSAT result closes
only the exact configured step/input-byte attacker language. It is not a proof
that no arbitrary Turing machine, hidden-subgroup algorithm or future quantum
algorithm can attack the full construction.

## Oracle-free symbolic attacker rule

A useful synthesized breaker must generalize across many/all instances of a
reduced model. It may contain its algorithm and shared universal constants, but
it must not contain a table of challenge-specific answers or select a different
program per challenge.

The research harness expands the DSL in stages:

```text
level 0: exact XOR-period screen                         implemented
level 1: affine GF(2)                                   implemented / exact
level 2: degree<=2 ANF / AND                            implemented / exact
level 3: bounded bit-vector straight-line program       implemented / Z3+CEGIS
         XOR/AND/ADD/NOT/shift/rotate/immediates
level 4: conditionals / selects / richer word programs  future
level 5: bounded loops / register machines              future
level 6: bounded Turing-machine/program synthesis       future
```

For each bounded level the desired result is one of:

```text
SAT     -> a generic candidate breaker exists; analyze/fix immediately
UNSAT   -> this bounded attacker class is closed for the specified model
UNKNOWN -> no conclusion; increase resources or reduce/partition the search
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
