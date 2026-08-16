# V0ID Protocol Architecture — Planned Evolution

> **Status:** architecture plan, not an implemented-protocol specification.
>
> Items below are separated into near-term engineering, research gates and deliberately frozen economic/consensus features. A planned box must not be interpreted as a current security property.

## 1. Design rule

Every component must earn its right to exist.

The architecture should grow by adding a layer only when that layer solves a concrete deficiency without silently weakening an existing trust boundary.

The intended dependency direction is:

```text
semantic job
   |
private series strategy
   |
trusted polymorphism
   |
canonical encrypted-program representation
   |
authenticated encrypted compute transport
   |
remote evaluator execution
   |
execution evidence / client verification
   |
optional accounting / settlement
   |
optional deterministic chain substrate
```

No later layer is allowed to retroactively redefine an earlier security claim.

## 2. Planned cloud architecture

### 2.1 Execution classes and padding — next infrastructure milestone

Current frame sizes, instruction counts and timing expose substantial public shape information.

Planned execution classes should define bounded public buckets such as:

```text
class id
maximum registers
maximum instructions
instruction chunk size
maximum outputs
frame/padding policy
runtime budget
GPU memory budget
```

Goals:

- make admission predictable;
- make resource accounting explicit;
- reduce unnecessary workload fingerprinting;
- avoid arbitrary per-job memory growth;
- provide a stable scheduler unit.

This is traffic-shape reduction, not magical traffic-analysis elimination.

### 2.2 Multi-job scheduler / admission control

The current demo is a single REP service with a small session cache.

Planned service layer:

```text
CURVE/ZAP front door
        |
        v
validated request decoder
        |
        v
admission controller
   |            |
reject        accept
                 |
                 v
          bounded job queue
                 |
        +--------+--------+
        |        |        |
     GPU W0   GPU W1   GPU Wn
        |        |        |
        +--------+--------+
                 |
          result dispatcher
```

Scheduler policy must account for:

- execution class;
- GPU memory pressure;
- cached server-key/session cost;
- queue depth;
- per-authenticated-user quotas;
- total runtime budget;
- cancellation/expiry;
- denial-of-service resistance.

Do not make client-supplied priority a free resource-amplification primitive.

### 2.3 Worker isolation

Possible future deployment modes:

- one process per GPU;
- bounded worker pool;
- process isolation between trust domains;
- container/service-manager isolation where useful;
- explicit GPU assignment rather than implicit global CUDA state.

The architecture should prefer a small privileged/authenticated front end and narrow evaluator worker API rather than turning the network parser into the GPU runtime.

### 2.4 Persistence and restart semantics

Current TFHE sessions are in-memory and expire after the TTL.

Possible later checkpoint layer:

```text
session metadata
+ encrypted evaluator state
+ progress counter
+ protocol version/profile
+ authenticated owner binding
+ integrity checksum/commitment
```

Questions that must be answered before implementation:

- can TFHE-rs GPU state be safely serialized/reconstructed at useful cost?
- what exact ciphertext/key objects are durable?
- how is stale/replayed checkpoint state rejected?
- how is a checkpoint tied to authenticated user, job, epoch and session id?
- does persistence leak additional workload information?

Persistence is not worth adding merely because databases exist.

## 3. Authentication / key-management evolution

The current static CURVE allowlist is a good research boundary because it is narrow and auditable.

Possible later additions, in order of demonstrated need:

1. atomic allowlist reload;
2. explicit key expiry/rotation epochs;
3. revocation records;
4. signed evaluator identity records / discovery metadata;
5. optional organization/user delegation;
6. deployment-specific PKI integration.

Invariant:

```text
transport authentication identity
    must remain distinct from
application job/session identity
```

The application must continue binding the authenticated transport identity into the session instead of trusting a self-declared `peer_id`.

## 4. Series / polymorphism evolution

### 4.1 Keep generator substitution architectural

The polymorphism engine must continue accepting `PolymorphicSeriesGenerator` rather than becoming a KMAC-specific engine.

Expected stable shape:

```text
PolymorphicSeriesGenerator
        |
   +----+-------------------+
   |        |               |
 KMAC     Wasm      trusted custom strategy
   |        |               |
   +--------+---------------+
            |
       DerivedSeries
            |
       ProgramMorpher
```

### 4.2 Distinguisher benchmark

Before claiming that private polymorphism materially hides structural origin, build a held-out classifier benchmark over evaluator-visible features:

- program/job family;
- graph/topology features;
- serialized sizes;
- public dimensions;
- timing/round shape;
- intentionally public profile ids;
- correlation between independently morphed instances.

A layer that does not measurably change attacker capability does not earn a stronger security claim.

### 4.3 Round-dependent polymorphism

Current research direction includes round-dependent secret state encodings so a simple skip-and-stop evaluator cannot necessarily land in the accepted final hidden representation even when semantic state has a fixed point.

This is an experiment against a defined cheating class, not a universal proof of useful work.

## 5. Execution-soundness gate

This is the major unresolved protocol research gate.

### 5.1 Threat question

The verifier ultimately needs an economically meaningful answer to:

> Can a malicious evaluator produce a client-accepted final hidden representation/result while skipping a significant fraction of the requested expensive encrypted computation?

### 5.2 Current evidence is insufficient for issuance

Current components can bind:

- intended job image;
- context/session/job/epoch;
- generator/profile material;
- message ordering;
- authenticated transport identity;
- some narrow checkpoint/round properties.

They do not yet establish general execution soundness.

### 5.3 Candidate directions

Escalate only as required:

- execution-dependent encrypted accumulators coupled to hidden representation changes;
- challenge-dependent checkpoint state;
- randomized audit positions where threat-model compatible;
- proof-carrying execution;
- established verifiable-computation / succinct-proof systems if they can verify the required encrypted workload economically.

Any candidate must answer:

1. Can meaningful work be skipped while preserving accepted evidence?
2. Can evidence be replayed across jobs or epochs?
3. Can evidence be spliced across sessions?
4. Is verification substantially cheaper than repeating FHE execution?
5. Does evidence leak hidden program semantics or private polymorphism state?
6. Is verifier cost bounded enough to resist denial of service?

## 6. Protocol-funded issuance remains frozen

Useful-compute protocol issuance must remain disabled until the execution-soundness gate is strong enough for consensus use.

Reason:

```text
weak execution evidence + protocol minting
        = economic attack surface
```

A transport-authenticated GPU result is not sufficient evidence for minting new supply.

## 7. User-funded compute settlement may come earlier

A user-funded job transfers existing value rather than automatically creating new supply.

Possible lifecycle:

```text
client posts job + fee
        |
executor accepts
        |
encrypted execution
        |
result + evidence
        |
client accepts / dispute path
        |
existing-value settlement
```

Even here, disputes and completion rules require careful design, but the monetary risk is categorically different from protocol inflation.

## 8. Deterministic chain substrate

Ledger engineering may proceed independently of useful-compute minting.

### 8.1 First milestone

Build a deterministic state-transition core with:

- canonical byte encoding;
- domain-separated hashes;
- typed transaction envelopes;
- transaction ids;
- block ids;
- state roots;
- work-event ids;
- account/object nonces;
- replay rejection;
- proof/nullifier duplicate rejection;
- deterministic `apply(block, state) -> state'`;
- save/reload tests.

No EVM, staking, monetary policy or network stack should appear automatically merely because the word "blockchain" appears.

### 8.2 Consensus boundary later

Consensus/order/finality should be an adapter around the independently testable deterministic application state machine.

The computation lane should first operate with reward = 0 before protocol economics are introduced.

### 8.3 Monetary invariant

Any later policy must preserve:

```text
protocol_issuance(epoch) <= epoch_emission_budget(epoch)
```

Unlimited submissions must never imply unlimited issuance.

## 9. Planned protocol object model

A future job object should eventually make public versus private fields explicit rather than letting them emerge accidentally from serialization.

Possible conceptual split:

```text
PublicJobDescriptor
    protocol_version
    execution_class
    job_id
    epoch
    allowed FHE/profile ids
    public shape bucket
    encrypted payload commitments

PrivateClientContext
    semantic program
    plaintext inputs
    SeriesSeed
    private generator state
    MorphSeed
    TFHE ClientKey

EvaluatorSession
    authenticated_user_id
    job_id
    epoch
    session_id
    server key
    encrypted init
    encrypted registers
    completed instruction count

ExecutionEvidence
    exact scheme/version
    job/session/epoch binding
    challenge binding
    evidence bytes
    verifier-cost bound
```

This is a planning model, not the current wire ABI.

## 10. Protocol versioning policy

Keep distinct version domains distinct:

```text
V0IDNET1     outer peer/network envelope
V0TFHE01     TFHE cloud metadata protocol
V0ID*C02     Rust opaque TFHE object envelopes
series profile/version
execution-evidence version
future chain encoding version
```

Do not overload one version integer to mean every layer changed together.

Rules for future upgrades:

- reject unsupported versions explicitly;
- do not silently reinterpret old fields;
- bind negotiated security/profile choices into the relevant transcript/context;
- make downgrade behavior fail closed;
- preserve canonical encodings for anything that becomes consensus-visible.

## 11. Observability and metrics

The current streamed console progress is the first step.

A production-like research daemon may later expose bounded metrics such as:

- authenticated requests accepted/rejected;
- active sessions;
- queue depth;
- execution-class distribution;
- chunk completion latency;
- GPU worker utilization;
- expired/cancelled sessions;
- protocol parse/auth errors.

Do not export private program contents, ciphertext dumps, secret keys or accidentally identifying high-cardinality labels merely for dashboards.

## 12. Fuzzing / release gates

Before hostile public exposure:

- fuzz V0IDNET1 decoder;
- fuzz TFHE cloud metadata codec;
- fuzz multipart count/size boundaries;
- negative-test ZAP identity mismatches;
- negative-test wrong server pin / wrong client key;
- negative-test duplicate/reordered/skipped chunks;
- negative-test stale session and epoch reuse;
- sanitizer/UB passes on the current tree;
- safe/conformant TFHE serialization migration or equivalent validation;
- independent cryptographic review;
- independent FHE/protocol review;
- reproducible benchmark corpus;
- explicit threat model/security games.

## 13. Target architecture

```text
                         TRUSTED CLIENT
                              |
                 private series / polymorphism
                              |
                    canonical encrypted job
                              |
                 TFHE ClientKey stays local
                              |
                              v
                 CURVE authenticated channel
                              |
                       protocol front door
                              |
                   validation + admission
                              |
                     execution-class queue
                              |
                  +-----------+-----------+
                  |           |           |
               GPU W0      GPU W1      GPU Wn
                  |           |           |
                  +-----------+-----------+
                              |
                      encrypted result
                              |
                    execution evidence
                              |
                              v
                         CLIENT VERIFIER
                              |
                 +------------+------------+
                 |                         |
          user-funded settlement      research evidence
                 |                         |
                 v                         v
        deterministic ledger       malicious-evaluator
             substrate                test harness
                 |
                 v
        protocol issuance gate
        [FROZEN until earned]
```

## 14. Things deliberately not planned by default

The architecture does not automatically need:

- a generic smart-contract VM;
- an EVM clone;
- staking;
- proof-of-stake consensus;
- a custom transport cipher;
- a custom replacement for ML-KEM;
- a native untrusted plugin loader;
- arbitrary evaluator shell access;
- a giant `Blockchain` god-class;
- a permanent mining-to-FHE conversion ratio.

If any of those are introduced, they must solve a specific requirement and survive a separate threat/cost analysis.

## 15. Homomorphic modular neural execution profile

The planned neural profile treats a neural network as a modular composition/dataflow object that can run either clear or homomorphically encrypted without changing the model identity.

### 15.1 End-to-end neural input path

```text
TOKEN STREAM / NUMERIC INPUT
             |
             v
    Token <-> Neuron Codec
             |
             v
 Resolution / Nearest Mapper
             |
             +------------------------------+
             |                              |
      plaintext context              encrypted context
             |                              |
             +--------------+---------------+
                            |
                            v
                    Modular NeuralGraph
                     /      |       \
                built-in  Wasm   stateful modules
                     \      |       /
                            v
                  selected execution backend
                     |                |
                 PLAIN_CPU        TFHE_CUDA
                                      |
                                      v
                         distributed encrypted workers
                                      |
                         feedforward / backprop /
                              weight update
                                      |
                                      v
                           encrypted output/state
```

### 15.2 Token <-> firing-neuron representation

A versioned `TokenNeuronCodec` must translate symbolic tokens into a canonical firing-neuron representation and translate valid output firing patterns back into tokens or token candidates.

Possible codec strategies include one-hot firing, sparse patterns or bounded activation codes, but the graph/backend must depend on the codec interface rather than one fixed encoding.

Remote execution must bind the exact codec/vocabulary identity so the same numeric firing pattern cannot be interpreted under a silently substituted token scheme.

### 15.3 Numerical resolution and nearest-neighbor mapping

A separate resolution layer maps a broad numerical input range to a finite set of representative values.

For range `[L,H]` and resolution `R`:

```text
[L,H]
  |
  +--> q[0] q[1] ... q[R-1]
                 |
input x ---------+
                 |
         nearest representative
                 |
                 v
          canonical neural value
```

The first implementation may use uniform intervals. The architecture also permits a committed non-uniform resolution table later.

If the source number is secret, nearest-representative selection may be executed homomorphically. If the selected trust policy permits client-side preprocessing, the client may quantize before encryption.

### 15.4 Context has both location and protection policy

Context must not be represented by one ambiguous flag.

Location:

```text
LOCAL_CLIENT
CLOUD_CONTENT_ADDRESSED
```

Protection:

```text
PLAINTEXT_CONTEXT
ENCRYPTED_CONTEXT
```

These combine independently, e.g. local encrypted context means the client selects context locally and encrypts it before the cloud sees it; cloud encrypted context means the evaluator resolves a content-addressed ciphertext object and feeds it into the encrypted graph without plaintext recovery.

The invocation commitment must bind context checksum, location and protection policy.

### 15.5 Modular feedforward/training graph

The module tree describes ownership while typed ports describe actual flow.

```text
model
├── input-pipeline
│   ├── token-neuron-codec
│   ├── resolution-map
│   └── context-select
├── network
│   ├── layer-0
│   ├── layer-1
│   └── custom-neural.wasm
└── trainer
    ├── loss
    ├── backprop
    └── weight-update
```

Typed ports may carry:

```text
ACTIVATION
GRADIENT
WEIGHT
BIAS
CONTEXT
LOSS
CONTROL
```

The dataflow graph remains free to express residual connections, shared state, gradient routing and distributed partitioning.

### 15.6 Bounded non-halting policy

The neural/runtime architecture does **not** solve the halting problem. Instead, every potentially unbounded component receives a finite execution budget.

This applies particularly to:

- custom Wasm;
- recurrent/adaptive loops;
- iterative context processing;
- training loops;
- future programmable neural modules.

Possible outcomes:

```text
HALTED
INTERMEDIATE
DEFAULT_OUTPUT
NULL
ERROR
```

Policy:

```text
normal halt
   -> HALTED + normal output

budget exhaustion
   -> if a valid checkpointable intermediate exists and profile permits it:
          INTERMEDIATE
      else:
          invoke server-side HALTING_DEFAULT_MODULE
              -> valid bounded result: DEFAULT_OUTPUT
              -> no valid result:     NULL
```

The server-side halting default module is part of the advertised execution class/profile. Its module id, version, digest, ABI and own execution budget must be bound into the job before the client accepts execution.

The fallback module is itself strictly bounded. It may not recursively become another unbounded computation. Trap/timeout/schema failure produces `NULL` or `ERROR` according to the profile.

For encrypted neural execution, intermediate/default outputs must remain within the declared encrypted tensor/output representation. The evaluator must not decrypt client-private state merely to produce the fallback.

This converts non-termination from an infinite wait into a deterministic bounded service outcome without making a false computability claim.

### 15.7 Invocation identity for neural jobs

A future neural invocation commitment should bind at minimum:

```text
NeuralGraph digest
execution mode: PLAIN_CPU | TFHE_CUDA
token/neuron codec id + version + digest
resolution-map id + parameters/digest
context checksum(s)
context location(s)
context protection mode(s)
model/weight-state checksum
halting budget/profile
server halting-default module id/version/digest
job id
epoch
```

Changing any of those makes a different requested execution.

### 15.8 Testing order

Build the semantics in the cheapest layer first:

```text
1. token <-> firing pattern round-trip tests
2. deterministic nearest-resolution mapping tests
3. plain fixed-point NeuralGraph executor
4. feedforward / loss / backprop / weight-update differential tests
5. context clear/encrypted policy tests
6. bounded-halting/default-module tests
7. tiny TFHE neural lowering tests
8. distributed encrypted neural worker tests
9. heavyweight encrypted training stress tests
```

The plain executor is the semantic oracle for the encrypted implementation; full encrypted training should not be the first debugging environment.
