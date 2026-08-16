# V0ID modular neural runtime

> Status: additive architecture scaffold. The graph/module/context ABI is implemented; the token/neuron codec, resolution mapper, plain numerical executor and TFHE tensor-lowering backend are separate follow-up milestones.

The neural runtime is deliberately **not** a second hard-coded V0ID protocol. It is an execution profile layered over the same module/content identity and future cloud execution boundaries.

The model definition is independent of whether the user chooses clear or encrypted execution.

```text
same NeuralGraph
      |
      +--> PLAIN_CPU
      |
      +--> TFHE_CUDA
```

Encryption belongs to the invocation/backend, not to the identity of the neural network.

## 1. Module tree versus dataflow graph

A neural model needs both.

The **module tree** describes ownership/composition:

```text
model
├── encoder
│   ├── token-neuron-codec
│   ├── resolution-mapper
│   ├── dense-0
│   ├── activation-0
│   └── dense-1
└── trainer
    ├── loss
    ├── backprop
    └── weight-update
```

Each `NeuralModuleNode` therefore has an optional `parent_id`.

The **dataflow graph** is separate:

```text
input.activation
      |
      v
dense.x -> dense.y
              |
              v
       activation.x -> activation.y
                              |
                              v
                         output.activation
```

Training routes may be non-tree-shaped:

```text
prediction -> loss
                |
             gradient
                |
                v
             backprop
                |
        weight_gradient
                |
                v
          weight-update
```

Keeping composition and tensor routing separate allows residual connections, shared parameters, gradient routes and later distributed placement without corrupting the human module hierarchy.

## 2. Token <-> firing-neuron codec

The planned neural input path begins with an explicit token/neuron conversion layer rather than making token IDs a hidden assumption of the network.

```text
token stream
    |
    v
TokenNeuronCodec
    |
    +--> token -> canonical firing-neuron representation
    |
    +--> firing-neuron representation -> token / token candidate
    |
    v
numeric neural input
```

The codec is an interface and may be replaced independently of the neural graph backend.

A codec may choose, for example:

- one token -> one firing-neuron index;
- one token -> a sparse set of firing neurons;
- one token -> a bounded activation pattern;
- a reverse nearest-match policy when a produced firing pattern does not exactly equal one token code.

The exact mapping, vocabulary identity, neuron count, activation format and reverse-decoding policy must be versioned/canonically committed when used in a remote job.

This layer is conceptually separate from embeddings. A later embedding module may consume the canonical firing representation, but the token/neuron codec defines the reversible symbolic boundary first.

## 3. Resolution / nearest-neighbor numeric mapping

Before values enter the neural graph, a separate resolution mapper may discretize a numerical range into a fixed number of representative values.

For a configured range and resolution:

```text
minimum = L
maximum = H
resolution = R
```

the mapper constructs a canonical ordered representative set:

```text
q[0], q[1], ... q[R-1]
```

covering `[L,H]`.

Every input number `x` is mapped to the nearest representative:

```text
quantize(x) = argmin q[i] |x - q[i]|
```

with a deterministic tie-breaking rule.

Conceptually:

```text
continuous / wide integer input
             |
             v
      split range into R
       resolution points
             |
             v
 nearest-neighbor selection
             |
             v
 canonical quantized number
             |
             v
 firing / activation representation
```

The mapping may be uniform initially, but the interface should not require all future resolution tables to be uniform. A non-uniform content-addressed resolution table is acceptable if its exact identity is committed into the invocation.

The purpose is to give clear and homomorphic backends the **same finite numerical vocabulary**. It is not a claim that nearest-neighbor quantization is optimal for every neural workload.

A future encrypted implementation may perform the nearest-representative selection homomorphically when the input value itself must remain encrypted. A clear client may also quantize before encryption when that leakage/trust policy is acceptable.

## 4. Typed port ABI

Current port roles:

```text
ACTIVATION
GRADIENT
WEIGHT
BIAS
CONTEXT
LOSS
CONTROL
```

Each port carries:

```text
name
direction: INPUT | OUTPUT
role
TensorShape
numeric format
mutable-state flag
```

Current numeric formats are deliberately integer/fixed-point oriented:

```text
UINT8
INT8
UINT16
INT16
FIXED16_16
FIXED8_24
```

That avoids pretending the current encrypted backend already provides arbitrary IEEE floating-point tensor execution.

A dataflow edge is valid only when source and destination agree on:

```text
shape
numeric format
port role
```

and an input port has at most one graph driver.

## 5. Built-in module operations

The graph vocabulary currently describes:

```text
GROUP
INPUT
OUTPUT
DENSE
ACTIVATION
LOSS
BACKPROP
WEIGHT_UPDATE
WASM_CUSTOM
```

Planned input/runtime modules additionally include conceptual roles for:

```text
TOKEN_NEURON_CODEC
RESOLUTION_MAP
CONTEXT_SELECT
HALTING_DEFAULT
```

These are architecture roles until they earn concrete ABI/opcode definitions.

`GROUP` exists only for composition. It does not execute.

## 6. Custom Wasm neural modules

Module synchronization has a dedicated:

```text
ModuleKind::neural_wasm
```

A `WASM_CUSTOM` neural node references a normal V0ID `ModuleDescriptor` and requires the descriptor kind to be `NEURAL_WASM`.

The referenced module may be:

```text
PRIVATE_LOCAL
SHARED_SYNC
```

so a client can keep a private neural strategy/module local, or intentionally synchronize a content-addressed shared module.

The graph commitment binds the module descriptor/content digest; it does not execute arbitrary Wasm merely because a descriptor was received.

Future neural Wasm execution should follow the same narrow philosophy as the existing polymorphism Wasm seam:

```text
Wasm module
    |
    | implements allowed neural operations through typed ports
    v
validated neural runtime
    |
    v
chosen execution backend
```

Do not expose raw CUDA/TFHE pointers or arbitrary host access to neural Wasm.

## 7. Context identity, location and protection

Context selection has two independent questions:

1. **Where is the context object?**
2. **Is its content clear or encrypted for this execution?**

The current `NeuralContextRef` models location:

```text
LOCAL_CLIENT
CLOUD_CONTENT_ADDRESSED
```

The planned invocation model adds a protection choice:

```text
PLAINTEXT_CONTEXT
ENCRYPTED_CONTEXT
```

These axes deliberately remain separate.

Examples:

```text
LOCAL_CLIENT + PLAINTEXT_CONTEXT
    -> local clear/debug execution

LOCAL_CLIENT + ENCRYPTED_CONTEXT
    -> client selects locally, encrypts, sends ciphertext context

CLOUD_CONTENT_ADDRESSED + PLAINTEXT_CONTEXT
    -> evaluator resolves known clear context by checksum

CLOUD_CONTENT_ADDRESSED + ENCRYPTED_CONTEXT
    -> evaluator resolves encrypted context object by checksum and keeps it encrypted
```

Every context carries a nonzero SHA3-512 checksum/digest identifying the exact context object or canonical ciphertext/container object required by the selected profile.

Conceptually:

```text
context source
    |
    +--> local bytes
    |       |
    |       +--> optional encryption
    |
    +--> content-addressed cloud object
            |
            +--> clear object
            +--> encrypted object
    |
    v
ContextRef + ContextProtection
    |
    v
CONTEXT typed neural port
```

The checksum answers **which context object** is requested. It is not authorization by itself.

A remote neural invocation should eventually bind at least:

```text
graph digest
token/neuron codec identity
resolution-map identity
context digest(s)
context location(s)
context protection mode(s)
model-state/weight digest
job id
epoch
execution profile
halting/default-module policy
```

before remote execution starts.

## 8. Execution mode

`NeuralInvocation` currently selects:

```cpp
NeuralExecutionMode::plain_cpu
NeuralExecutionMode::tfhe_cuda
```

This is intentionally an invocation property.

A user should be able to take exactly the same graph and say:

```text
run this locally/clear for speed and debugging
```

or:

```text
run this through the confidential TFHE backend
```

without serializing a different model format.

The same idea applies to context protection: graph identity remains stable while the invocation says whether a particular context enters the graph in clear or encrypted form.

The backend interface begins at:

```cpp
class NeuralExecutionBackend {
public:
    virtual ~NeuralExecutionBackend() = default;
    virtual NeuralExecutionMode mode() const noexcept = 0;
};
```

Actual tensor execution APIs will be added only when the clear and encrypted tensor representations are defined cleanly.

## 9. Bounded execution and non-halting policy

V0ID must not claim to solve the halting problem.

Instead, every potentially non-terminating execution profile must have an explicit finite budget such as:

```text
maximum graph steps
maximum recurrent iterations
maximum Wasm instructions/fuel
maximum wall/runtime budget where applicable
```

When the budget is exhausted, the runtime produces a defined outcome rather than waiting forever.

Planned outcome classes:

```text
HALTED
INTERMEDIATE
DEFAULT_OUTPUT
NULL
ERROR
```

### Normal halt

```text
computation halts within budget
        -> HALTED
        -> return normal output
```

### Valid intermediate state

If the selected execution profile declares the current state checkpointable and semantically valid:

```text
budget exhausted
        -> INTERMEDIATE
        -> return/bind the latest valid intermediate state
```

For encrypted execution, the intermediate state remains encrypted unless the client explicitly decrypts it.

### Server-side halting default module

An evaluator/execution class may configure a server-side **halting default module**.

```text
budget exhausted
        |
        +--> valid intermediate requested/available -> INTERMEDIATE
        |
        +--> otherwise invoke HALTING_DEFAULT_MODULE
                                  |
                                  +--> valid bounded result -> DEFAULT_OUTPUT
                                  |
                                  +--> no valid result      -> NULL
```

The default module is not an unbound server implementation detail. Its module id, version, digest, ABI and execution budget must be advertised and bound into the execution profile/invocation before the client accepts the job.

That prevents an evaluator from silently changing fallback semantics after the job begins.

The default module itself is also bounded. If it exhausts its own budget, traps, fails validation or cannot emit an output matching the declared output-port schema, the runtime returns `NULL` or `ERROR` according to the profile rather than recursively invoking another unbounded fallback.

For the homomorphic backend, a halting default module must either:

- operate on the encrypted/intermediate representation through allowed neural operations; or
- produce a canonical encrypted-compatible fallback value/output shape.

It must not require the evaluator to decrypt client-private neural state.

This is a **bounded non-halting policy**, not a decision procedure for whether arbitrary programs would eventually halt.

## 10. Canonical graph and invocation commitments

`NeuralGraph::digest512()` computes SHA3-512 over a canonical representation of:

```text
protocol id
graph id/version
module ids
module parent relationships
module operation kinds
port names/schema/state flags
referenced Wasm module identities/digests
dataflow edges
```

Node, port and edge vector ordering does not alter the commitment.

`NeuralInvocation::digest512()` separately binds the requested run, including the graph identity, execution mode, context identities/locations and optional model-state identity.

The planned invocation commitment should be extended to bind the token/neuron codec, resolution map, context protection modes and halting/default-module policy as those ABIs become concrete.

This makes:

```text
same graph + plaintext context
```

and:

```text
same graph + encrypted context
```

or:

```text
same graph + different server halting-default module
```

distinct requested executions.

## 11. Planned distributed homomorphic shape

The module tree does not dictate placement. A scheduler can map modules/subgraphs independently:

```text
NeuralGraph
   |
   +-- encoder.token-codec -> worker A or trusted client
   +-- encoder.quantizer   -> worker A
   +-- encoder.block0      -> worker A
   +-- encoder.block1      -> worker B
   +-- trainer.loss        -> worker C
```

Encrypted typed port values can cross worker boundaries:

```text
token/context input
       |
 token-neuron codec
       |
 resolution mapping
       |
 encrypted activation
       v
worker A
   |
 encrypted activation
   v
worker B
   |
 encrypted activation / loss
   v
worker C
```

Backprop reverses the gradient flow while keeping the same typed-port model.

A distributed encrypted context can remain ciphertext throughout routing. A clear context can intentionally enter a clear backend or be encrypted at a defined trust boundary before it enters homomorphic workers.

## 12. Model state and weight updates

`NeuralInvocation` can already bind an optional `model_state_digest`.

The planned state lifecycle is:

```text
weights W_t
    |
 feedforward
    |
   loss
    |
 backprop
    |
 gradient
    |
 weight-update
    |
weights W_t+1
```

For encrypted execution, the goal is to permit encrypted model/optimizer state to remain resident in a bounded evaluator session between steps, while the client retains the decryption authority.

This requires a separate state/checkpoint protocol; it is not silently added to the current TFHE Boolean cloud session.

The non-halting policy applies to training/recurrent workloads too: a bounded training step may return a valid encrypted intermediate checkpoint, a bound default-module output, or null rather than becoming an unbounded cloud job.

## 13. Testing strategy

Use the same split already useful elsewhere in V0ID:

```text
large neural graph
    -> clear/fixed-point local semantic tests

small neural graph
    -> real encrypted backend tests

large encrypted neural graph
    -> explicit heavyweight stress benchmark
```

Additional differential tests should cover:

- token -> firing pattern -> token round trips;
- deterministic resolution buckets and tie-breaking;
- clear quantization versus encrypted quantization agreement;
- plaintext-context versus encrypted-context semantic agreement where policy permits comparison;
- normal halt versus budget exhaustion;
- intermediate-state return;
- server default-module fallback;
- default-module timeout/trap -> NULL/ERROR;
- commitment changes when codec, resolution, context protection or fallback module changes.

Do not make a full encrypted training network the first correctness test.

## 14. Current implemented scaffold

The current code provides:

- hierarchical module-tree validation;
- typed tensor ports;
- separate dataflow edges;
- feedforward/backprop/weight-update operation identities;
- `NEURAL_WASM` content-addressed module kind;
- local or cloud-content-addressed context references;
- user-selectable plain or TFHE execution mode;
- canonical SHA3-512 neural graph commitment;
- invocation commitment over graph/mode/context/model-state identity;
- fail-closed graph/shape/module/context validation.

Architecture now specified, but still to implement:

- token <-> firing-neuron codec ABI;
- numeric resolution / nearest-neighbor mapper;
- explicit plaintext/encrypted context protection field;
- server halting-default module profile and bounded outcome ABI;
- plain fixed-point CPU numerical executor;
- concrete neural Wasm ABI/runtime;
- TFHE tensor lowering and kernels;
- encrypted weight/model-state residency;
- distributed neural worker placement/routing;
- training/checkpoint protocol;
- execution-soundness evidence for distributed encrypted training.
