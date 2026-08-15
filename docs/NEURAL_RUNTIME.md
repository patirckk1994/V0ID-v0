# V0ID modular neural runtime

> Status: additive architecture scaffold. The graph/module/context ABI is implemented; the plain numerical executor and TFHE tensor-lowering backend are separate follow-up milestones.

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
│   ├── input
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

## 2. Typed port ABI

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

## 3. Built-in module operations

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

These are graph/ABI identities, not claims that every operation already has a production executor.

`GROUP` exists only for composition. It does not execute.

## 4. Custom Wasm neural modules

Module synchronization now has a dedicated:

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
    | emits/implements allowed neural operations through typed ports
    v
validated neural runtime
    |
    v
chosen execution backend
```

Do not expose raw CUDA/TFHE pointers or arbitrary host access to neural Wasm.

## 5. Context by checksum

`NeuralContextRef` has two current locations:

```text
LOCAL_CLIENT
CLOUD_CONTENT_ADDRESSED
```

Both carry a nonzero SHA3-512 checksum/digest.

Conceptually:

```text
local context bytes
      |
   SHA3-512
      |
 ContextDigest
```

or:

```text
ContextDigest
      |
      v
content-addressed cloud context object
```

The checksum answers **which context object** is requested. It is not authorization by itself.

Future cloud job/session binding should include at least:

```text
graph digest
context digest(s)
model-state/weight digest
job id
epoch
execution profile
```

before remote execution starts.

## 6. Execution mode

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

The backend interface begins at:

```cpp
class NeuralExecutionBackend {
public:
    virtual ~NeuralExecutionBackend() = default;
    virtual NeuralExecutionMode mode() const noexcept = 0;
};
```

Actual tensor execution APIs will be added only when the clear and encrypted tensor representations are defined cleanly.

## 7. Canonical graph commitment

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

This makes the graph identity about model structure rather than incidental in-memory ordering.

## 8. Planned distributed shape

The module tree does not dictate placement. A later scheduler can map modules/subgraphs independently:

```text
NeuralGraph
   |
   +-- encoder.block0 -> worker A
   +-- encoder.block1 -> worker A
   +-- encoder.block2 -> worker B
   +-- trainer.loss   -> worker C
```

Encrypted typed port values can then cross worker boundaries:

```text
worker A
   |
 encrypted activation
   v
worker B
   |
 encrypted activation
   v
worker C
```

Backprop reverses the gradient flow while keeping the same typed-port model.

## 9. Model state and weight updates

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

## 10. Testing strategy

Use the same split already useful elsewhere in V0ID:

```text
large neural graph
    -> clear/fixed-point local semantic tests

small neural graph
    -> real encrypted backend tests

large encrypted neural graph
    -> explicit heavyweight stress benchmark
```

Do not make a full encrypted training network the first correctness test.

## 11. Current implemented scaffold

The current code provides:

- hierarchical module-tree validation;
- typed tensor ports;
- separate dataflow edges;
- feedforward/backprop/weight-update operation identities;
- `NEURAL_WASM` content-addressed module kind;
- local or cloud-content-addressed context references;
- user-selectable plain or TFHE execution mode;
- canonical SHA3-512 neural graph commitment;
- fail-closed graph/shape/module/context validation.

Still to implement:

- plain fixed-point CPU numerical executor;
- concrete neural Wasm ABI/runtime;
- TFHE tensor lowering and kernels;
- encrypted weight/model-state residency;
- distributed neural worker placement/routing;
- training/checkpoint protocol;
- execution-soundness evidence for distributed encrypted training.
