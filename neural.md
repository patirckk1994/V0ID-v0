# V0ID Neural Architecture

> Status: architecture and structural execution scaffolding are implemented; numerical neural execution is the next major milestone. This document intentionally separates what exists today from what is planned.

V0ID treats neural computation as a typed, backend-neutral execution graph that can later run either in clear fixed-point form or through the TFHE/CUDA encrypted backend.

The architecture has three main layers:

```text
high-level neural description
        |
        v
MLP / graph precompiler
        |
        v
NeuralGraph
        |
        v
NeuralInvocation
        |
        +--> PLAIN_CPU
        |
        +--> TFHE_CUDA
        |
        v
NeuralExecutionTrace
        |
        v
Neural integrity / semantic verification
```

The core design rule is that **model identity, execution policy, and execution proof/integrity are separate concepts**.

---

## 1. NeuralGraph

`NeuralGraph` is the canonical model representation.

It contains:

```text
module tree
+ typed ports
+ dataflow edges
+ optional neural Wasm module identities
```

The module tree describes human/auditable composition. The dataflow graph describes actual tensor flow.

This distinction is intentional.

A model may look hierarchically like:

```text
model
├─ encoder
│  ├─ dense-0
│  ├─ activation-0
│  └─ dense-1
└─ trainer
   ├─ loss
   ├─ backprop
   └─ weight-update
```

while the dataflow graph is free to express residual paths, gradient routing, shared state, parameter reuse, and other connections that do not naturally fit a strict tree.

Current built-in graph operations are:

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

Current typed port roles are:

```text
ACTIVATION
GRADIENT
WEIGHT
BIAS
CONTEXT
LOSS
CONTROL
```

Current numeric formats are deliberately fixed/integer oriented:

```text
UINT8
INT8
UINT16
INT16
FIXED16_16
FIXED8_24
```

This avoids pretending the encrypted backend already supports arbitrary floating-point neural execution.

Every edge is validated against:

```text
source/output direction
source/destination shape
numeric format
port role
single-driver input rule
```

A graph therefore rejects malformed tensor wiring before expensive execution begins.

---

## 2. Generic MLP port precompiler

Ordinary multilayer perceptrons would be painful to construct by hand, so V0ID includes a generic MLP precompiler.

A compact description such as:

```cpp
input_size = 4;
layers = {
    {8, true},
    {6, true},
    {3, false}
};
```

expands to:

```text
input [B,4]
    |
    v
Dense 4 -> 8
    |
Activation
    |
    v
Dense 8 -> 6
    |
Activation
    |
    v
Dense 6 -> 3
    |
    v
output [B,3]
```

For a generic dense layer:

```text
B = batch size
N = input width
M = output width
```

it derives:

```text
x       [B,N]
weight  [N,M]
bias    [M]
y       [B,M]
```

The associated parameter modules look like:

```text
parameters.layer.0.weight
parameters.layer.0.bias
parameters.layer.1.weight
parameters.layer.1.bias
...
```

There are no separate `Dense768x512`, `Dense512x256`, etc. operation classes. Layer sizes are data.

---

## 3. Training graph

When training mode is enabled, the same precompiler generates the reverse/training side:

```text
forward pass
    |
    v
loss
    |
    v
gradient
    |
    v
Backprop last layer
    |
    v
Backprop previous layer
    |
   ...
```

For each forward layer `N -> M`, the backprop structure exposes:

```text
gradient_in      [B,M]
activation_in    [B,N]
preactivation    [B,M]
activation_out   [B,M]
weight           [N,M]

-> gradient_out      [B,N]
-> weight_gradient   [N,M]
-> bias_gradient     [M]
```

The preactivation and post-activation outputs are both retained because a future numerical backend needs the forward state required by activation derivatives.

Each layer also receives an SGD update structure:

```text
weight
weight_gradient
bias
bias_gradient
learning_rate
    |
    v
updated_weight
updated_bias
```

Conceptually:

```text
W(t+1) = W(t) - learning_rate * dW
b(t+1) = b(t) - learning_rate * db
```

The current implementation generates and validates this structure. Numerical execution of these equations is the next runtime milestone.

---

## 4. Execution policy is separate from model identity

The graph does not become a different model just because encryption is enabled.

```text
                 NeuralGraph
                     |
              NeuralInvocation
                     |
             +-------+-------+
             |               |
         PLAIN_CPU       TFHE_CUDA
```

`NeuralInvocation` selects execution mode and binds the run to the exact graph, selected contexts, and optional model/weight state.

This matters because V0ID wants the clear backend to become the semantic oracle for the encrypted backend.

The intended future testing model is:

```text
same graph
same inputs
same model state

PLAIN_CPU result
       vs
TFHE_CUDA result
```

rather than maintaining separate clear and encrypted neural languages.

---

## 5. Context model

Context is currently identified by name, location, and a nonzero digest.

Current locations are:

```text
LOCAL_CLIENT
CLOUD_CONTENT_ADDRESSED
```

The architecture additionally plans an independent protection axis:

```text
PLAINTEXT
HOMOMORPHIC_ENCRYPTED
```

The intended combinations are:

```text
local + plaintext
local + encrypted
cloud + plaintext
cloud + encrypted
```

The checksum identifies **which context object** is requested. It is not authorization by itself.

For encrypted cloud execution, the evaluator should operate on ciphertext context without receiving the client decryption key.

---

## 6. Token -> neuron and numeric resolution input path

The planned neural input pipeline is:

```text
tokens
  |
  v
TokenNeuronCodec
  |
  v
firing-neuron representation
  |
  v
Resolution / nearest-neighbor mapper
  |
  v
Context injection
  |
  v
NeuralGraph
```

The token/neuron codec is intended to remain pluggable. A token may map to:

```text
one firing neuron
sparse firing pattern
another bounded canonical activation representation
```

The numeric resolution mapper defines a finite representable input set over a range `[L,H]` and maps arbitrary inputs to the nearest representable value using deterministic tie-breaking.

These components are architecture-level until they receive concrete ABI types and execution semantics.

---

## 7. Neural execution trace

The neural integrity layer begins with an explicit execution trace.

A `NeuralExecutionTrace` records concrete outputs observed during execution:

```text
step 0:
    forward.input.activation

step 1:
    forward.layer.0.dense.y

step 2:
    forward.layer.0.activation.y

step 3:
    forward.layer.1.dense.y

...
```

Each trace entry records:

```text
step index
node ID
port ID
port role
numeric format
tensor shape
representation
value bytes
```

Representations are currently:

```text
CANONICAL_PLAINTEXT
OPAQUE_CIPHERTEXT
```

This allows a TFHE evaluator to return encrypted intermediate state without pretending that the server can interpret the plaintext.

A trace commitment is bound to:

```text
graph digest
invocation digest
all trace entries
```

Changing the value, endpoint, step, schema, or representation changes the commitment.

**Important:** a trace commitment proves which trace was returned. It does not by itself prove that the neural arithmetic was executed correctly.

---

## 8. Neural integrity checkpoints

V0ID intentionally does not define a special `CHECKSUM_NODE` neural opcode.

Instead, `NeuralIntegrityPlan` references ordinary neural output ports:

```text
layer output
activation output
loss output
backprop output
weight-update output
...
```

This leaves open the stronger future design where a hidden integrity circuit is compiled from ordinary `DENSE`, `ACTIVATION`, and similar operations.

Conceptually:

```text
                 normal neural computation

input
  |
  v
Dense 0
  |
  v
Activation 0  <---- integrity checkpoint A
  |
  v
Dense 1
  |
  v
Activation 1  <---- integrity checkpoint B
  |
  v
Dense 2       <---- integrity checkpoint C
  |
  v
output
```

A receipt binds:

```text
graph digest
invocation digest
trace digest
integrity-plan digest
observed checkpoint commitments
```

Receipt validation re-derives the checkpoint commitments from the supplied trace. A server therefore cannot satisfy the receipt API merely by attaching the expected checksum values to an unrelated trace.

---

## 9. Hidden neural integrity lane: planned direction

The stronger planned mechanism is a checksum/integrity lane that runs through the real neural computation while looking structurally similar to normal neural work.

The design goal is not:

```text
ordinary neuron
ordinary neuron
CHECKSUM NEURON
ordinary neuron
```

but something closer to:

```text
Dense
Activation
Dense
Activation
Dense
```

where only the client knows which values or paths are serving an integrity role.

The integrity lane should consume actual intermediate network state.

Conceptually:

```text
C0 = secret or independently predictable challenge

C1 = F(C0, layer0_state)
C2 = F(C1, layer1_state)
C3 = F(C2, layer2_state)
...
Cn = final integrity witness
```

This requirement is critical. An independent side-network would only prove that the side-network ran correctly; it would not force correct execution of the useful network.

The polymorphic-series machinery may later be used to derive placement, challenge coefficients, decoys, or other hidden interpretation data, but that is not yet wired into the neural integrity implementation.

---

## 10. Full semantic verification

A `NeuralTraceSemanticVerifier` interface exists for the stronger development mode:

```text
server executes graph
      |
      v
returns complete trace
      |
      v
client replays every operation
      |
      v
checks every transition
```

This is expensive in communication but extremely valuable during development.

The immediate plan is:

```text
PlainFixedPointNeuralBackend
          |
          +--> executes DENSE
          +--> executes ACTIVATION
          +--> executes LOSS
          +--> executes BACKPROP
          +--> executes SGD
          |
          v
NeuralExecutionTrace
          |
          v
Plain semantic replay verifier
```

Once the plain backend becomes the reference semantics, the encrypted TFHE backend can be checked against the same graph and execution model.

---

## 11. Bounded execution and default outcome policy

V0ID does not claim to solve the halting problem.

Potentially nonterminating execution must instead run under explicit finite budgets such as:

```text
maximum graph steps
maximum recurrent iterations
maximum Wasm fuel
maximum execution rounds
runtime limits where applicable
```

Planned outcomes are:

```text
HALTED
INTERMEDIATE
DEFAULT_OUTPUT
NULL
ERROR
```

A configured server-side halting-default module may provide bounded fallback output when the main execution exhausts its budget and no resumable checkpoint is returned.

The default module itself must be bounded and must not recurse into another fallback loop.

---

## 12. What exists now

Implemented/scaffolded today:

```text
NeuralGraph
module tree
validated typed dataflow
graph digest
NeuralInvocation
plain / TFHE backend selection
context identity/location
neural Wasm module identity
generic MLP precompiler
forward graph generation
training graph generation
backprop graph generation
SGD update graph generation
NeuralExecutionTrace
trace commitment
integrity plans
integrity receipts
known-answer checkpoint verification
semantic verifier interface
```

Current regression coverage includes the neural graph, MLP precompiler, backprop/SGD graph expansion, execution-trace binding, integrity checkpoints, known-answer receipts, and fail-closed validation behavior.

---

## 13. What does not exist yet

Not yet implemented as real numerical neural execution:

```text
plain fixed-point tensor executor
actual Dense arithmetic
actual activation arithmetic
actual loss arithmetic
actual backpropagation arithmetic
actual SGD state update
token/neuron codec
resolution mapper
context protection ABI
TFHE neural tensor lowering
encrypted neural backpropagation
hidden polymorphic integrity lane
cryptographic proof of full execution
```

The current integrity system is therefore a structural and known-answer verification scaffold, not a general proof-of-correct-execution system.

---

## 14. Recommended next milestone

The next major implementation step is the plain fixed-point neural executor.

```text
MlpPortPrecompiler
       |
       v
NeuralGraph
       |
       v
PlainFixedPointNeuralBackend
       |
       +--> feedforward
       +--> loss
       +--> backprop
       +--> SGD
       |
       v
NeuralExecutionTrace
       |
       v
semantic replay / known-answer tests
```

Only after this clear semantic oracle is stable should V0ID lower the same operations into TFHE/CUDA.

The intended progression is:

```text
1 neuron
    ->
1 dense layer
    ->
2 layers
    ->
tiny MLP
    ->
encrypted inference
    ->
encrypted backprop
    ->
encrypted weight update
```

This keeps failures local and makes the encrypted backend testable against a known correct implementation.

---

## 15. Architectural summary

```text
                 TOKEN / NUMERIC INPUT
                         |
                   [future codec]
                         |
                         v
                  MLP PRECOMPILER
                         |
                         v
                    NeuralGraph
                         |
            +------------+-------------+
            |                          |
       forward graph              training graph
            |                          |
     Dense / Activation       Loss / Backprop / SGD
            |                          |
            +------------+-------------+
                         |
                  NeuralInvocation
                         |
                +--------+--------+
                |                 |
            PLAIN_CPU         TFHE_CUDA
                |                 |
                +--------+--------+
                         |
                NeuralExecutionTrace
                         |
                  Trace Commitment
                         |
                Integrity Checkpoints
                         |
                  Integrity Receipt
                         |
                         v
                 CLIENT VERIFICATION
                         |
               +---------+----------+
               |                    |
      checkpoint verification   semantic replay
               |                    |
               +---------+----------+
                         |
                         v
              hidden integrity lane
                     [planned]
```

The result is a typed neural execution VM with model compilation, training structure, clear/encrypted backend selection, execution tracing, and a path toward hidden neural integrity circuits without conflating a returned trace with a cryptographic proof of correct execution.
