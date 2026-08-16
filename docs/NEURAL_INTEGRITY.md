# V0ID neural execution integrity scaffold

> Status: implemented structural trace/checkpoint scaffold. This does **not** yet prove that neural arithmetic was executed correctly. It provides the trace and known-answer interfaces needed for the future plain semantic verifier and hidden integrity lane.

## 1. Why the graph itself is not proof

`NeuralGraph` describes the computation that should run. Returning the same graph does not prove that an evaluator actually performed every transition.

V0ID now distinguishes:

```text
NeuralGraph
    intended topology / operations / typed ports

NeuralExecutionTrace
    concrete intermediate output values claimed for one invocation

NeuralIntegrityPlan
    client interpretation of selected ordinary trace outputs

NeuralIntegrityReceipt
    commitments to those selected outputs
```

The trace is bound to both:

```text
graph digest
invocation digest
```

so it cannot be silently transplanted to a different model or execution request.

## 2. Full execution trace

`NeuralExecutionTrace` contains `NeuralTraceEntry` records:

```text
step index
node id
port id
role
numeric format
shape
representation
value bytes
```

A trace entry may represent:

```text
CANONICAL_PLAINTEXT
OPAQUE_CIPHERTEXT
```

The latter is intended for serialized TFHE/ciphertext state returned by an encrypted evaluator. The trace commitment can bind those opaque bytes, but client-side known-answer checking requires the selected values to be decrypted/normalized first.

Structural validation checks:

- exact graph commitment;
- exact invocation commitment;
- referenced node exists;
- referenced port exists and is an output;
- role/format/shape exactly match the graph ABI;
- duplicate `(step,node,port)` coordinates are rejected;
- trace value sizes are bounded.

It deliberately does **not** claim that a `DENSE`, `ACTIVATION`, `BACKPROP`, or `WEIGHT_UPDATE` transition was mathematically correct.

## 3. Canonical trace commitment

Each trace entry has its own SHA3-512 commitment through the existing V0ID module-digest primitive. The commitment includes the endpoint and step, so the same bytes moved to another neuron/port do not retain the same commitment.

Conceptually:

```text
EntryCommitment = H(
    step
    || node
    || port
    || role
    || numeric format
    || tensor shape
    || representation
    || value bytes
)
```

The complete trace commitment binds the graph, invocation, and canonicalized set of entry commitments.

Vector ordering does not change the trace digest; `step_index` carries logical ordering.

## 4. Integrity checkpoints use ordinary neural outputs

The integrity design intentionally does **not** add an obvious opcode such as:

```text
CHECKSUM_NODE
```

Instead, `NeuralIntegrityPlan` references ordinary output ports already present in the neural graph:

```text
checkpoint "middle"
    -> step 12
    -> forward.layer.3.activation.y

checkpoint "final"
    -> step 27
    -> forward.layer.7.dense.y
```

This keeps the integrity interpretation separate from the neural operation vocabulary.

A future hidden checksum/integrity precompiler can therefore construct its lane from ordinary operations such as:

```text
DENSE
ACTIVATION
DENSE
ACTIVATION
```

while the client privately knows which ordinary outputs belong to the integrity circuit.

This scaffold does not yet attempt to hide graph topology or access patterns from an evaluator.

## 5. Known-answer receipt

`make_neural_integrity_receipt()` selects the requested checkpoint trace entries and commits to them.

For a known-answer integrity circuit, the client independently holds:

```text
NeuralIntegrityExpectation
```

bound to the same:

```text
graph
invocation
integrity plan
```

Verification succeeds only when every expected checkpoint commitment equals the observed commitment.

This is suitable for a future predefined integrity lane whose outputs are predictable by the client while appearing as ordinary neural computation to the evaluator.

## 6. Encrypted execution

For TFHE execution the intended flow is:

```text
server executes encrypted NeuralGraph
        |
        v
opaque ciphertext execution trace
        |
        v
client receives trace
        |
        v
client decrypts / canonicalizes selected values
        |
        v
known-answer integrity receipt
        |
        v
compare against client expectation
```

The server never needs the TFHE client key.

The current scaffold refuses to construct a known-answer receipt directly from an `OPAQUE_CIPHERTEXT` checkpoint. This prevents accidentally comparing randomized ciphertext bytes to an expected plaintext value.

## 7. Stronger full-trace verification

The header also defines:

```cpp
class NeuralTraceSemanticVerifier
```

as the boundary for a future backend-specific full replay verifier.

The next plain fixed-point neural backend should implement semantic verification first:

```text
returned full trace
      |
      v
PlainFixedPoint semantic replay
      |
      +-> verify Dense arithmetic
      +-> verify activation arithmetic
      +-> verify loss
      +-> verify backprop
      +-> verify SGD updates
```

That gives V0ID a development oracle before attempting the same operations under TFHE.

## 8. Security claim boundary

Current implemented claim:

```text
A trace/receipt is cryptographically bound to one graph, one invocation,
and exact claimed intermediate values at declared ordinary output ports.
```

Not currently claimed:

```text
The evaluator necessarily executed every requested neural transition.
```

A malicious evaluator can still fabricate a self-consistent trace unless the client independently checks transition semantics or uses a stronger proof system.

The planned integrity lane is therefore a cheap known-answer/probabilistic detector, while full semantic replay is the development-grade verifier. Succinct proof systems remain a possible later layer rather than being implied by this scaffold.

## 9. Regression coverage

The existing target:

```bash
cmake --build --preset gpu-fhe --target v0id-test-neural-graph
```

now additionally checks:

- graph/invocation-bound execution traces;
- canonical trace commitments;
- changed trace values change the commitment;
- trace/port schema mismatches fail closed;
- integrity plans over ordinary output ports;
- known-answer integrity receipts;
- changed expected integrity values are rejected;
- opaque ciphertext checkpoints require client normalization;
- wrong graph bindings fail closed;
- integrity checkpoints cannot target input ports.

The arithmetic executor is intentionally still a later milestone.
