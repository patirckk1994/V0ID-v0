# V0ID MLP port precompiler

> Status: implemented graph-expansion scaffold. This does not yet perform numerical feedforward, backpropagation or TFHE tensor execution; it generates and validates the exact low-level neural graph/port structure those backends will consume.

The MLP precompiler exists to avoid hand-writing hundreds of repetitive neural ports and edges for ordinary multilayer perceptrons.

A compact description such as:

```cpp
v0id::neural::MlpPrecompileSpec spec;
spec.graph_id = "example-mlp";
spec.batch_size = 8;
spec.input_size = 64;
spec.layers = {
    {32, true},
    {16, true},
    {4,  false},
};
spec.training = v0id::neural::MlpTrainingMode::backprop_sgd;

auto compiled = v0id::neural::MlpPortPrecompiler::compile(spec);
```

expands into a normal `NeuralGraph`.

## Forward expansion

For a dense layer with:

```text
batch size = B
input width = N
output width = M
```

it emits:

```text
weight parameter   [N,M]
bias parameter     [M]

DENSE
    x              [B,N]   ACTIVATION input
    weight         [N,M]   WEIGHT input
    bias           [M]     BIAS input
    y              [B,M]   ACTIVATION output
```

If the layer requests an activation node:

```text
DENSE.y [B,M]
     |
     v
ACTIVATION.x [B,M]
     |
     v
ACTIVATION.y [B,M]
```

Layer sizes are generic. No separate `Dense768x512`, `Dense512x256`, etc. operation classes are created.

## Parameter modules

Each layer gets content-addressable graph identities for its mutable parameter ports:

```text
parameters.layer.0.weight
parameters.layer.0.bias
parameters.layer.1.weight
parameters.layer.1.bias
...
```

The current scaffold represents those parameter sources with the generic `INPUT` graph operation and typed `WEIGHT` / `BIAS` output ports. Actual model-state storage/checkpoint ownership remains a later runtime concern.

## Training expansion

When `MlpTrainingMode::backprop_sgd` is selected, the precompiler additionally emits:

```text
trainer.target
trainer.loss
trainer.learning-rate

for each layer, reverse order:
    trainer.layer.N.backprop
    trainer.layer.N.weight-update
```

### Backprop macro

For a forward layer `N -> M`:

```text
BACKPROP
    gradient_in       [B,M]   GRADIENT input
    activation_in     [B,N]   ACTIVATION input
    preactivation     [B,M]   ACTIVATION input
    activation_out    [B,M]   ACTIVATION input
    weight            [N,M]   WEIGHT input

    gradient_out      [B,N]   GRADIENT output
    weight_gradient   [N,M]   GRADIENT output
    bias_gradient     [M]     GRADIENT output
```

The precompiler deliberately feeds both the dense preactivation and the post-activation value into the reverse-pass node. That keeps enough forward state available for a later numerical backend to implement activation derivatives without having to reconstruct hidden intermediate values from unrelated graph state.

The reverse gradient chain is generated automatically:

```text
loss.gradient
      |
      v
backprop.last.gradient_in
      |
backprop.last.gradient_out
      |
      v
backprop.previous.gradient_in
      |
     ...
```

### SGD update macro

Each layer also receives:

```text
WEIGHT_UPDATE
    weight             [N,M]   WEIGHT input
    weight_gradient    [N,M]   GRADIENT input
    bias               [M]     BIAS input
    bias_gradient      [M]     GRADIENT input
    learning_rate      [1]     CONTROL input

    updated_weight     [N,M]   WEIGHT output
    updated_bias       [M]     BIAS output
```

This is the structural representation of the intended update:

```text
W(t+1) = W(t) - learning_rate * dW
b(t+1) = b(t) - learning_rate * db
```

The numerical executor has not yet been implemented, so the current code does not claim to execute those arithmetic equations.

## Backend neutrality

The precompiler never chooses encryption.

```text
MlpPrecompileSpec
       |
       v
MlpPortPrecompiler
       |
       v
NeuralGraph
       |
       +--> NeuralInvocation(PLAIN_CPU)
       |
       +--> NeuralInvocation(TFHE_CUDA)
```

This prevents the project from acquiring two incompatible model languages such as `PlainMLPCompiler` and `EncryptedMLPCompiler`.

The same graph identity should be usable by the future clear fixed-point oracle and the future homomorphic backend.

## Why precompile before numerical execution

The precompiler provides a deterministic structural boundary where V0ID can reject invalid models cheaply before expensive encrypted execution begins.

Examples:

```text
layer output width 512
next layer input width 768
    -> rejected during graph construction/validation
```

instead of discovering the mismatch after a long TFHE job.

It also gives the future TFHE lowering backend a normalized graph with explicit tensor dimensions rather than asking it to infer dimensions from ad-hoc user code.

## Current tests

The existing `v0id-test-neural-graph` regression target now also checks:

- generic inference MLP expansion;
- derived `[B,N]`, `[N,M]`, `[M]`, `[B,M]` port dimensions;
- multi-layer forward wiring;
- automatic loss/target/training structure;
- reverse backprop gradient chain;
- generic weight/bias gradient dimensions;
- SGD weight-update ports;
- deterministic precompilation;
- graph commitment changes when a layer width changes;
- fail-closed zero input/layer dimensions.

Run:

```bash
cmake --build --preset gpu-fhe --target v0id-test-neural-graph
```

## Next numerical milestone

The next runtime layer should consume the generated graph rather than bypass it:

```text
MLP precompiler
     |
     v
NeuralGraph
     |
     +--> plain fixed-point executor
     |       feedforward
     |       loss
     |       backprop
     |       SGD
     |
     +--> TFHE lowering later
```

This keeps the plain implementation useful as the semantic oracle for encrypted differential tests.
