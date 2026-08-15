# V0ID Local Control Plane

This is the first local operator/web interface for V0ID. It is intentionally a
small client-side control ABI, not a second cloud protocol.

## Trust boundary

The local V0ID process is authoritative. The PHP page is only an operator UI.
The remote evaluator is still the untrusted/limited party.

The client is allowed to know its own models, module wiring, Series-First
configuration, job inputs/outputs and progress. The long-lived issuer-private
SeriesSeed currently remains process-local by default simply because serializing
it into browser-visible state is unnecessary; this is not a claim that the local
client must be hidden from itself.

Current flow:

```text
browser
  |
  | localhost HTTP
  v
web/index.php
  |
  | reads state.json
  | atomically creates command JSON
  v
runtime root
  |-- state.json
  |-- registry.json
  |-- commands/*.json
  |-- responses/*.json
  |-- uploads/*.wasm
  `-- modules/<sha3-512>.wasm
  ^
  |
v0id-local-control
  |
  +-- Series-First stack
  +-- built-in KMACXOF256 series generator
  +-- POLYMORPHISM_WASM generator
  +-- module descriptors/bindings
  `-- MathVM/WAMR execution
```

The runtime directory should be outside the HTTP document root.

## What is wired now

The C++ control plane exposes the existing V0ID abstractions rather than
reimplementing them in PHP:

- built-in `KmacSeriesGenerator`;
- `PolymorphicSeriesGenerator` profile selection;
- `WasmSeriesGenerator` for a bound `POLYMORPHISM_WASM` module when MathVM/WAMR
  support is enabled;
- `SeriesFirstStackContext`, purpose-specific private stack series and the
  algorithm-later expansion boundary;
- `ModuleDescriptor` / content SHA3-512 / private-local vs shared-sync module
  metadata;
- binding slots for `series_generator`, `mathvm`, `strategy`, and `neural`;
- bounded local MathVM execution through the existing WAMR sandbox;
- progress snapshots which can be polled while the C++ process is busy.

The current control plane does **not** yet submit the existing streamed TFHE CUDA
cloud job. The state schema already treats computation/progress generically so a
future cloud-client adapter can publish the existing client/server progress
callbacks into the same UI without changing the PHP protocol.

## Module editing model

Wasm bytes are content-addressed and versioned. The dashboard can upload a new
module and edit runtime metadata such as MathVM entrypoint and primitive
requirements.

A `(kind, module_id, module_version)` identity cannot silently change to different
bytes. Uploading different code under the same identity fails; increment the
module version instead. This preserves the existing module commitment model.

The `series_generator` binding only accepts `POLYMORPHISM_WASM`; `mathvm` only
accepts `MATHVM_WASM`; `strategy` only accepts `STRATEGY_WASM`; and `neural` only
accepts `NEURAL_WASM`.

Shared bound modules are committed through `shared_module_set_digest512()` into
`SeriesFirstStackContext::shared_modules_binding` when a stack computation is
run.

## JSON command ABI

Commands use one immutable file per operation:

```json
{
  "protocol": "v0id-local-control-v1",
  "command_id": "4a95...",
  "command": "configure_series",
  "payload": {
    "mode": "kmacxof256",
    "series_bytes": 64
  }
}
```

Supported commands in this first slice:

```text
register_module
update_module_config
remove_module
bind_module
unbind_module
configure_series
run_computation
shutdown
```

`run_computation` currently supports:

```text
series_generator
series_first_stack
mathvm
```

## Progress

`state.json` contains a live computation object:

```json
{
  "computation": {
    "job_id": "...",
    "type": "series_first_stack",
    "state": "running",
    "stage": "algorithm-later",
    "current": 3,
    "total": 5,
    "percent": 60.0,
    "message": "expanding selected algorithm only after purpose series exists",
    "result": {}
  }
}
```

The PHP page polls the state endpoint once per second, so the progress display is
independent of the command-processing loop.

## Build and run

After pulling the branch, reconfigure once because the control target adds a
pinned `nlohmann_json` FetchContent dependency:

```bash
cmake --preset gpu-fhe
cmake --build --preset gpu-fhe --target v0id-local-control
```

For a non-GPU build, use whichever existing configure/build directory you use;
the local control target itself does not require OpenFHE CUDA/TFHE.

Start the C++ side:

```bash
mkdir -p /tmp/v0id-control
./build-gpu/v0id-local-control /tmp/v0id-control
```

In another shell, start PHP on loopback only:

```bash
V0ID_CONTROL_ROOT=/tmp/v0id-control \
php -S 127.0.0.1:8080 -t web
```

Then open `http://127.0.0.1:8080/` locally.

The PHP process and C++ process need filesystem permissions to the same runtime
directory.

## Next integration boundary

Do not add another cloud protocol for the dashboard. The next useful adapter is
to let the existing TFHE cloud client publish its real stages through the same
control state:

```text
client preparation
key/server material preparation
encrypted chunk generation
chunk upload
remote execution progress
output selection
result download
client decryption
```

The actual TFHE transport/session semantics remain the existing CURVE/ZAP + typed
multipart protocol.
