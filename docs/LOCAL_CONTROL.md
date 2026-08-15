# V0ID Local Control Plane

This is the first local operator/web interface for V0ID. It is intentionally a
small client-side control ABI, not a second cloud protocol.

## Trust boundary

The local V0ID process is authoritative. The PHP pages are only operator UIs.
The remote evaluator is still the untrusted/limited party.

The client is allowed to know its own models, module wiring, Series-First
configuration, job inputs/outputs and progress. The long-lived issuer-private
SeriesSeed currently remains process-local by default simply because serializing
it into browser-visible state is unnecessary; this is not a claim that the local
client must be hidden from itself.

The encrypted cloud page follows the intended split:

```text
browser
  |
  | localhost HTTP
  v
web/cloud.php
  |
  | local JSON command
  v
v0id-local-control
  |
  | trusted client preparation
  | TFHE ClientKey stays local
  | encrypt program/input locally
  v
ZeroMQ CURVE/ZAP cloud transport
  |
  v
remote evaluator
  |
  | server/evaluation key + ciphertext only
  | encrypted chunk execution
  v
encrypted result
  |
  v
local client decryption
  |
  v
cloud_state.json -> browser progress/result
```

The dashboard itself does not need to run on the remote evaluator. The runtime
directory should remain outside the HTTP document root.

## Local module / Series-First interface

`web/index.php` exposes the existing V0ID abstractions rather than reimplementing
them in PHP:

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

The ordinary local-control directory remains:

```text
state.json
registry.json
commands/*.json
responses/*.json
uploads/*.wasm
modules/<sha3-512>.wasm
```

## Remote encrypted TFHE interface

GPU builds now add a second worker to the same `v0id-local-control` process. It
uses a separate queue so a long encrypted remote job cannot consume or reorder
module/Series-First administrative commands:

```text
cloud_state.json
cloud_registry.json
cloud_commands/*.json
cloud_responses/*.json
```

`web/cloud.php` can:

1. configure an existing remote evaluator endpoint;
2. select the local CURVE client key files and pinned server public key file;
3. select the expected authenticated server peer id;
4. choose timeout, exact-request retry attempts and encrypted chunk size;
5. submit a `BooleanProgramImage` plus its input words;
6. watch trusted-client preparation, encrypted chunk submission, remote chunk
   completion, result retrieval and local decryption progress;
7. display the final locally decrypted output words.

The current remote job format is the existing compact Boolean VM. The page accepts
all current `BooleanProgramOpcode` values:

```text
XOR2
XOR5
XOR_ROT1
ROT_COPY
CHI
XOR_INPUT
XOR_CONST
```

The page contains a one-instruction identity example by default, but the JSON
editor can submit any program accepted by `BooleanProgramImage::validate()` and
the existing TFHE cloud protocol limits.

The C++ adapter is `execute_boolean_program_tfhe_cloud()`. It reuses the existing:

- TFHE CUDA client preparation API;
- encrypted instruction chunk API;
- typed `TfheCloudInstall`, `TfheCloudChunk`, `TfheCloudFinish`, and result codec;
- ZeroMQ CURVE/ZAP authenticated transport;
- local TFHE decryption API.

It does not create a separate cloud wire protocol.

## Retry semantics

For a transport failure, the client reconnects and resends the **exact same**
authenticated request. This matches the server-side idempotent replay window:

```text
chunk request -> server executes -> ACK lost
same chunk request -> cached ACK returned, no re-execution

finish request -> result built -> RESULT lost
same finish request -> cached encrypted result returned
```

The control-plane setting is named `retry_attempts`; it is the total number of
attempts for one exact request, including the first send.

## Progress

The local module/Series-First page polls `state.json`. The encrypted cloud page
polls `cloud_state.json`. Both are atomically replaced JSON snapshots.

Cloud stages include:

```text
plaintext-oracle          optional cheap local reference
client-key-generation
client-client-encryption
client-prepare
remote-install
encrypt-chunk
remote-execution
transport-retry
remote-finish
client-decrypt
verify
completed / failed
```

The current request/reply cloud protocol reports remote progress at **chunk
boundaries**, not instruction-by-instruction while a remote request is still in
flight. Lowering `instruction_chunk_size` gives more frequent remote progress
updates at the cost of more network request/ack boundaries.

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

## Build and run

The `gpu-fhe` preset now includes the TFHE remote-control hook. Reconfigure after
pulling because the preset project include changed:

```bash
cmake --preset gpu-fhe
cmake --build --preset gpu-fhe --target v0id-local-control
```

Start the local C++ client/control process:

```bash
mkdir -p /tmp/v0id-control
./build-gpu/v0id-local-control /tmp/v0id-control
```

Start PHP on loopback only:

```bash
V0ID_CONTROL_ROOT=/tmp/v0id-control \
php -S 127.0.0.1:8080 -t web
```

Open:

```text
http://127.0.0.1:8080/           module / Series-First interface
http://127.0.0.1:8080/cloud.php  encrypted remote execution interface
```

The PHP process and C++ process need filesystem permissions to the same runtime
directory.

## Remote evaluator

The remote machine still runs the existing evaluator/server side. For example,
a test evaluator generated through `v0id-tfhe-cloud keygen` can be launched with
the existing server command and an allowlisted client public key. The local cloud
page then points at that server's `tcp://host:port` endpoint and pins the server
public key locally.

The remote evaluator receives no TFHE ClientKey and no plaintext program/input
through this interface. The final encrypted result is returned to the local
client and decrypted there.
