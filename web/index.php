<?php
declare(strict_types=1);

// Deliberately tiny local frontend: PHP never executes V0ID crypto itself. It
// reads the C++ snapshot and atomically queues JSON commands for the client-side
// LocalControlPlane. Run PHP bound to localhost and keep V0ID_CONTROL_ROOT out of
// the web document root.
$root = rtrim(getenv('V0ID_CONTROL_ROOT') ?: '/tmp/v0id-control', DIRECTORY_SEPARATOR);
$commandsDir = $root . DIRECTORY_SEPARATOR . 'commands';
$uploadsDir = $root . DIRECTORY_SEPARATOR . 'uploads';
$responsesDir = $root . DIRECTORY_SEPARATOR . 'responses';
$statePath = $root . DIRECTORY_SEPARATOR . 'state.json';

foreach ([$root, $commandsDir, $uploadsDir, $responsesDir] as $dir) {
    if (!is_dir($dir) && !mkdir($dir, 0770, true) && !is_dir($dir)) {
        http_response_code(500);
        exit('Unable to create V0ID control directory: ' . htmlspecialchars($dir));
    }
}

function h(mixed $value): string {
    return htmlspecialchars((string)$value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function read_json_file(string $path): ?array {
    if (!is_file($path)) return null;
    $raw = file_get_contents($path);
    if ($raw === false) return null;
    try {
        $value = json_decode($raw, true, 128, JSON_THROW_ON_ERROR);
        return is_array($value) ? $value : null;
    } catch (Throwable) {
        return null;
    }
}

function atomic_json_write(string $path, array $value): void {
    $tmp = $path . '.tmp.' . bin2hex(random_bytes(8));
    $encoded = json_encode($value, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . "\n";
    if (file_put_contents($tmp, $encoded, LOCK_EX) === false) {
        throw new RuntimeException('Unable to write command temp file');
    }
    if (!rename($tmp, $path)) {
        @unlink($tmp);
        throw new RuntimeException('Unable to publish command atomically');
    }
}

function queue_command(string $commandsDir, string $command, array $payload): string {
    $id = bin2hex(random_bytes(16));
    $record = [
        'protocol' => 'v0id-local-control-v1',
        'command_id' => $id,
        'command' => $command,
        'payload' => $payload,
        'submitted_unix_ms' => (int)floor(microtime(true) * 1000),
    ];
    atomic_json_write($commandsDir . DIRECTORY_SEPARATOR . $id . '.json', $record);
    return $id;
}

function parse_requirements(string $raw): array {
    $raw = trim($raw);
    if ($raw === '') return [];
    $decoded = json_decode($raw, true, 64, JSON_THROW_ON_ERROR);
    if (!is_array($decoded)) throw new RuntimeException('Primitive requirements must be a JSON array');
    return $decoded;
}

if (isset($_GET['api']) && $_GET['api'] === 'state') {
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    $state = read_json_file($statePath) ?? [
        'protocol' => 'v0id-local-control-v1',
        'revision' => 0,
        'status' => 'C++ control plane has not published state.json yet',
    ];
    echo json_encode($state, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    exit;
}

$message = '';
$error = '';
$queuedId = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        $action = (string)($_POST['action'] ?? '');
        if ($action === 'configure_series') {
            $queuedId = queue_command($commandsDir, 'configure_series', [
                'mode' => (string)($_POST['mode'] ?? 'kmacxof256'),
                'series_bytes' => max(1, (int)($_POST['series_bytes'] ?? 64)),
            ]);
        } elseif ($action === 'register_module') {
            if (!isset($_FILES['module_file']) || !is_uploaded_file($_FILES['module_file']['tmp_name'])) {
                throw new RuntimeException('Choose a Wasm module file first');
            }
            if ((int)$_FILES['module_file']['size'] <= 0 || (int)$_FILES['module_file']['size'] > 1024 * 1024) {
                throw new RuntimeException('Module upload must contain 1..1048576 bytes');
            }
            $uploadName = 'module-' . bin2hex(random_bytes(16)) . '.wasm';
            $target = $uploadsDir . DIRECTORY_SEPARATOR . $uploadName;
            if (!move_uploaded_file($_FILES['module_file']['tmp_name'], $target)) {
                throw new RuntimeException('Unable to move uploaded module into local staging');
            }
            $queuedId = queue_command($commandsDir, 'register_module', [
                'upload_name' => $uploadName,
                'kind' => (string)($_POST['kind'] ?? 'MATHVM_WASM'),
                'visibility' => (string)($_POST['visibility'] ?? 'PRIVATE_LOCAL'),
                'module_id' => trim((string)($_POST['module_id'] ?? '')),
                'module_version' => max(1, (int)($_POST['module_version'] ?? 1)),
                'entrypoint' => trim((string)($_POST['entrypoint'] ?? 'v0id_main')),
                'required_primitives' => parse_requirements((string)($_POST['required_primitives'] ?? '')),
            ]);
        } elseif ($action === 'update_module') {
            $queuedId = queue_command($commandsDir, 'update_module_config', [
                'module_key' => (string)($_POST['module_key'] ?? ''),
                'entrypoint' => trim((string)($_POST['entrypoint'] ?? 'v0id_main')),
                'required_primitives' => parse_requirements((string)($_POST['required_primitives'] ?? '')),
            ]);
        } elseif ($action === 'bind_module') {
            $queuedId = queue_command($commandsDir, 'bind_module', [
                'slot' => (string)($_POST['slot'] ?? ''),
                'module_key' => (string)($_POST['module_key'] ?? ''),
            ]);
        } elseif ($action === 'unbind_module') {
            $queuedId = queue_command($commandsDir, 'unbind_module', [
                'slot' => (string)($_POST['slot'] ?? ''),
            ]);
        } elseif ($action === 'remove_module') {
            $queuedId = queue_command($commandsDir, 'remove_module', [
                'module_key' => (string)($_POST['module_key'] ?? ''),
            ]);
        } elseif ($action === 'run_series_generator') {
            $queuedId = queue_command($commandsDir, 'run_computation', [
                'type' => 'series_generator',
                'epoch' => max(0, (int)($_POST['epoch'] ?? 0)),
                'input_hex' => preg_replace('/\s+/', '', (string)($_POST['input_hex'] ?? '')),
            ]);
        } elseif ($action === 'run_series_stack') {
            $queuedId = queue_command($commandsDir, 'run_computation', [
                'type' => 'series_first_stack',
                'job_id' => trim((string)($_POST['job_id'] ?? '')),
                'epoch' => max(0, (int)($_POST['epoch'] ?? 0)),
                'purpose' => (string)($_POST['purpose'] ?? 'execution-integrity'),
                'machine_protocol' => trim((string)($_POST['machine_protocol'] ?? 'v0id-local-control-v1')),
                'fhe_parameter_set' => trim((string)($_POST['fhe_parameter_set'] ?? 'LOCAL-CONTROL')),
                'semantic_text' => (string)($_POST['semantic_text'] ?? 'local-control-computation'),
                'algorithm_id' => trim((string)($_POST['algorithm_id'] ?? 'v0id-local-preview')),
                'algorithm_version' => max(1, (int)($_POST['algorithm_version'] ?? 1)),
                'algorithm_context_hex' => preg_replace('/\s+/', '', (string)($_POST['algorithm_context_hex'] ?? '')),
                'output_bytes' => max(1, (int)($_POST['output_bytes'] ?? 64)),
            ]);
        } elseif ($action === 'run_mathvm') {
            $queuedId = queue_command($commandsDir, 'run_computation', [
                'type' => 'mathvm',
                'module_key' => (string)($_POST['module_key'] ?? ''),
            ]);
        } else {
            throw new RuntimeException('Unknown dashboard action');
        }
        $message = 'Queued command ' . $queuedId;
    } catch (Throwable $e) {
        $error = $e->getMessage();
    }
}

$state = read_json_file($statePath) ?? [];
$modules = is_array($state['modules'] ?? null) ? $state['modules'] : [];
$bindings = is_array($state['bindings'] ?? null) ? $state['bindings'] : [];
$computation = is_array($state['computation'] ?? null) ? $state['computation'] : [];
$series = is_array($state['series_first'] ?? null) ? $state['series_first'] : [];

?><!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>V0ID Local Control</title>
<style>
body{font-family:system-ui,sans-serif;margin:0;background:#111;color:#eee}main{max-width:1200px;margin:auto;padding:24px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(330px,1fr));gap:16px}.card{background:#1b1b1b;border:1px solid #333;border-radius:10px;padding:16px;margin-bottom:16px}h1,h2,h3{margin-top:0}label{display:block;margin:8px 0 4px;color:#bbb}input,select,textarea,button{box-sizing:border-box;width:100%;padding:8px;background:#0d0d0d;color:#eee;border:1px solid #444;border-radius:6px}textarea{min-height:80px;font-family:monospace}button{margin-top:10px;cursor:pointer;background:#242424}.ok{padding:10px;background:#17351f}.err{padding:10px;background:#4a1818}.mono{font-family:monospace;overflow-wrap:anywhere}.progress{height:18px;background:#333;border-radius:9px;overflow:hidden}.bar{height:100%;background:#888;width:0}.small{font-size:.9em;color:#aaa}table{width:100%;border-collapse:collapse}td,th{padding:6px;border-bottom:1px solid #333;text-align:left;vertical-align:top}</style>
</head>
<body><main>
<h1>V0ID Local Control</h1>
<p class="small">Local operator interface. The C++ client is authoritative; PHP only reads state JSON and queues commands.</p>
<?php if ($message !== ''): ?><div class="ok"><?=h($message)?></div><?php endif; ?>
<?php if ($error !== ''): ?><div class="err"><?=h($error)?></div><?php endif; ?>

<div class="card">
<h2>Runtime state</h2>
<div>Revision: <span id="revision" class="mono"><?=h($state['revision'] ?? 0)?></span></div>
<div>Last error: <span id="last-error" class="mono"><?=h($state['last_error'] ?? '')?></span></div>
<h3>Computation</h3>
<div id="job-line" class="mono"><?=h(($computation['type'] ?? 'idle') . ' / ' . ($computation['stage'] ?? 'idle'))?></div>
<div class="progress"><div id="progress-bar" class="bar" style="width:<?=h((float)($computation['percent'] ?? 0))?>%"></div></div>
<div id="progress-text" class="small"><?=h((string)($computation['percent'] ?? 0))?>% — <?=h($computation['message'] ?? '')?></div>
<pre id="result-json" class="mono"><?=h(json_encode($computation['result'] ?? new stdClass(), JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES))?></pre>
</div>

<div class="grid">
<section class="card">
<h2>Series-First</h2>
<div>Mode: <b><?=h($series['mode'] ?? 'unknown')?></b></div>
<div class="mono small"><?=h(json_encode($series['selected_profile'] ?? new stdClass(), JSON_UNESCAPED_SLASHES))?></div>
<form method="post">
<input type="hidden" name="action" value="configure_series">
<label>Generator mode</label><select name="mode"><option value="kmacxof256">KMACXOF256 built-in</option><option value="module">Bound POLYMORPHISM_WASM module</option></select>
<label>Series bytes</label><input name="series_bytes" type="number" min="1" max="1048576" value="<?=h($series['series_bytes'] ?? 64)?>">
<button>Apply Series-First configuration</button>
</form>
</section>

<section class="card">
<h2>Run Series generator</h2>
<form method="post">
<input type="hidden" name="action" value="run_series_generator">
<label>Epoch</label><input name="epoch" type="number" min="0" value="0">
<label>Input bytes (hex)</label><textarea name="input_hex" placeholder="deadbeef"></textarea>
<button>Run derivation</button>
</form>
</section>

<section class="card">
<h2>Run Series-First stack</h2>
<form method="post">
<input type="hidden" name="action" value="run_series_stack">
<label>Job ID (optional)</label><input name="job_id" value="web-preview">
<label>Epoch</label><input name="epoch" type="number" min="0" value="0">
<label>Purpose</label><select name="purpose"><option>execution-integrity</option><option>polymorphism</option><option>machine-layout</option><option>quine-challenge</option><option>strategy-plugin</option><option>application-auth</option><option>job-receipt</option></select>
<label>Machine protocol</label><input name="machine_protocol" value="v0id-local-control-v1">
<label>FHE parameter set</label><input name="fhe_parameter_set" value="LOCAL-CONTROL">
<label>Semantic text</label><input name="semantic_text" value="local-control-computation">
<label>Algorithm ID</label><input name="algorithm_id" value="v0id-local-preview">
<label>Algorithm version</label><input name="algorithm_version" type="number" min="1" value="1">
<label>Algorithm context (hex)</label><textarea name="algorithm_context_hex"></textarea>
<label>Output bytes</label><input name="output_bytes" type="number" min="1" max="1048576" value="64">
<button>Run stack derivation</button>
</form>
</section>
</div>

<div class="card">
<h2>Modules</h2>
<table><thead><tr><th>Key</th><th>Kind</th><th>Visibility</th><th>Digest</th><th>Entrypoint</th></tr></thead><tbody>
<?php foreach ($modules as $m): ?><tr><td class="mono"><?=h($m['key'] ?? '')?></td><td><?=h($m['kind'] ?? '')?></td><td><?=h($m['visibility'] ?? '')?></td><td class="mono small"><?=h($m['digest_sha3_512'] ?? '')?></td><td><?=h($m['entrypoint'] ?? '')?></td></tr><?php endforeach; ?>
</tbody></table>
<div class="small">Bindings: <span class="mono"><?=h(json_encode($bindings, JSON_UNESCAPED_SLASHES))?></span></div>
</div>

<div class="grid">
<section class="card">
<h2>Register / new module version</h2>
<form method="post" enctype="multipart/form-data">
<input type="hidden" name="action" value="register_module">
<label>Wasm file</label><input type="file" name="module_file" accept=".wasm,application/wasm" required>
<label>Kind</label><select name="kind"><option>POLYMORPHISM_WASM</option><option>MATHVM_WASM</option><option>STRATEGY_WASM</option><option>NEURAL_WASM</option></select>
<label>Visibility</label><select name="visibility"><option>PRIVATE_LOCAL</option><option>SHARED_SYNC</option></select>
<label>Module ID</label><input name="module_id" required placeholder="my-module">
<label>Version</label><input name="module_version" type="number" min="1" value="1">
<label>Entrypoint</label><input name="entrypoint" value="v0id_main">
<label>MathVM primitive requirements (JSON array)</label><textarea name="required_primitives" placeholder='[{"tag":65537,"id":"add-mod-u64","version":1}]'></textarea>
<button>Register content-addressed module</button>
</form>
</section>

<section class="card">
<h2>Hook module into client</h2>
<form method="post">
<input type="hidden" name="action" value="bind_module">
<label>Slot</label><select name="slot"><option value="series_generator">series_generator</option><option value="mathvm">mathvm</option><option value="strategy">strategy</option><option value="neural">neural</option></select>
<label>Module</label><select name="module_key"><?php foreach ($modules as $m): ?><option value="<?=h($m['key'] ?? '')?>"><?=h($m['key'] ?? '')?></option><?php endforeach; ?></select>
<button>Bind</button>
</form>
<form method="post">
<input type="hidden" name="action" value="unbind_module">
<label>Slot to unbind</label><select name="slot"><option>series_generator</option><option>mathvm</option><option>strategy</option><option>neural</option></select>
<button>Unbind</button>
</form>
</section>

<section class="card">
<h2>Edit module runtime config</h2>
<form method="post">
<input type="hidden" name="action" value="update_module">
<label>Module</label><select name="module_key"><?php foreach ($modules as $m): ?><option value="<?=h($m['key'] ?? '')?>"><?=h($m['key'] ?? '')?></option><?php endforeach; ?></select>
<label>Entrypoint</label><input name="entrypoint" value="v0id_main">
<label>Primitive requirements (JSON array)</label><textarea name="required_primitives"></textarea>
<button>Update config</button>
</form>
</section>

<section class="card">
<h2>Run MathVM module</h2>
<form method="post">
<input type="hidden" name="action" value="run_mathvm">
<label>Module (blank selection uses mathvm binding)</label><select name="module_key"><option value="">bound mathvm slot</option><?php foreach ($modules as $m): if (($m['kind'] ?? '') === 'MATHVM_WASM'): ?><option value="<?=h($m['key'] ?? '')?>"><?=h($m['key'] ?? '')?></option><?php endif; endforeach; ?></select>
<button>Execute bounded MathVM computation</button>
</form>
</section>
</div>

<script>
async function refreshState(){
  try{
    const r=await fetch('?api=state',{cache:'no-store'}); if(!r.ok)return;
    const s=await r.json();
    document.getElementById('revision').textContent=s.revision ?? 0;
    document.getElementById('last-error').textContent=s.last_error ?? '';
    const c=s.computation ?? {};
    document.getElementById('job-line').textContent=(c.type ?? 'idle')+' / '+(c.stage ?? 'idle');
    const pct=Number(c.percent ?? 0);
    document.getElementById('progress-bar').style.width=Math.max(0,Math.min(100,pct))+'%';
    document.getElementById('progress-text').textContent=pct.toFixed(1)+'% — '+(c.message ?? '');
    document.getElementById('result-json').textContent=JSON.stringify(c.result ?? {},null,2);
  }catch(e){}
}
setInterval(refreshState,1000);
</script>
</main></body></html>
