<?php
declare(strict_types=1);

// Local operator page for the remote TFHE evaluator. The browser talks only to
// this local PHP process; C++ performs key loading, TFHE preparation, CURVE/ZAP
// transport, remote encrypted execution and local decryption.
$root = rtrim(getenv('V0ID_CONTROL_ROOT') ?: '/tmp/v0id-control', DIRECTORY_SEPARATOR);
$commandsDir = $root . DIRECTORY_SEPARATOR . 'cloud_commands';
$responsesDir = $root . DIRECTORY_SEPARATOR . 'cloud_responses';
$statePath = $root . DIRECTORY_SEPARATOR . 'cloud_state.json';

foreach ([$root, $commandsDir, $responsesDir] as $dir) {
    if (!is_dir($dir) && !mkdir($dir, 0770, true) && !is_dir($dir)) {
        http_response_code(500);
        exit('Unable to create V0ID cloud-control directory: ' . htmlspecialchars($dir));
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
    $encoded = json_encode(
        $value,
        JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR
    ) . "\n";
    if (file_put_contents($tmp, $encoded, LOCK_EX) === false) {
        throw new RuntimeException('Unable to write TFHE cloud command temp file');
    }
    if (!rename($tmp, $path)) {
        @unlink($tmp);
        throw new RuntimeException('Unable to publish TFHE cloud command atomically');
    }
}

function queue_cloud_command(string $commandsDir, string $command, array $payload): string {
    $id = bin2hex(random_bytes(16));
    atomic_json_write($commandsDir . DIRECTORY_SEPARATOR . $id . '.json', [
        'protocol' => 'v0id-tfhe-cloud-control-v1',
        'command_id' => $id,
        'command' => $command,
        'payload' => $payload,
        'submitted_unix_ms' => (int)floor(microtime(true) * 1000),
    ]);
    return $id;
}

if (isset($_GET['api']) && $_GET['api'] === 'state') {
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    $state = read_json_file($statePath) ?? [
        'protocol' => 'v0id-tfhe-cloud-control-v1',
        'revision' => 0,
        'configured' => false,
        'status' => 'GPU local-control worker has not published cloud_state.json yet',
    ];
    echo json_encode($state, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    exit;
}

$message = '';
$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        $action = (string)($_POST['action'] ?? '');
        if ($action === 'configure_cloud') {
            $id = queue_cloud_command($commandsDir, 'configure_cloud', [
                'endpoint' => trim((string)($_POST['endpoint'] ?? '')),
                'client_peer_id' => trim((string)($_POST['client_peer_id'] ?? '')),
                'client_public_key_file' => trim((string)($_POST['client_public_key_file'] ?? '')),
                'client_secret_key_file' => trim((string)($_POST['client_secret_key_file'] ?? '')),
                'server_public_key_file' => trim((string)($_POST['server_public_key_file'] ?? '')),
                'expected_server_peer_id' => trim((string)($_POST['expected_server_peer_id'] ?? '')),
                'timeout_ms' => max(1, (int)($_POST['timeout_ms'] ?? 3600000)),
                'retry_attempts' => min(8, max(1, (int)($_POST['retry_attempts'] ?? 2))),
                'instruction_chunk_size' => min(32, max(1, (int)($_POST['instruction_chunk_size'] ?? 32))),
                'verify_plaintext_result' => isset($_POST['verify_plaintext_result']),
            ]);
            $message = 'Queued cloud endpoint configuration ' . $id;
        } elseif ($action === 'run_tfhe') {
            $programRaw = trim((string)($_POST['program_json'] ?? ''));
            $inputsRaw = trim((string)($_POST['input_words_json'] ?? ''));
            $program = json_decode($programRaw, true, 128, JSON_THROW_ON_ERROR);
            $inputs = json_decode($inputsRaw, true, 128, JSON_THROW_ON_ERROR);
            if (!is_array($program) || !is_array($inputs)) {
                throw new RuntimeException('Program and input words must decode to JSON objects/arrays');
            }
            $id = queue_cloud_command($commandsDir, 'run_tfhe_boolean_program', [
                'job_id' => trim((string)($_POST['job_id'] ?? 'web-tfhe-job')),
                'epoch' => max(0, (int)($_POST['epoch'] ?? 1)),
                'program' => $program,
                'input_words' => $inputs,
            ]);
            $message = 'Queued encrypted remote computation ' . $id;
        } else {
            throw new RuntimeException('Unknown TFHE cloud dashboard action');
        }
    } catch (Throwable $e) {
        $error = $e->getMessage();
    }
}

$state = read_json_file($statePath) ?? [];
$config = is_array($state['config'] ?? null) ? $state['config'] : [];
$computation = is_array($state['computation'] ?? null) ? $state['computation'] : [];

$defaultProgram = json_encode([
    'register_count' => 1,
    'input_word_count' => 1,
    'instructions' => [[
        'op' => 'XOR_INPUT',
        'dst' => 0,
        'a' => 0,
        'input_index' => 0,
    ]],
    'output_registers' => [0],
], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

$defaultInputs = json_encode(['0x0123456789abcdef'], JSON_PRETTY_PRINT);
?><!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>V0ID Encrypted Cloud</title>
<style>
body{font-family:system-ui,sans-serif;margin:0;background:#111;color:#eee}main{max-width:1200px;margin:auto;padding:24px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(360px,1fr));gap:16px}.card{background:#1b1b1b;border:1px solid #333;border-radius:10px;padding:16px;margin-bottom:16px}h1,h2{margin-top:0}a{color:#bbb}label{display:block;margin:8px 0 4px;color:#bbb}input,textarea,button{box-sizing:border-box;width:100%;padding:8px;background:#0d0d0d;color:#eee;border:1px solid #444;border-radius:6px}textarea{min-height:170px;font-family:monospace}button{margin-top:10px;cursor:pointer;background:#242424}.ok{padding:10px;background:#17351f}.err{padding:10px;background:#4a1818}.mono{font-family:monospace;overflow-wrap:anywhere}.small{font-size:.9em;color:#aaa}.progress{height:20px;background:#333;border-radius:10px;overflow:hidden}.bar{height:100%;background:#888;width:0}pre{white-space:pre-wrap;word-break:break-word;background:#0d0d0d;padding:10px;border-radius:6px}</style>
</head>
<body><main>
<h1>V0ID Encrypted Cloud</h1>
<p class="small"><a href="/">← local modules / Series-First</a> · This page stays local. C++ encrypts the program/input and submits ciphertext to the configured remote evaluator.</p>
<?php if ($message !== ''): ?><div class="ok"><?=h($message)?></div><?php endif; ?>
<?php if ($error !== ''): ?><div class="err"><?=h($error)?></div><?php endif; ?>

<div class="card">
<h2>Remote computation state</h2>
<div>Configured: <b id="configured"><?=h(($state['configured'] ?? false) ? 'YES' : 'NO')?></b></div>
<div>Revision: <span id="revision" class="mono"><?=h($state['revision'] ?? 0)?></span></div>
<div>Job: <span id="job" class="mono"><?=h($computation['job_id'] ?? '')?></span></div>
<div>Stage: <span id="stage" class="mono"><?=h($computation['stage'] ?? 'idle')?></span></div>
<div class="progress"><div id="progress-bar" class="bar" style="width:<?=h((float)($computation['percent'] ?? 0))?>%"></div></div>
<div id="progress-text" class="small"><?=h((string)($computation['percent'] ?? 0))?>% — <?=h($computation['message'] ?? '')?></div>
<div>Last error: <span id="last-error" class="mono"><?=h($state['last_error'] ?? '')?></span></div>
<pre id="result-json"><?=h(json_encode($computation['result'] ?? new stdClass(), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES))?></pre>
</div>

<div class="grid">
<section class="card">
<h2>Remote evaluator</h2>
<form method="post">
<input type="hidden" name="action" value="configure_cloud">
<label>Endpoint</label><input name="endpoint" value="<?=h($config['endpoint'] ?? 'tcp://127.0.0.1:7788')?>" placeholder="tcp://host:7788">
<label>Local client peer ID</label><input name="client_peer_id" value="<?=h($config['client_peer_id'] ?? 'client-a')?>">
<label>Client public key file</label><input name="client_public_key_file" value="<?=h($config['client_public_key_file'] ?? 'client-a.public')?>">
<label>Client secret key file</label><input name="client_secret_key_file" value="<?=h($config['client_secret_key_file'] ?? 'client-a.secret')?>">
<label>Remote server public key file</label><input name="server_public_key_file" value="<?=h($config['server_public_key_file'] ?? 'server.public')?>">
<label>Expected server peer ID</label><input name="expected_server_peer_id" value="<?=h($config['expected_server_peer_id'] ?? 'gpu-node')?>">
<label>Timeout (ms)</label><input type="number" min="1" name="timeout_ms" value="<?=h($config['timeout_ms'] ?? 3600000)?>">
<label>Exact-request attempts</label><input type="number" min="1" max="8" name="retry_attempts" value="<?=h($config['retry_attempts'] ?? 2)?>">
<label>Encrypted instructions per remote chunk</label><input type="number" min="1" max="32" name="instruction_chunk_size" value="<?=h($config['instruction_chunk_size'] ?? 32)?>">
<label><input style="width:auto" type="checkbox" name="verify_plaintext_result" <?=($config['verify_plaintext_result'] ?? true) ? 'checked' : ''?>> Compare decrypted output with cheap local plaintext oracle</label>
<button>Save remote endpoint</button>
</form>
</section>

<section class="card">
<h2>Run encrypted Boolean program</h2>
<form method="post">
<input type="hidden" name="action" value="run_tfhe">
<label>Job ID</label><input name="job_id" value="web-tfhe-job">
<label>Epoch</label><input type="number" min="0" name="epoch" value="1">
<label>Input words (JSON; strings preserve full uint64 values)</label>
<textarea name="input_words_json"><?=h($defaultInputs)?></textarea>
<label>BooleanProgramImage (JSON)</label>
<textarea name="program_json"><?=h($defaultProgram)?></textarea>
<button>Encrypt locally and execute remotely</button>
</form>
<p class="small">Current op names: XOR2, XOR5, XOR_ROT1, ROT_COPY, CHI, XOR_INPUT, XOR_CONST. The default one-instruction program simply returns its encrypted input word.</p>
</section>
</div>

<div class="card">
<h2>Trust split</h2>
<pre>LOCAL CLIENT                         REMOTE EVALUATOR
ClientKey             YES            NO
plaintext program     YES            NO
plaintext input       YES            NO
server/eval key       generated      YES
encrypted init        generated  ---> YES
encrypted chunks      generated  ---> YES
encrypted result                 <--- YES
plaintext result      after decrypt   NO</pre>
</div>

<script>
async function refreshState(){
  try{
    const r=await fetch('/cloud.php?api=state',{cache:'no-store'});
    const s=await r.json();
    const c=s.computation||{};
    document.getElementById('configured').textContent=s.configured?'YES':'NO';
    document.getElementById('revision').textContent=s.revision||0;
    document.getElementById('job').textContent=c.job_id||'';
    document.getElementById('stage').textContent=c.stage||'idle';
    const p=Number(c.percent||0);
    document.getElementById('progress-bar').style.width=Math.max(0,Math.min(100,p))+'%';
    document.getElementById('progress-text').textContent=p.toFixed(1)+'% — '+(c.message||'');
    document.getElementById('last-error').textContent=s.last_error||'';
    document.getElementById('result-json').textContent=JSON.stringify(c.result||{},null,2);
  }catch(e){}
}
setInterval(refreshState,1000);
refreshState();
</script>
</main></body></html>
