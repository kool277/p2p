#!/usr/bin/env php
<?php
// A command-line client over the qalqond sidecar. It speaks the CLI contract in
// docs/CLIENT-ADAPTER.md, so interop runs can drive it like any other client.
//
//   qalqon.php enroll --server <url> --ca <hex file> --data <dir> --token <token>
//   qalqon.php call   --server <url> --ca <hex file> --data <dir> --user <id> --peer <id> [--records N] [--relay-only]
//   qalqon.php answer --server <url> --ca <hex file> --data <dir> --user <id> [--relay-only] [--wait-ms N]
//
// The daemon's socket comes from QALQOND_SOCKET, and the password from QALQON_PASSWORD.
// There is no cryptography here: the keys and all protocol logic stay inside qalqond.

declare(strict_types=1);

require __DIR__ . '/../../bindings/sidecar-clients/php/QalqonClient.php';

use Qalqon\QalqonClient;
use Qalqon\QalqonError;

function flag(array $argv, string $name): ?string
{
    $i = array_search($name, $argv, true);
    return $i !== false && isset($argv[$i + 1]) ? $argv[$i + 1] : null;
}

function required(array $argv, string $name): string
{
    return flag($argv, $name) ?? throw new RuntimeException("{$name} is required");
}

function say(array $value): void
{
    echo json_encode($value, JSON_THROW_ON_ERROR), "\n";
    flush();
}

function client(): QalqonClient
{
    $socket = getenv('QALQOND_SOCKET');
    if ($socket === false) {
        throw new RuntimeException('QALQOND_SOCKET is not set');
    }
    return new QalqonClient($socket);
}

function config(array $argv): array
{
    $config = [
        'serverUrl' => required($argv, '--server'),
        'caBundle' => base64_encode(hex2bin(trim(file_get_contents(required($argv, '--ca'))))),
        'keyStore' => ['kind' => 'osDefault'],
        'dataDir' => required($argv, '--data'),
    ];
    if (in_array('--relay-only', $argv, true)) {
        $config['relayPolicy'] = 'relayOnly';
    }
    return $config;
}

function credentials(array $argv): array
{
    $password = getenv('QALQON_PASSWORD');
    if ($password === false) {
        throw new RuntimeException('QALQON_PASSWORD is not set');
    }
    return ['userId' => required($argv, '--user'), 'secret' => base64_encode($password)];
}

function record(int $n): string
{
    return sprintf('record %06d %s', $n, str_repeat('x', 64));
}

function run_call(array $argv): void
{
    $q = client();
    $session = $q->connect(config($argv), credentials($argv));
    say(['state' => 'connected']);
    $records = (int) (flag($argv, '--records') ?? 1000);
    $peer = ['userId' => required($argv, '--peer')];
    $channel = $q->session_openChannel($session, $peer, ['label' => 'interop', 'ordered' => true, 'reliable' => true]);

    $sent = 0;
    $received = 0;
    $rekeyed = false;
    $deadline = time() + 120;
    while ($received < $records) {
        if (time() > $deadline) {
            throw new RuntimeException("only {$received} of {$records} came back");
        }
        while ($sent < $records && $sent - $received < 64) {
            $q->channel_send($channel, record($sent));
            $sent++;
        }
        $message = $q->channel_receive($channel, 50);
        if ($message !== null) {
            if ($message !== record($received)) {
                throw new RuntimeException("reply {$received} is wrong");
            }
            $received++;
        }
        if (!$rekeyed && $received >= $records / 2) {
            $q->session_rotateKeys($session, $peer);
            $rekeyed = true;
        }
    }
    $info = $q->channel_info($channel);
    $export = $q->session_exportAudit($session, (object) []);
    $entries = substr_count(base64_decode($export['events'], true), "\n");
    $q->session_close($session);
    say([
        'result' => 'ok',
        'records' => $received,
        'path' => $info['path'],
        'key_epoch' => $info['keyEpoch'],
        'peer_status' => $info['peer']['status'],
        'safety_number' => $info['peer']['safetyNumber'],
        'audit_entries' => $entries,
    ]);
}

function run_answer(array $argv): void
{
    $q = client();
    $session = $q->connect(config($argv), credentials($argv));
    say(['state' => 'connected']);
    $deadline = time() + (int) ((int) (flag($argv, '--wait-ms') ?? 60000) / 1000);
    $request = null;
    while ($request === null) {
        if (time() > $deadline) {
            throw new RuntimeException('no call arrived in time');
        }
        $event = $q->session_nextEvent($session, 200);
        if (is_array($event) && $event['type'] === 'channelRequested') {
            $request = $event['requestId'];
        }
    }
    $channel = $q->session_acceptChannel($session, $request);
    $info = $q->channel_info($channel);
    $echoed = 0;
    try {
        while (true) {
            $message = $q->channel_receive($channel, 200);
            if ($message !== null) {
                $q->channel_send($channel, $message);
                $echoed++;
            }
        }
    } catch (QalqonError $e) {
        // The peer closed.
    }
    say([
        'result' => 'ok',
        'records' => $echoed,
        'path' => $info['path'],
        'peer_status' => $info['peer']['status'],
        'safety_number' => $info['peer']['safetyNumber'],
    ]);
    try {
        $q->session_close($session);
    } catch (QalqonError $e) {
        // Already closed.
    }
}

try {
    switch ($argv[1] ?? '') {
        case 'enroll':
            $request = ['enrollmentToken' => required($argv, '--token'), 'deviceName' => flag($argv, '--name') ?? 'php-cli'];
            say(['enrolled' => client()->enrollDevice(config($argv), $request)]);
            break;
        case 'call':
            run_call($argv);
            break;
        case 'answer':
            run_answer($argv);
            break;
        default:
            throw new RuntimeException('usage: qalqon.php <enroll|call|answer> ...');
    }
} catch (Throwable $e) {
    say(['result' => 'error', 'error' => $e->getMessage()]);
    exit(1);
}
