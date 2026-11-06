<?php
// Runs the shared vectors through the PHP client, against a qalqond it starts itself.

declare(strict_types=1);

require __DIR__ . '/QalqonClient.php';

use Qalqon\QalqonClient;

$directory = sys_get_temp_dir() . '/qalqon-conformance-' . getmypid();
mkdir($directory, 0700);
$socket = "{$directory}/qalqond.sock";
$daemon = proc_open(['target/debug/qalqond', 'serve', '--socket', $socket], [2 => ['file', '/dev/null', 'w']], $pipes);
for ($i = 0; $i < 500 && !file_exists($socket); $i++) {
    usleep(10000);
}
$failed = 0;
try {
    $client = new QalqonClient($socket);
    foreach (array_slice($argv, 1) as $file) {
        $report = json_decode($client->conformanceRun(file_get_contents($file)), true, 512, JSON_THROW_ON_ERROR);
        printf("%s: %d passed, %d failed\n", basename($file), $report['passed'], count($report['failed']));
        if ($report['failed'] !== [] || $report['passed'] === 0) {
            $failed++;
        }
    }
} finally {
    proc_terminate($daemon);
    proc_close($daemon);
    @unlink($socket);
    @rmdir($directory);
}
exit($failed === 0 ? 0 : 1);
