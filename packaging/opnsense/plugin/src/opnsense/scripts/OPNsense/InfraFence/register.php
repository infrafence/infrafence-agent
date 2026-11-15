#!/usr/local/bin/php
<?php

/*
 * Registers the agent once. The install token comes from the root-only
 * spool file the GUI controller wrote (never configd parameters, never
 * argv) and reaches the agent on stdin; the spool file is removed first.
 * It always exits 0: configd hides the output of a failing script, and the
 * GUI shows the JSON "message".
 */

require_once 'script/load_phalcon.php';

use OPNsense\InfraFence\General;

$spool = '/var/db/infrafence/register.token';
$token = @file_get_contents($spool, false, null, 0, 1024);
@unlink($spool);
$token = is_string($token) ? trim($token) : '';
if (!preg_match('#^[A-Za-z0-9_.:+/=\-]{8,512}$#', $token)) {
    echo json_encode(['status' => 'error', 'message' => 'no install token']) . PHP_EOL;
    exit(0);
}

$mdl = new General();
$mode = (string)$mdl->mode;
if (!in_array($mode, ['protect', 'monitor'], true)) {
    $mode = 'monitor';
}
$url = (string)$mdl->server_url;
/* https only: the install token and then the agent token go to it. Plain
 * http only for the lab, with a flag file root creates. */
$scheme = file_exists('/var/db/infrafence/allow-http') ? 'https?' : 'https';
if (!preg_match('#^' . $scheme . '://[A-Za-z0-9.\-]+(:[0-9]+)?(/[A-Za-z0-9._~/\-]*)?$#', $url)) {
    echo json_encode(['status' => 'error', 'message' => 'invalid dashboard URL (https:// required)']) . PHP_EOL;
    exit(0);
}
$name = gethostname();
if (!is_string($name) || $name === '') {
    $name = 'opnsense';
}

$cmd = sprintf(
    '/usr/local/sbin/infrafence-agent register --token-stdin --mode %s %s %s',
    escapeshellarg($mode),
    escapeshellarg($url),
    escapeshellarg($name)
);
$env = ['PATH' => '/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin',
    'INFRAFENCE_CONFIG' => '/usr/local/etc/infrafence/config.json'];
$p = proc_open($cmd, [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, null, $env);
if (!is_resource($p)) {
    echo json_encode(['status' => 'error', 'message' => 'could not start the agent']) . PHP_EOL;
    exit(0);
}
fwrite($pipes[0], $token . "\n");
fclose($pipes[0]);
$out = stream_get_contents($pipes[1]) . stream_get_contents($pipes[2]);
fclose($pipes[1]);
fclose($pipes[2]);
$rc = proc_close($p);
$lines = array_values(array_filter(array_map('trim', explode("\n", $out))));
$last = count($lines) ? $lines[count($lines) - 1] : '';
/* log lines start with "2026/11/15 10:00:00 file.go:12: " */
$last = preg_replace('#^\S+ \S+ \S+\.go:\d+: #', '', $last);
if ($rc !== 0) {
    echo json_encode(['status' => 'error', 'message' => $last !== '' ? $last : 'registration failed']) . PHP_EOL;
    exit(0);
}
echo json_encode(['status' => 'ok']) . PHP_EOL;
