<?php
declare(strict_types=1);

/**
 * DirectAdmin User-Level Read-Only JSON IPC Relay (invoked via user/stats.raw with `php -n`).
 * Connects strictly to /var/run/da-resourced-user.sock where Linux Kernel SO_PEERCRED
 * enforces per-UID tenant isolation.
 */

function emit_user_json(array $body): void
{
    echo "HTTP/1.1 200 OK\r\n";
    echo "Content-Type: application/json; charset=utf-8\r\n";
    echo "Cache-Control: no-store, no-cache, must-revalidate\r\n";
    echo "X-Content-Type-Options: nosniff\r\n\r\n";
    echo json_encode($body, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . "\n";
    exit(0);
}

$daUsername = trim((string) (getenv('USERNAME') ?: ''));
$qs = (string) (getenv('QUERY_STRING') ?: '');
parse_str($qs, $query);

$action = isset($query['action']) && $query['action'] === 'get_logs' ? 'get_logs' : 'get_user_stats';

$req = [
    'action' => $action,
    'username' => $daUsername,
    'limit' => 10,
];

$sockPath = getenv('DA_LIMITER_USER_SOCK') ?: '/var/run/da-resourced-user.sock';
$errno = 0;
$errstr = '';
$fp = @stream_socket_client('unix://' . $sockPath, $errno, $errstr, 5.0);
if ($fp === false) {
    emit_user_json([
        'ok' => false,
        'error' => "Resource monitoring service is temporarily unavailable ({$errstr}).",
    ]);
}

stream_set_timeout($fp, 10);
fwrite($fp, json_encode($req, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . "\n");
$rawReply = fgets($fp);
fclose($fp);

if (!is_string($rawReply) || trim($rawReply) === '') {
    emit_user_json(['ok' => false, 'error' => 'Empty response from monitoring daemon']);
}

$decoded = json_decode($rawReply, true);
if (!is_array($decoded)) {
    emit_user_json(['ok' => false, 'error' => 'Invalid response from monitoring daemon']);
}

emit_user_json($decoded);
