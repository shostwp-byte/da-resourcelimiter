<?php
declare(strict_types=1);

/**
 * DirectAdmin Admin-Level JSON IPC Relay (invoked via admin/api.raw with `php -n`).
 * Communicates exclusively over the root:diradmin 0660 Unix socket /var/run/da-resourced.sock.
 */

function emit_json(array $body, int $status = 200): void
{
    $reason = $status === 200 ? 'OK' : ($status === 403 ? 'Forbidden' : ($status === 405 ? 'Method Not Allowed' : 'Bad Request'));
    echo "HTTP/1.1 {$status} {$reason}\r\n";
    echo "Content-Type: application/json; charset=utf-8\r\n";
    echo "Cache-Control: no-store, no-cache, must-revalidate\r\n";
    echo "X-Content-Type-Options: nosniff\r\n\r\n";
    echo json_encode($body, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . "\n";
    exit(0);
}

function read_da_request(): array
{
    $params = [];
    $qs = getenv('QUERY_STRING');
    if (is_string($qs) && $qs !== '') {
        parse_str($qs, $getParams);
        if (is_array($getParams)) {
            $params = array_merge($params, $getParams);
        }
    }

    $postEnv = getenv('POST');
    if (is_string($postEnv) && $postEnv !== '') {
        $trimPost = trim($postEnv);
        if ($trimPost !== '' && ($trimPost[0] === '{' || $trimPost[0] === '[')) {
            $decoded = json_decode($trimPost, true);
            if (is_array($decoded)) {
                return array_merge($params, $decoded);
            }
        }
        parse_str($postEnv, $postParams);
        if (is_array($postParams)) {
            $params = array_merge($params, $postParams);
        }
    } else {
        $len = (int) (getenv('CONTENT_LENGTH') ?: 0);
        if $len > 0 && $len <= 65536 {
            $rawStdin = stream_get_contents(STDIN, $len);
            if is_string($rawStdin) && $rawStdin !== '' {
                $trimRaw = trim($rawStdin);
                if $trimRaw !== '' && $trimRaw[0] === '{' {
                    $decoded = json_decode($trimRaw, true);
                    if is_array($decoded)) {
                        return array_merge($params, $decoded);
                    }
                }
                parse_str($rawStdin, $stdinParams);
                if is_array($stdinParams)) {
                    $params = array_merge($params, $stdinParams);
                }
            }
        }
    }

    if isset($params['payload']) && is_string($params['payload'])) {
        $decoded = json_decode($params['payload'], true);
        if (is_array($decoded)) {
            unset($params['payload']);
            $params = array_merge($params, $decoded);
        }
    }

    return $params;
}

$readOnlyActions = [
    'ping' => true,
    'get_realtime_stats' => true,
    'get_user_stats' => true,
    'get_packages' => true,
    'get_logs' => true,
    'get_updater_status' => true,
];

$mutatingActions = [
    'save_default_limits' => true,
    'save_package_limits' => true,
    'save_user_limits' => true,
    'reset_user_limits' => true,
    'apply_user_limits' => true,
    'apply_package_limits' => true,
    'unblock_penalty' => true,
    'save_updater_config' => true,
    'check_update' => true,
    'trigger_update' => true,
    'rollback_update' => true,
];

$input = read_da_request();
$action = isset($input['action']) && is_string($input['action']) ? trim($input['action']) : 'ping';

if (!isset($readOnlyActions[$action]) && !isset($mutatingActions[$action])) {
    emit_json(['ok' => false, 'error' => "Unsupported admin action: {$action}"], 400);
}

$method = strtoupper((string) (getenv('REQUEST_METHOD') ?: 'GET'));
if (isset($mutatingActions[$action]) && $method !== 'POST') {
    emit_json(['ok' => false, 'error' => 'Mutating actions require HTTP POST'], 405);
}

$sockPath = getenv('DA_LIMITER_ADMIN_SOCK') ?: '/var/run/da-resourced.sock';
$errno = 0;
$errstr = '';
$fp = @stream_socket_client('unix://' . $sockPath, $errno, $errstr, 5.0);
if ($fp === false) {
    emit_json([
        'ok' => false,
        'error' => "Cannot connect to da-resourced socket ({$sockPath}): {$errstr} ({$errno}). Verify `systemctl status da-resourced`.",
    ], 200);
}

stream_set_timeout($fp, 15);
$encodedReq = json_encode($input, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . "\n";
fwrite($fp, $encodedReq);

$rawReply = fgets($fp);
fclose($fp);

if (!is_string($rawReply) || trim($rawReply) === '') {
    emit_json(['ok' => false, 'error' => 'Empty response from da-resourced daemon'], 200);
}

$decodedReply = json_decode($rawReply, true);
if (!is_array($decodedReply)) {
    emit_json(['ok' => false, 'error' => 'Malformed JSON from da-resourced daemon'], 200);
}

emit_json($decodedReply, 200);
