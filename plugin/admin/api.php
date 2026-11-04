<?php
declare(strict_types=1);

/**
 * DirectAdmin Admin-Level JSON IPC Relay (invoked via admin/api.raw with `php -n`).
 * Communicates over /var/run/da-resourced.sock where Linux Kernel SO_PEERCRED verifies
 * that the caller UID is root, diradmin, or a DirectAdmin Administrator (admin.list).
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

function read_da_request(bool &$detectedPost): array
{
    $detectedPost = false;
    $params = [];

    $qs = getenv('QUERY_STRING');
    if (is_string($qs) && $qs !== '') {
        parse_str(html_entity_decode($qs, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'), $getParams);
        if (is_array($getParams)) {
            $params = array_merge($params, $getParams);
        }
    }

    $postEnv = getenv('POST');
    if (is_string($postEnv) && $postEnv !== '') {
        $detectedPost = true;
        $cleanPost = html_entity_decode($postEnv, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        $trimPost = trim($cleanPost);
        if ($trimPost !== '' && ($trimPost[0] === '{' || $trimPost[0] === '[')) {
            $decoded = json_decode($trimPost, true);
            if (is_array($decoded)) {
                return normalize_ipc_payload(array_merge($params, $decoded));
            }
        }
        parse_str($cleanPost, $postParams);
        if (is_array($postParams)) {
            $params = array_merge($params, $postParams);
        }
    } elseif (defined('STDIN') && is_resource(STDIN)) {
        $reqMeth = strtoupper((string) (getenv('REQUEST_METHOD') ?: ''));
        $cLen = (int) (getenv('CONTENT_LENGTH') ?: 0);
        $waitUsec = ($reqMeth === 'POST' || $cLen > 0) ? 200000 : 0;
        $readStreams = [STDIN];
        $writeStreams = null;
        $exceptStreams = null;
        if (@stream_select($readStreams, $writeStreams, $exceptStreams, 0, $waitUsec) > 0) {
            @stream_set_blocking(STDIN, false);
            $maxBytes = ($cLen > 0 && $cLen <= 65536) ? $cLen : 65536;
            $rawStdin = @stream_get_contents(STDIN, $maxBytes);
            if (is_string($rawStdin) && trim($rawStdin) !== '') {
                $detectedPost = true;
                $trimRaw = trim($rawStdin);
                if ($trimRaw[0] === '{' || $trimRaw[0] === '[') {
                    $decoded = json_decode($trimRaw, true);
                    if (is_array($decoded)) {
                        return normalize_ipc_payload(array_merge($params, $decoded));
                    }
                }
                parse_str($rawStdin, $stdinParams);
                if (is_array($stdinParams)) {
                    $params = array_merge($params, $stdinParams);
                }
            }
        }
    }

    if (isset($params['payload_b64']) && is_string($params['payload_b64'])) {
        $b64 = strtr(trim($params['payload_b64']), '-_ ', '+/+');
        $rem = strlen($b64) % 4;
        if ($rem > 0) {
            $b64 .= str_repeat('=', 4 - $rem);
        }
        $rawJson = base64_decode($b64, true);
        if (is_string($rawJson) && $rawJson !== '') {
            $decoded = json_decode($rawJson, true);
            if (is_array($decoded)) {
                unset($params['payload_b64']);
                $params = array_merge($params, $decoded);
            }
        }
    }

    if (isset($params['payload']) && is_string($params['payload'])) {
        $cleanPayload = html_entity_decode($params['payload'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        $decoded = json_decode($cleanPayload, true);
        if (is_array($decoded)) {
            unset($params['payload']);
            $params = array_merge($params, $decoded);
        }
    }

    return normalize_ipc_payload($params);
}

function normalize_ipc_payload(array $params): array
{
    foreach (['limit', 'backup_retention'] as $intKey) {
        if (isset($params[$intKey]) && !is_int($params[$intKey])) {
            $strVal = trim((string) $params[$intKey]);
            if ($strVal === '') {
                unset($params[$intKey]);
            } else {
                $params[$intKey] = (int) $strVal;
            }
        }
    }

    foreach (['sync_users', 'keep_stored_token'] as $boolKey) {
        if (isset($params[$boolKey]) && !is_bool($params[$boolKey])) {
            $params[$boolKey] = filter_var($params[$boolKey], FILTER_VALIDATE_BOOLEAN);
        }
    }

    if (isset($params['limits']) && is_array($params['limits'])) {
        foreach (['enabled', 'custom_override', 'mysql_penalty_enabled'] as $bKey) {
            if (isset($params['limits'][$bKey]) && !is_bool($params['limits'][$bKey])) {
                $params['limits'][$bKey] = filter_var($params['limits'][$bKey], FILTER_VALIDATE_BOOLEAN);
            }
        }
        $limitIntKeys = [
            'cpu_quota',
            'cpu_weight',
            'mem_high_mb',
            'mem_max_mb',
            'io_weight',
            'tasks_max',
            'php_max_children',
            'php_mem_limit_mb',
            'mysql_max_connections',
            'mysql_max_statement_time_sec',
            'mysql_max_mem_mb',
            'mysql_max_active_queries',
            'mysql_penalty_threshold',
            'mysql_penalty_window_sec',
            'mysql_penalty_duration_sec',
            'mysql_penalty_conn',
            'mysql_penalty_time_sec',
        ];
        foreach ($limitIntKeys as $iKey) {
            if (isset($params['limits'][$iKey]) && !is_int($params['limits'][$iKey])) {
                $params['limits'][$iKey] = (int) $params['limits'][$iKey];
            }
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

$detectedPost = false;
$input = read_da_request($detectedPost);
unset($input['pipe_post']);

$envMethod = strtoupper((string) (getenv('REQUEST_METHOD') ?: ''));
$isPost = ($envMethod === 'POST') || $detectedPost;

$action = '';
if (isset($input['action']) && is_string($input['action'])) {
    $action = trim($input['action']);
} elseif (!$isPost && empty($input)) {
    $action = 'ping';
}

if ($action === '') {
    emit_json(['ok' => false, 'error' => 'Empty request payload received by DirectAdmin CGI relay'], 400);
}
$input['action'] = $action;

if (!isset($readOnlyActions[$action]) && !isset($mutatingActions[$action])) {
    emit_json(['ok' => false, 'error' => "Unsupported admin action: {$action}"], 400);
}

if (isset($mutatingActions[$action]) && !$isPost) {
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
