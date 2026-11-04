<?php
declare(strict_types=1);

/**
 * DirectAdmin Admin-Level JSON IPC Relay (invoked via admin/api.raw with `php -n`).
 * Communicates over /var/run/da-resourced.sock where Linux Kernel SO_PEERCRED verifies
 * that the caller UID is root, diradmin, or a DirectAdmin Administrator (admin.list).
 *
 * Security layers:
 *   1. Strict separation between GET query parameters and POST body payloads (S3).
 *   2. Same-Origin verification via Sec-Fetch-Site + Origin/Referer against HTTP_HOST (S3).
 *   3. Per-UID HMAC-SHA256 CSRF token required on every mutating POST action (S3).
 *   4. Conditional HTML-entity decoding only when legacy DirectAdmin CGI encoding is detected (Q3).
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

/**
 * Parses URL-encoded query/form strings while avoiding corrupting literal HTML entities
 * inside parameter values unless DirectAdmin encoded delimiter '&' as '&amp;' (Q3).
 */
function parse_da_form_string(string $raw): array
{
    $normalized = $raw;
    if (strpos($raw, '&amp;') !== false && preg_match('/&(?!amp;)/', $raw) === 0) {
        $normalized = str_replace('&amp;', '&', $raw);
    }
    $out = [];
    parse_str($normalized, $out);
    return is_array($out) ? $out : [];
}

/**
 * Decodes JSON payloads directly first; falls back to HTML-entity decoding only if
 * legacy DirectAdmin CGI escaped quotes into '&quot;' or numeric entities (Q3).
 */
function decode_da_json(string $raw): ?array
{
    $trimmed = trim($raw);
    if ($trimmed === '') {
        return null;
    }
    if ($trimmed[0] === '{' || $trimmed[0] === '[') {
        $direct = json_decode($trimmed, true);
        if (is_array($direct)) {
            return $direct;
        }
    }
    if (strpos($trimmed, '&quot;') !== false || strpos($trimmed, '&#') !== false) {
        $unescaped = trim(html_entity_decode($trimmed, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'));
        if ($unescaped !== '' && ($unescaped[0] === '{' || $unescaped[0] === '[')) {
            $fallback = json_decode($unescaped, true);
            if (is_array($fallback)) {
                return $fallback;
            }
        }
    }
    return null;
}

function expand_payload_wrappers(array $params): array
{
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
        $decoded = decode_da_json($params['payload']);
        if (is_array($decoded)) {
            unset($params['payload']);
            $params = array_merge($params, $decoded);
        }
    }

    return $params;
}

function read_da_request(bool &$detectedPost, string &$extractedCsrfToken): array
{
    $detectedPost = false;
    $extractedCsrfToken = '';

    $reqMeth = strtoupper((string) (getenv('REQUEST_METHOD') ?: ''));
    $postParams = [];

    $postEnv = getenv('POST');
    if (is_string($postEnv) && $postEnv !== '') {
        $detectedPost = true;
        $decodedJson = decode_da_json($postEnv);
        if (is_array($decodedJson)) {
            $postParams = $decodedJson;
        } else {
            $postParams = parse_da_form_string($postEnv);
        }
    } elseif (defined('STDIN') && is_resource(STDIN)) {
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
                $decodedJson = decode_da_json($rawStdin);
                if (is_array($decodedJson)) {
                    $postParams = $decodedJson;
                } else {
                    $postParams = parse_da_form_string($rawStdin);
                }
            }
        }
    }

    if ($reqMeth === 'POST' || $detectedPost) {
        // Strictly isolate POST body from QUERY_STRING so query params cannot smuggle mutating actions (S3).
        if (isset($postParams['csrf_token']) && is_string($postParams['csrf_token'])) {
            $extractedCsrfToken = trim($postParams['csrf_token']);
            unset($postParams['csrf_token']);
        }
        $expanded = expand_payload_wrappers($postParams);
        if ($extractedCsrfToken === '' && isset($expanded['csrf_token']) && is_string($expanded['csrf_token'])) {
            $extractedCsrfToken = trim($expanded['csrf_token']);
        }
        unset($expanded['csrf_token']);
        if ($extractedCsrfToken === '') {
            $hdrToken = getenv('HTTP_X_DARL_CSRF');
            if (is_string($hdrToken) && trim($hdrToken) !== '') {
                $extractedCsrfToken = trim($hdrToken);
            }
        }
        return normalize_ipc_payload($expanded);
    }

    $getParams = [];
    $qs = getenv('QUERY_STRING');
    if (is_string($qs) && $qs !== '') {
        $getParams = parse_da_form_string($qs);
    }
    return normalize_ipc_payload($getParams);
}

function normalize_url_authority(string $url): string
{
    $parts = @parse_url(trim($url));
    if (!is_array($parts) || empty($parts['host'])) {
        return '';
    }
    $scheme = strtolower((string) ($parts['scheme'] ?? ''));
    $host = strtolower((string) $parts['host']);
    if (strpos($host, ':') !== false && $host[0] !== '[') {
        $host = '[' . $host . ']';
    }
    $port = isset($parts['port']) ? (int) $parts['port'] : 0;
    if ($port > 0 && !(($scheme === 'https' && $port === 443) || ($scheme === 'http' && $port === 80))) {
        return $host . ':' . $port;
    }
    return $host;
}

function normalize_host_header(string $hostHeader): array
{
    $clean = strtolower(trim($hostHeader));
    if ($clean === '') {
        return [];
    }
    $candidates = [$clean];
    if (substr($clean, -4) === ':443') {
        $candidates[] = substr($clean, 0, -4);
    } elseif (substr($clean, -3) === ':80') {
        $candidates[] = substr($clean, 0, -3);
    }
    return array_values(array_unique($candidates));
}

function verify_same_origin_post(): ?string
{
    $secFetch = strtolower(trim((string) (getenv('HTTP_SEC_FETCH_SITE') ?: '')));
    if ($secFetch !== '' && $secFetch !== 'same-origin' && $secFetch !== 'none') {
        return 'Forbidden: cross-site request blocked (Sec-Fetch-Site)';
    }

    $rawHost = (string) (getenv('HTTP_HOST') ?: '');
    if ($rawHost === '') {
        $srvName = trim((string) (getenv('SERVER_NAME') ?: ''));
        $srvPort = trim((string) (getenv('SERVER_PORT') ?: ''));
        if ($srvName !== '') {
            $rawHost = $srvPort !== '' ? ($srvName . ':' . $srvPort) : $srvName;
        }
    }
    $allowedHosts = normalize_host_header($rawHost);
    if (empty($allowedHosts)) {
        return null;
    }

    $origin = trim((string) (getenv('HTTP_ORIGIN') ?: ''));
    if ($origin !== '') {
        if (strtolower($origin) === 'null') {
            return 'Forbidden: null Origin header rejected';
        }
        $originAuth = normalize_url_authority($origin);
        if ($originAuth === '' || !in_array($originAuth, $allowedHosts, true)) {
            return 'Forbidden: Origin header does not match DirectAdmin host';
        }
        return null;
    }

    $referer = trim((string) (getenv('HTTP_REFERER') ?: ''));
    if ($referer !== '') {
        $refAuth = normalize_url_authority($referer);
        if ($refAuth === '' || !in_array($refAuth, $allowedHosts, true)) {
            return 'Forbidden: Referer header does not match DirectAdmin host';
        }
    }

    return null;
}

function current_effective_uid(): int
{
    if (function_exists('posix_geteuid')) {
        return (int) posix_geteuid();
    }
    $myUid = getmyuid();
    return $myUid !== false ? (int) $myUid : 0;
}

function resolve_csrf_key_candidates(int $uid): array
{
    $paths = [];
    $override = getenv('DA_LIMITER_CSRF_KEY_FILE');
    if (is_string($override) && trim($override) !== '') {
        $paths[] = trim($override);
    }
    if (function_exists('posix_getpwuid')) {
        $pw = @posix_getpwuid($uid);
        if (is_array($pw) && !empty($pw['dir']) && is_dir($pw['dir'])) {
            $paths[] = rtrim((string) $pw['dir'], '/') . '/.da_limiter_csrf.key';
        }
    }
    $home = trim((string) (getenv('HOME') ?: ''));
    if ($home !== '' && is_dir($home)) {
        $paths[] = rtrim($home, '/') . '/.da_limiter_csrf.key';
    }
    $paths[] = rtrim(sys_get_temp_dir(), '/\\') . DIRECTORY_SEPARATOR . '.da_limiter_csrf_' . $uid . '.key';
    return array_values(array_unique($paths));
}

function read_or_init_secret_file(string $path, int $uid): ?string
{
    clearstatcache(true, $path);
    if (file_exists($path) || is_link($path)) {
        if (is_link($path)) {
            return null;
        }
        $st = @lstat($path);
        if (!is_array($st)) {
            return null;
        }
        // On POSIX systems verify ownership and 0600 mode (skip strict UID/mode check on Windows unit test runner)
        if (DIRECTORY_SEPARATOR === '/') {
            if ((int) $st['uid'] !== $uid || (($st['mode'] & 0077) !== 0)) {
                return null;
            }
        }
        $raw = @file_get_contents($path);
        if (is_string($raw) && strlen(trim($raw)) >= 64) {
            return trim($raw);
        }
        return null;
    }

    $fp = @fopen($path, 'xb');
    if ($fp === false) {
        return null;
    }
    @chmod($path, 0600);
    $secret = bin2hex(random_bytes(32));
    fwrite($fp, $secret . "\n");
    fclose($fp);
    return $secret;
}

function load_csrf_secret(): string
{
    $uid = current_effective_uid();
    foreach (resolve_csrf_key_candidates($uid) as $candidate) {
        $sec = read_or_init_secret_file($candidate, $uid);
        if (is_string($sec) && $sec !== '') {
            return $sec;
        }
    }
    return '';
}

function compute_csrf_token(string $secret, int $window): string
{
    $uid = current_effective_uid();
    $daUser = trim((string) (getenv('USERNAME') ?: ''));
    return hash_hmac('sha256', $uid . '|' . $daUser . '|' . $window, $secret);
}

function issue_csrf_token(string $secret): string
{
    if ($secret === '') {
        return '';
    }
    $window = intdiv(time(), 43200);
    return compute_csrf_token($secret, $window);
}

function verify_csrf_token(string $secret, string $provided): bool
{
    if ($secret === '' || $provided === '' || strlen($provided) !== 64) {
        return false;
    }
    $window = intdiv(time(), 43200);
    foreach ([$window, $window - 1] as $w) {
        $expected = compute_csrf_token($secret, $w);
        if (hash_equals($expected, $provided)) {
            return true;
        }
    }
    return false;
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

$csrfSecret = load_csrf_secret();
$detectedPost = false;
$providedCsrfToken = '';
$input = read_da_request($detectedPost, $providedCsrfToken);
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

if (isset($mutatingActions[$action])) {
    if (!$isPost) {
        emit_json(['ok' => false, 'error' => 'Mutating actions require HTTP POST'], 405);
    }
    $originErr = verify_same_origin_post();
    if ($originErr !== null) {
        emit_json(['ok' => false, 'error' => $originErr], 403);
    }
    if (!verify_csrf_token($csrfSecret, $providedCsrfToken)) {
        emit_json(['ok' => false, 'error' => 'Forbidden: invalid or missing CSRF token (reload the page and try again)'], 403);
    }
}

$freshCsrf = !$isPost ? issue_csrf_token($csrfSecret) : '';

$sockPath = getenv('DA_LIMITER_ADMIN_SOCK') ?: '/var/run/da-resourced.sock';
$errno = 0;
$errstr = '';
$fp = @stream_socket_client('unix://' . $sockPath, $errno, $errstr, 5.0);
if ($fp === false) {
    $errPayload = [
        'ok' => false,
        'error' => "Cannot connect to da-resourced socket ({$sockPath}): {$errstr} ({$errno}). Verify `systemctl status da-resourced`.",
    ];
    if ($freshCsrf !== '') {
        $errPayload['csrf_token'] = $freshCsrf;
    }
    emit_json($errPayload, 200);
}

stream_set_timeout($fp, 15);
$encodedReq = json_encode($input, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . "\n";
fwrite($fp, $encodedReq);

$rawReply = fgets($fp);
fclose($fp);

if (!is_string($rawReply) || trim($rawReply) === '') {
    $errPayload = ['ok' => false, 'error' => 'Empty response from da-resourced daemon'];
    if ($freshCsrf !== '') {
        $errPayload['csrf_token'] = $freshCsrf;
    }
    emit_json($errPayload, 200);
}

$decodedReply = json_decode($rawReply, true);
if (!is_array($decodedReply)) {
    $errPayload = ['ok' => false, 'error' => 'Malformed JSON from da-resourced daemon'];
    if ($freshCsrf !== '') {
        $errPayload['csrf_token'] = $freshCsrf;
    }
    emit_json($errPayload, 200);
}

if ($freshCsrf !== '') {
    $decodedReply['csrf_token'] = $freshCsrf;
}

emit_json($decodedReply, 200);
