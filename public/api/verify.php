<?php
declare(strict_types=1);

/**
 * Lizenz-Prüf-Endpunkt. Der Chat ruft diesen Endpunkt stündlich auf und
 * erhält bei Erfolg ein frisch signiertes Ed25519-Token zurück.
 *
 * Request  (POST, JSON oder Form):
 *   { "key": "...", "domain": "chat.example.de", "instance": "..." }
 *
 * Response (JSON):
 *   erfolgreich: { "valid": true,  "token": "<payload>.<sig>" }
 *   abgelehnt:   { "valid": false, "reason": "locked|expired|bad_domain|too_many|unknown_key|bad_request" }
 */

require dirname(__DIR__, 2) . '/src/Db.php';
require dirname(__DIR__, 2) . '/src/Keystore.php';
require dirname(__DIR__, 2) . '/src/Token.php';

use Yapp\License\Db;
use Yapp\License\Token;

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

$ip = $_SERVER['REMOTE_ADDR'] ?? '';

function respond(array $data, int $status = 200): never
{
    http_response_code($status);
    echo json_encode($data, JSON_UNESCAPED_SLASHES);
    exit;
}

function writeLog(string $result, ?string $key, ?string $instance, ?string $domain, string $detail = ''): void
{
    global $ip;
    try {
        $stmt = Db::pdo()->prepare(
            'INSERT INTO log (ts, license_key, instance_id, domain, ip, result, detail)
             VALUES (?, ?, ?, ?, ?, ?, ?)'
        );
        $stmt->execute([time(), $key, $instance, $domain, $ip, $result, $detail]);
    } catch (\Throwable) {
        // Logging darf die Antwort nie verhindern.
    }
}

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
    respond(['valid' => false, 'reason' => 'bad_request', 'detail' => 'POST erwartet'], 405);
}

// Eingabe lesen – JSON-Body bevorzugt, sonst Formfelder.
$raw   = file_get_contents('php://input') ?: '';
$input = json_decode($raw, true);
if (!is_array($input)) {
    $input = $_POST;
}

$key      = isset($input['key'])      ? trim((string) $input['key'])      : '';
$domain   = isset($input['domain'])   ? strtolower(trim((string) $input['domain'])) : '';
$instance = isset($input['instance']) ? trim((string) $input['instance']) : '';

// Domain normalisieren: Port und führendes www. weg, nur Host.
$domain = preg_replace('/:\d+$/', '', $domain) ?? $domain;
$domain = preg_replace('/^www\./', '', $domain) ?? $domain;

if ($key === '' || $domain === '' || $instance === '') {
    writeLog('bad_request', $key ?: null, $instance ?: null, $domain ?: null, 'Felder fehlen');
    respond(['valid' => false, 'reason' => 'bad_request'], 400);
}
if (strlen($key) > 128 || strlen($domain) > 253 || strlen($instance) > 128) {
    writeLog('bad_request', null, null, null, 'Feld zu lang');
    respond(['valid' => false, 'reason' => 'bad_request'], 400);
}

$pdo  = Db::pdo();
$stmt = $pdo->prepare('SELECT * FROM keys WHERE license_key = ?');
$stmt->execute([$key]);
$lic = $stmt->fetch();

if ($lic === false) {
    writeLog('unknown_key', $key, $instance, $domain);
    respond(['valid' => false, 'reason' => 'unknown_key']);
}

if ($lic['status'] === 'locked') {
    writeLog('locked', $key, $instance, $domain);
    respond(['valid' => false, 'reason' => 'locked']);
}

if ($lic['expires_at'] !== null && (int) $lic['expires_at'] < time()) {
    writeLog('expired', $key, $instance, $domain);
    respond(['valid' => false, 'reason' => 'expired']);
}

if (strtolower($lic['domain']) !== $domain) {
    writeLog('bad_domain', $key, $instance, $domain, 'erwartet ' . $lic['domain']);
    respond(['valid' => false, 'reason' => 'bad_domain']);
}

// Instanz-Verwaltung: bekannte Instanz aktualisieren, neue nur anlegen,
// solange max_instances nicht überschritten wird.
$now = time();
$sel = $pdo->prepare('SELECT id FROM instances WHERE key_id = ? AND instance_id = ?');
$sel->execute([$lic['id'], $instance]);
$known = $sel->fetch();

if ($known === false) {
    $cnt = $pdo->prepare('SELECT COUNT(*) FROM instances WHERE key_id = ?');
    $cnt->execute([$lic['id']]);
    if ((int) $cnt->fetchColumn() >= (int) $lic['max_instances']) {
        writeLog('too_many', $key, $instance, $domain, 'max ' . $lic['max_instances']);
        respond(['valid' => false, 'reason' => 'too_many']);
    }
    $ins = $pdo->prepare(
        'INSERT INTO instances (key_id, instance_id, domain, first_seen, last_seen)
         VALUES (?, ?, ?, ?, ?)'
    );
    $ins->execute([$lic['id'], $instance, $domain, $now, $now]);
} else {
    $upd = $pdo->prepare('UPDATE instances SET last_seen = ?, domain = ? WHERE id = ?');
    $upd->execute([$now, $domain, $known['id']]);
}

// Alles gut – Token ausstellen. Läuft nie länger als der Key selbst.
$expires = $now + Token::TTL_SECONDS;
if ($lic['expires_at'] !== null) {
    $expires = min($expires, (int) $lic['expires_at']);
}

$token = Token::issue([
    'domain'     => $domain,
    'instance'   => $instance,
    'key_fp'     => substr(hash('sha256', $key), 0, 16),
    'expires_at' => $expires,
]);

writeLog('ok', $key, $instance, $domain);
respond(['valid' => true, 'token' => $token]);
