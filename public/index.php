<?php
declare(strict_types=1);

/**
 * Admin-Panel des Lizenzservers: Keys erzeugen, Domain binden, Instanzen
 * begrenzen, Laufzeit setzen, sperren/entsperren und Log ansehen.
 */

require dirname(__DIR__) . '/src/Db.php';
require dirname(__DIR__) . '/src/Auth.php';
require dirname(__DIR__) . '/src/Keystore.php';

use Nooky\License\Auth;
use Nooky\License\Db;
use Nooky\License\Keystore;

Auth::boot();

$pdo  = Db::pdo();
$page = $_GET['page'] ?? 'dashboard';

function e(string $s): string
{
    return htmlspecialchars($s, ENT_QUOTES, 'UTF-8');
}

/** Lizenzschlüssel im Format XXXX-XXXX-XXXX-XXXX (Großbuchstaben + Ziffern, ohne Verwechsler). */
function makeKey(): string
{
    $alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // ohne 0/O/1/I
    $out = '';
    for ($i = 0; $i < 16; $i++) {
        if ($i > 0 && $i % 4 === 0) {
            $out .= '-';
        }
        $out .= $alphabet[random_int(0, strlen($alphabet) - 1)];
    }
    return $out;
}

// ---- Login ----------------------------------------------------------------
if ($page === 'login') {
    $error = '';
    if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
        if (!Auth::checkCsrf($_POST['csrf'] ?? null)) {
            $error = 'Sitzung abgelaufen, bitte erneut.';
        } elseif (Auth::attempt(trim((string) ($_POST['username'] ?? '')), (string) ($_POST['password'] ?? ''))) {
            header('Location: ?page=dashboard');
            exit;
        } else {
            $error = 'Login fehlgeschlagen.';
        }
    }
    render_login($error);
    exit;
}

if ($page === 'logout') {
    Auth::logout();
    header('Location: ?page=login');
    exit;
}

// ---- Ab hier nur eingeloggt ----------------------------------------------
Auth::requireLogin();

// POST-Aktionen.
if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
    if (!Auth::checkCsrf($_POST['csrf'] ?? null)) {
        http_response_code(400);
        exit('CSRF');
    }
    $action = $_POST['action'] ?? '';

    if ($action === 'create') {
        $domain = strtolower(trim((string) ($_POST['domain'] ?? '')));
        $domain = preg_replace('/^www\./', '', preg_replace('/:\d+$/', '', $domain) ?? $domain) ?? $domain;
        $max    = max(1, (int) ($_POST['max_instances'] ?? 1));
        $days   = (int) ($_POST['days'] ?? 0);
        $note   = trim((string) ($_POST['note'] ?? '')) ?: null;
        $expires = $days > 0 ? time() + $days * 86400 : null;

        if ($domain !== '') {
            $stmt = $pdo->prepare(
                'INSERT INTO keys (license_key, domain, max_instances, expires_at, status, note, created_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?)'
            );
            $stmt->execute([makeKey(), $domain, $max, $expires, 'active', $note, time()]);
        }
    } elseif ($action === 'lock' || $action === 'unlock') {
        $stmt = $pdo->prepare('UPDATE keys SET status = ? WHERE id = ?');
        $stmt->execute([$action === 'lock' ? 'locked' : 'active', (int) ($_POST['id'] ?? 0)]);
    } elseif ($action === 'delete') {
        $stmt = $pdo->prepare('DELETE FROM keys WHERE id = ?');
        $stmt->execute([(int) ($_POST['id'] ?? 0)]);
    } elseif ($action === 'reset_instances') {
        $stmt = $pdo->prepare('DELETE FROM instances WHERE key_id = ?');
        $stmt->execute([(int) ($_POST['id'] ?? 0)]);
    }
    header('Location: ?page=' . urlencode(is_string($page) ? $page : 'dashboard'));
    exit;
}

// ---- Ansichten ------------------------------------------------------------
if ($page === 'log') {
    $rows = $pdo->query('SELECT * FROM log ORDER BY id DESC LIMIT 200')->fetchAll();
    render_log($rows);
    exit;
}

// Dashboard (Key-Liste).
$keys = $pdo->query(
    'SELECT k.*, (SELECT COUNT(*) FROM instances i WHERE i.key_id = k.id) AS inst_count
     FROM keys k ORDER BY k.id DESC'
)->fetchAll();
render_dashboard($keys);


// ---- Rendering ------------------------------------------------------------
function layout_head(string $title): void
{
    $csrf = Auth::csrfToken();
    echo '<!doctype html><html lang="de"><head><meta charset="utf-8">';
    echo '<meta name="viewport" content="width=device-width, initial-scale=1">';
    echo '<title>' . e($title) . ' · nooky-license</title>';
    echo '<style>' . panel_css() . '</style></head><body>';
    echo '<header><div class="brand">nooky<span>·license</span></div><nav>';
    if (Auth::check()) {
        echo '<a href="?page=dashboard">Keys</a><a href="?page=log">Log</a>';
        echo '<a class="ghost" href="?page=logout">Abmelden</a>';
    }
    echo '</nav></header><main>';
    // CSRF für JS-freie Forms global verfügbar machen.
    $GLOBALS['__csrf'] = $csrf;
}

function layout_foot(): void
{
    echo '</main></body></html>';
}

function csrf_field(): string
{
    return '<input type="hidden" name="csrf" value="' . e($GLOBALS['__csrf'] ?? Auth::csrfToken()) . '">';
}

function render_login(string $error): void
{
    layout_head('Login');
    echo '<div class="card narrow"><h1>Anmelden</h1>';
    if ($error !== '') {
        echo '<p class="err">' . e($error) . '</p>';
    }
    echo '<form method="post" action="?page=login">' . csrf_field();
    echo '<label>Benutzername<input name="username" autofocus autocomplete="username"></label>';
    echo '<label>Passwort<input type="password" name="password" autocomplete="current-password"></label>';
    echo '<button type="submit">Login</button></form></div>';
    layout_foot();
}

function render_dashboard(array $keys): void
{
    layout_head('Keys');
    echo '<div class="card"><h1>Neuen Key erzeugen</h1>';
    echo '<form method="post" class="grid"><input type="hidden" name="action" value="create">' . csrf_field();
    echo '<label>Domain<input name="domain" placeholder="chat.nooky.cc" required></label>';
    echo '<label>Max. Instanzen<input type="number" name="max_instances" value="1" min="1"></label>';
    echo '<label>Laufzeit (Tage, 0 = unbegrenzt)<input type="number" name="days" value="0" min="0"></label>';
    echo '<label>Notiz<input name="note" placeholder="Kunde / Projekt"></label>';
    echo '<button type="submit">Key erzeugen</button></form></div>';

    echo '<div class="card"><h1>Keys</h1>';
    if (!$keys) {
        echo '<p class="muted">Noch keine Keys.</p>';
    } else {
        echo '<table><thead><tr><th>Key</th><th>Domain</th><th>Instanzen</th><th>Läuft ab</th><th>Status</th><th></th></tr></thead><tbody>';
        foreach ($keys as $k) {
            $expTxt = $k['expires_at'] === null
                ? '∞'
                : date('d.m.Y', (int) $k['expires_at']) . ((int) $k['expires_at'] < time() ? ' (abgelaufen)' : '');
            $locked = $k['status'] === 'locked';
            echo '<tr>';
            echo '<td><code>' . e($k['license_key']) . '</code>' . ($k['note'] ? '<br><span class="muted">' . e((string) $k['note']) . '</span>' : '') . '</td>';
            echo '<td>' . e($k['domain']) . '</td>';
            echo '<td>' . (int) $k['inst_count'] . ' / ' . (int) $k['max_instances'];
            if ((int) $k['inst_count'] > 0) {
                echo ' <form method="post" class="inline" onsubmit="return confirm(\'Instanzen dieses Keys zurücksetzen?\')"><input type="hidden" name="action" value="reset_instances"><input type="hidden" name="id" value="' . (int) $k['id'] . '">' . csrf_field() . '<button class="link">reset</button></form>';
            }
            echo '</td>';
            echo '<td>' . e($expTxt) . '</td>';
            echo '<td><span class="badge ' . ($locked ? 'bad' : 'ok') . '">' . ($locked ? 'gesperrt' : 'aktiv') . '</span></td>';
            echo '<td class="actions">';
            echo '<form method="post" class="inline"><input type="hidden" name="action" value="' . ($locked ? 'unlock' : 'lock') . '"><input type="hidden" name="id" value="' . (int) $k['id'] . '">' . csrf_field() . '<button class="' . ($locked ? '' : 'warn') . '">' . ($locked ? 'entsperren' : 'sperren') . '</button></form>';
            echo '<form method="post" class="inline" onsubmit="return confirm(\'Key endgültig löschen?\')"><input type="hidden" name="action" value="delete"><input type="hidden" name="id" value="' . (int) $k['id'] . '">' . csrf_field() . '<button class="danger">löschen</button></form>';
            echo '</td></tr>';
        }
        echo '</tbody></table>';
    }
    echo '</div>';
    layout_foot();
}

function render_log(array $rows): void
{
    layout_head('Log');
    echo '<div class="card"><h1>Prüf-Log <span class="muted">(letzte 200)</span></h1>';
    if (!$rows) {
        echo '<p class="muted">Noch keine Einträge.</p>';
    } else {
        echo '<table><thead><tr><th>Zeit</th><th>Ergebnis</th><th>Key</th><th>Domain</th><th>Instanz</th><th>IP</th></tr></thead><tbody>';
        foreach ($rows as $r) {
            $ok = $r['result'] === 'ok';
            echo '<tr>';
            echo '<td class="muted">' . e(date('d.m. H:i:s', (int) $r['ts'])) . '</td>';
            echo '<td><span class="badge ' . ($ok ? 'ok' : 'bad') . '">' . e((string) $r['result']) . '</span>' . ($r['detail'] ? ' <span class="muted">' . e((string) $r['detail']) . '</span>' : '') . '</td>';
            echo '<td><code>' . e((string) ($r['license_key'] ?? '–')) . '</code></td>';
            echo '<td>' . e((string) ($r['domain'] ?? '–')) . '</td>';
            echo '<td class="muted">' . e((string) ($r['instance_id'] ?? '–')) . '</td>';
            echo '<td class="muted">' . e((string) ($r['ip'] ?? '–')) . '</td>';
            echo '</tr>';
        }
        echo '</tbody></table>';
    }
    echo '</div>';
    layout_foot();
}

function panel_css(): string
{
    return <<<'CSS'
    :root{--bg:#0d0f0d;--panel:#15181a;--line:#262b2e;--txt:#e8eceb;--muted:#8a9490;--lime:#c7f24a;--violet:#8b5cf6;--pink:#ec4899;--bad:#ef4444;--ok:#c7f24a}
    *{box-sizing:border-box}
    body{margin:0;background:var(--bg);color:var(--txt);font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
    header{display:flex;justify-content:space-between;align-items:center;padding:14px 20px;border-bottom:1px solid var(--line);background:var(--panel)}
    .brand{font-weight:800;font-size:20px;letter-spacing:-.5px}
    .brand span{color:var(--lime)}
    nav a{color:var(--muted);text-decoration:none;margin-left:18px;font-weight:600}
    nav a:hover{color:var(--txt)}
    nav a.ghost{color:var(--pink)}
    main{max-width:1000px;margin:24px auto;padding:0 16px}
    h1{font-size:18px;margin:0 0 16px}
    .card{background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:20px;margin-bottom:20px}
    .card.narrow{max-width:360px;margin:60px auto}
    label{display:block;margin-bottom:12px;font-size:13px;color:var(--muted);font-weight:600}
    input{display:block;width:100%;margin-top:5px;padding:10px 12px;background:var(--bg);border:1px solid var(--line);border-radius:10px;color:var(--txt);font-size:14px}
    input:focus{outline:none;border-color:var(--lime)}
    .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:4px 16px;align-items:end}
    button{padding:9px 16px;border:0;border-radius:10px;background:var(--lime);color:#0d0f0d;font-weight:700;cursor:pointer;font-size:14px}
    button:hover{filter:brightness(1.08)}
    button.warn{background:#f59e0b}
    button.danger{background:transparent;color:var(--bad);border:1px solid var(--bad)}
    button.link{background:none;color:var(--muted);padding:0;font-weight:600;text-decoration:underline}
    table{width:100%;border-collapse:collapse;font-size:14px}
    th,td{text-align:left;padding:10px 8px;border-bottom:1px solid var(--line);vertical-align:top}
    th{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.5px}
    code{background:var(--bg);padding:2px 6px;border-radius:6px;font-size:13px;color:var(--lime)}
    .muted{color:var(--muted);font-size:13px}
    .badge{padding:2px 9px;border-radius:999px;font-size:12px;font-weight:700}
    .badge.ok{background:rgba(199,242,74,.15);color:var(--lime)}
    .badge.bad{background:rgba(239,68,68,.15);color:var(--bad)}
    .actions{display:flex;gap:8px;flex-wrap:wrap}
    .inline{display:inline}
    .err{background:rgba(239,68,68,.12);color:#fca5a5;padding:10px 12px;border-radius:10px;margin-bottom:12px}
    CSS;
}
