<?php
declare(strict_types=1);

/**
 * Einrichtung des Lizenzservers:
 *   - erzeugt das Ed25519-Schlüsselpaar (data/keys.json)
 *   - legt einen Admin-Account an
 *   - gibt den Public Key aus, der in den Chat eingebaut wird
 *
 * Aufruf (als der User, dem data/ gehört, z. B. www-data):
 *   php bin/setup.php
 *
 * Nicht-interaktiv (z. B. für Automatisierung):
 *   ADMIN_USER=admin ADMIN_PASS=geheim php bin/setup.php --force
 */

if (PHP_SAPI !== 'cli') {
    fwrite(STDERR, "Nur über die Kommandozeile.\n");
    exit(1);
}

require dirname(__DIR__) . '/src/Db.php';
require dirname(__DIR__) . '/src/Keystore.php';

use Yapp\License\Db;
use Yapp\License\Keystore;

$force = in_array('--force', $argv, true);

function prompt(string $label, bool $hidden = false): string
{
    fwrite(STDOUT, $label);
    if ($hidden && stream_isatty(STDIN)) {
        shell_exec('stty -echo 2>/dev/null');
        $value = rtrim((string) fgets(STDIN), "\n");
        shell_exec('stty echo 2>/dev/null');
        fwrite(STDOUT, "\n");
    } else {
        $value = rtrim((string) fgets(STDIN), "\n");
    }
    return $value;
}

echo "== yapp-license Setup ==\n\n";

// Datenbank anlegen/migrieren.
$pdo = Db::pdo();
echo "Datenbank:     " . Db::path() . "\n";

// Schlüsselpaar.
if (Keystore::exists() && !$force) {
    echo "Schlüsselpaar: vorhanden (keys.json bleibt unverändert)\n";
} else {
    if (Keystore::exists()) {
        echo "WARNUNG: --force überschreibt das bestehende Schlüsselpaar!\n";
        echo "Alle bereits ausgestellten Tokens werden damit ungültig.\n";
        if (prompt("Wirklich neu erzeugen? [tippe 'ja']: ") !== 'ja') {
            echo "Abgebrochen.\n";
            exit(1);
        }
    }
    Keystore::create();
    echo "Schlüsselpaar: neu erzeugt\n";
}

// Admin-Account.
$user = getenv('ADMIN_USER') ?: '';
$pass = getenv('ADMIN_PASS') ?: '';

if ($user === '') {
    $user = prompt("\nAdmin-Benutzername: ");
}
while (strlen($user) < 3) {
    $user = prompt("Benutzername (min. 3 Zeichen): ");
}

if ($pass === '') {
    $pass = prompt("Admin-Passwort: ", true);
    $again = prompt("Passwort wiederholen: ", true);
    if ($pass !== $again) {
        fwrite(STDERR, "Passwörter stimmen nicht überein.\n");
        exit(1);
    }
}
if (strlen($pass) < 8) {
    fwrite(STDERR, "Passwort muss mindestens 8 Zeichen haben.\n");
    exit(1);
}

$hash = password_hash($pass, PASSWORD_BCRYPT, ['cost' => 12]);
$stmt = $pdo->prepare(
    'INSERT INTO admins (username, pass_hash) VALUES (:u, :h)
     ON CONFLICT(username) DO UPDATE SET pass_hash = :h'
);
$stmt->execute([':u' => $user, ':h' => $hash]);
echo "Admin:         '{$user}' angelegt/aktualisiert\n";

// Public Key ausgeben.
echo "\n== Public Key für den Chat ==\n";
echo "Diesen Wert in der config.php des Chats unter 'public_key' eintragen:\n\n";
echo Keystore::publicKeyBase64() . "\n\n";
echo "Fertig.\n";
