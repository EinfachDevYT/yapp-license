<?php
declare(strict_types=1);

namespace Nooky\License;

/**
 * Hält das Ed25519-Schlüsselpaar des Lizenzservers (data/keys.json).
 * Der Secret Key signiert die Tokens, der Public Key wird in den Chat
 * eingebaut. Geht keys.json verloren, sind alle ausgestellten Tokens wertlos.
 */
final class Keystore
{
    public static function path(): string
    {
        return dirname(__DIR__) . '/data/keys.json';
    }

    public static function exists(): bool
    {
        return is_file(self::path());
    }

    /** Erzeugt ein neues Schlüsselpaar und schreibt es nach data/keys.json. */
    public static function create(): array
    {
        $pair   = sodium_crypto_sign_keypair();
        $secret = sodium_crypto_sign_secretkey($pair);
        $public = sodium_crypto_sign_publickey($pair);

        $data = [
            'algo'       => 'ed25519',
            'public'     => base64_encode($public),
            'secret'     => base64_encode($secret),
            'created_at' => time(),
        ];

        $json = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        if ($json === false) {
            throw new \RuntimeException('Schlüsselpaar konnte nicht serialisiert werden.');
        }

        // Erst mit 0600 anlegen, dann befüllen – der Secret Key darf nie
        // kurzzeitig world-readable auf der Platte liegen.
        $fh = fopen(self::path(), 'w');
        if ($fh === false) {
            throw new \RuntimeException('data/keys.json ist nicht schreibbar.');
        }
        chmod(self::path(), 0600);
        fwrite($fh, $json);
        fclose($fh);

        return $data;
    }

    private static function load(): array
    {
        if (!self::exists()) {
            throw new \RuntimeException('Kein Schlüsselpaar vorhanden – bitte zuerst bin/setup.php ausführen.');
        }
        $data = json_decode((string) file_get_contents(self::path()), true);
        if (!is_array($data) || !isset($data['public'], $data['secret'])) {
            throw new \RuntimeException('data/keys.json ist beschädigt.');
        }
        return $data;
    }

    public static function secretKey(): string
    {
        return base64_decode(self::load()['secret'], true)
            ?: throw new \RuntimeException('Secret Key ist beschädigt.');
    }

    public static function publicKeyBase64(): string
    {
        return self::load()['public'];
    }
}
