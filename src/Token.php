<?php
declare(strict_types=1);

namespace Nooky\License;

/**
 * Token-Format, das Server und Chat teilen.
 *
 *   <base64url(payload-json)> "." <base64url(ed25519-signatur)>
 *
 * Die Signatur wird über die rohen Payload-JSON-Bytes gebildet (detached),
 * damit beide Seiten exakt dieselben Bytes prüfen. Die Gegenstelle in
 * src/License.php des Chats verifiziert mit demselben Schema.
 */
final class Token
{
    /** Gültigkeit eines ausgestellten Tokens. Großzügiger als die 12 h
     *  Offline-Toleranz des Chats, damit ein Token innerhalb der Toleranz
     *  nie allein wegen Ablauf ungültig wird. */
    public const TTL_SECONDS = 48 * 3600;

    public static function issue(array $payload): string
    {
        $payload += [
            'v'         => 1,
            'issued_at' => time(),
            'expires_at'=> time() + self::TTL_SECONDS,
            'nonce'     => bin2hex(random_bytes(8)),
        ];

        $json = json_encode($payload, JSON_UNESCAPED_SLASHES);
        if ($json === false) {
            throw new \RuntimeException('Token-Payload konnte nicht serialisiert werden.');
        }

        $sig = sodium_crypto_sign_detached($json, Keystore::secretKey());

        return self::b64url($json) . '.' . self::b64url($sig);
    }

    private static function b64url(string $raw): string
    {
        return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
    }
}
