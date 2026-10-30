<?php
declare(strict_types=1);

namespace Nooky\License;

/**
 * Admin-Login (Session) und CSRF-Schutz fürs Panel.
 */
final class Auth
{
    public static function boot(): void
    {
        if (session_status() === PHP_SESSION_NONE) {
            session_set_cookie_params([
                'httponly' => true,
                'samesite' => 'Lax',
                'secure'   => (($_SERVER['HTTPS'] ?? '') !== '')
                              || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https'),
            ]);
            session_name('nooky_lic');
            session_start();
        }
    }

    public static function attempt(string $username, string $password): bool
    {
        $stmt = Db::pdo()->prepare('SELECT id, pass_hash FROM admins WHERE username = ?');
        $stmt->execute([$username]);
        $row = $stmt->fetch();

        if ($row === false) {
            // Dummy-Verify gegen User-Enumeration per Timing (konstanter Aufwand).
            password_verify($password, '$2y$12$liNstBElk3huoJXe2RG9p.tHcxNmObn1XF9kskbHwbmEBB0cmLHTS');
            return false;
        }
        if (!password_verify($password, $row['pass_hash'])) {
            return false;
        }

        session_regenerate_id(true);
        $_SESSION['admin_id']       = (int) $row['id'];
        $_SESSION['admin_username'] = $username;
        return true;
    }

    public static function check(): bool
    {
        return isset($_SESSION['admin_id']);
    }

    public static function requireLogin(): void
    {
        if (!self::check()) {
            header('Location: ?page=login');
            exit;
        }
    }

    public static function logout(): void
    {
        $_SESSION = [];
        session_destroy();
    }

    public static function csrfToken(): string
    {
        if (empty($_SESSION['csrf'])) {
            $_SESSION['csrf'] = bin2hex(random_bytes(16));
        }
        return $_SESSION['csrf'];
    }

    public static function checkCsrf(?string $token): bool
    {
        return is_string($token)
            && !empty($_SESSION['csrf'])
            && hash_equals($_SESSION['csrf'], $token);
    }
}
