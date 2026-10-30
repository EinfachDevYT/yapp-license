<?php
declare(strict_types=1);

namespace Yapp\License;

use PDO;

/**
 * Schlanker SQLite-Zugriff für den Lizenzserver. Legt das Schema beim
 * ersten Aufruf an (idempotent).
 */
final class Db
{
    private static ?PDO $pdo = null;

    public static function path(): string
    {
        return dirname(__DIR__) . '/data/license.sqlite';
    }

    public static function pdo(): PDO
    {
        if (self::$pdo instanceof PDO) {
            return self::$pdo;
        }

        $pdo = new PDO('sqlite:' . self::path(), null, null, [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false,
        ]);
        $pdo->exec('PRAGMA journal_mode = WAL');
        $pdo->exec('PRAGMA foreign_keys = ON');

        self::$pdo = $pdo;
        self::migrate($pdo);

        return $pdo;
    }

    private static function migrate(PDO $pdo): void
    {
        $pdo->exec(<<<'SQL'
            CREATE TABLE IF NOT EXISTS admins (
                id        INTEGER PRIMARY KEY,
                username  TEXT    NOT NULL UNIQUE,
                pass_hash TEXT    NOT NULL
            );

            CREATE TABLE IF NOT EXISTS keys (
                id            INTEGER PRIMARY KEY,
                license_key   TEXT    NOT NULL UNIQUE,
                domain        TEXT    NOT NULL,
                max_instances INTEGER NOT NULL DEFAULT 1,
                expires_at    INTEGER,                        -- unix, NULL = unbegrenzt
                status        TEXT    NOT NULL DEFAULT 'active', -- active | locked
                note          TEXT,
                created_at    INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS instances (
                id          INTEGER PRIMARY KEY,
                key_id      INTEGER NOT NULL REFERENCES keys(id) ON DELETE CASCADE,
                instance_id TEXT    NOT NULL,
                domain      TEXT,
                first_seen  INTEGER NOT NULL,
                last_seen   INTEGER NOT NULL,
                UNIQUE(key_id, instance_id)
            );

            CREATE TABLE IF NOT EXISTS log (
                id          INTEGER PRIMARY KEY,
                ts          INTEGER NOT NULL,
                license_key TEXT,
                instance_id TEXT,
                domain      TEXT,
                ip          TEXT,
                result      TEXT    NOT NULL,
                detail      TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_log_ts ON log(ts);
            SQL);
    }
}
