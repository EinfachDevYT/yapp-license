# nooky-license

Lizenzserver für [nooky-chat](https://github.com/EinfachDevYT/yapp-chat). PHP 8.4, SQLite, kein Framework.

## Aufbau

```
bin/setup.php          Einrichtung: Schlüsselpaar + Admin, gibt den Public Key aus
public/index.php       Admin-Panel: Keys erzeugen, Domain, Instanzen, Laufzeit, sperren, Log
public/api/verify.php  Prüf-API für den Chat, gibt ein signiertes Token zurück
src/                   Logik (Db, Keystore, Token, Auth)
data/                  license.sqlite + keys.json (nicht im Repo)
```

Document Root ist `public/`.

## Einrichtung

```bash
sudo -u www-data php bin/setup.php
```

Den ausgegebenen Public Key in der `config.php` des Chats unter `'license' => ['public_key' => …]` eintragen.
Anleitung für beide Teile: [nooky-chat/INSTALL.md](https://github.com/EinfachDevYT/yapp-chat/blob/main/INSTALL.md).
`data/keys.json` enthält den privaten Schlüssel – sichern und nie veröffentlichen.

## API

`POST /api/verify.php` mit JSON `{"key": "...", "domain": "chat.nooky.cc", "instance": "..."}`

- Erfolg: `{"valid": true, "token": "<payload>.<signatur>"}`
- Abgelehnt: `{"valid": false, "reason": "locked|expired|bad_domain|too_many|unknown_key|bad_request"}`

Token = `base64url(payload-json) "." base64url(ed25519-signatur über payload-json)`,
48 h gültig (nie länger als der Key selbst).
