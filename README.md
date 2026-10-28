# splunk-acs-app-export

Export every app (or a chosen few) from a Splunk Cloud Victoria stack through ACS, and unpack each one into `<out>/<app>/`. It's a single file that needs only the Python 3.8+ standard library.

```bash
export SPLUNK_TOKEN=eyJ...                              # ACS-capable token (sc_admin)
python acs_app_export.py --stack acme                   # all apps -> apps-acme/
python acs_app_export.py --stack acme --app my_app      # one app (repeatable, case-insensitive)
python acs_app_export.py --stack acme --list            # inventory only
python acs_app_export.py --stack acme --include 'TA-*' --exclude 'TA-old*'
```

For a specific search head (for example, an ES SHC member), pass its ACS prefix: `--stack sh-i-0abc123.acme`. You can also pass `--acs-base <url>`.

## Token

First match wins: `--token`, `--token-file PATH`, `--token-cmd "CMD"`, then `$SPLUNK_TOKEN`. `--token-cmd` works with any secret store:

```bash
--token-cmd "aws ssm get-parameter --name /splunk/acme --with-decryption --query Parameter.Value --output text"
--token-cmd "op read op://vault/splunk-acme/token"
```

## Behaviour

- **Re-runnable.** Apps already on disk are skipped, so a second run picks up only failures. Use `--force` to re-export everything.
- **Safe writes.** Each app is unpacked into a scratch folder, then moved into place in one step. An interrupted run never leaves a half-written app that looks complete.
- **Search-type apps** that refuse a `default/` export (`SEARCH_APPS_ONLY_LOCAL_AND_USERS_CONFIGS_ALLOWED`, `DEFAULT_APPS_EXPORT_NOT_ALLOWED`) are retried with `local/` + `users/` only. The results file records this.
- **Archive entries are validated.** Path-traversal, link and device entries are refused.
- 429 and 5xx responses retry with backoff. Listing pages at 100, the ACS maximum.
- `<out>/_export_results.json` holds a status per app. The exit code is `1` if any app failed.

| Flag | Effect |
|---|---|
| `--out DIR` | Output folder (default `apps-<stack>`) |
| `--keep-archive` | Also keep `<app>.tgz` |
| `--no-default` / `--no-users` | Leave out `default/` or `users/` (private objects) |
| `--timeout` / `--retries` | Per request (defaults: 300 s, 4 retries) |

## Tests

```bash
python -m unittest -v      # offline, against a fake ACS on localhost
```

Exported apps can contain lookups, credentials in `passwords.conf`, and user objects. `.gitignore` keeps `apps-*/` out of git.
