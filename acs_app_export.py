#!/usr/bin/env python3
"""
Export apps from one Splunk Cloud (Victoria) stack through the Admin Config
Service (ACS) and unpack each one into <out>/<app>/.

    python acs_app_export.py --stack acme                 # every app
    python acs_app_export.py --stack acme --app my_app    # just one (repeatable)
    python acs_app_export.py --stack acme --list          # inventory only

Token, first match wins: --token, --token-file, --token-cmd, $SPLUNK_TOKEN.
Standard library only; Python 3.8+.
"""

import argparse
import fnmatch
import io
import json
import os
import shutil
import ssl
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from datetime import datetime

ACS_HOST = "https://admin.splunk.com"

# ACS rejects count > 100 and returns no nextLink, so page with count+offset
# until a short page comes back.
PAGE_SIZE = 100

# Some apps refuse a full export and name the reason in the error body. Both
# are answered by retrying without the default/ layer.
RETRY_WITHOUT_DEFAULT = (
    "SEARCH_APPS_ONLY_LOCAL_AND_USERS_CONFIGS_ALLOWED",
    "DEFAULT_APPS_EXPORT_NOT_ALLOWED",
)

RESULTS_FILE = "_export_results.json"


class AcsError(Exception):
    def __init__(self, status, body):
        super().__init__(f"HTTP {status}: {body}")
        self.status = status
        self.body = body


# --------------------------------------------------------------------------
# Token
# --------------------------------------------------------------------------

def resolve_token(args):
    if args.token:
        return args.token.strip(), "--token"
    if args.token_file:
        with open(args.token_file, encoding="utf-8") as f:
            return f.read().strip(), f"--token-file {args.token_file}"
    if args.token_cmd:
        env = dict(os.environ, MSYS_NO_PATHCONV="1")  # keep Git Bash off /paths
        r = subprocess.run(args.token_cmd, shell=True, capture_output=True,
                           text=True, env=env)
        if r.returncode != 0 or not r.stdout.strip():
            sys.exit(f"ERROR: --token-cmd failed: {r.stderr.strip() or 'no output'}")
        return r.stdout.strip(), "--token-cmd"
    if os.environ.get("SPLUNK_TOKEN"):
        return os.environ["SPLUNK_TOKEN"].strip(), "$SPLUNK_TOKEN"
    sys.exit("ERROR: no token. Use --token, --token-file, --token-cmd or $SPLUNK_TOKEN.")


# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------

class Acs:
    def __init__(self, base, token, timeout, retries, insecure=False):
        self.base = base.rstrip("/")
        self.token = token
        self.timeout = timeout
        self.retries = retries
        self.ctx = ssl.create_default_context()
        if insecure:
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE

    def get(self, path, params=None):
        """GET -> (bytes, content_type). Retries 429 and 5xx with backoff."""
        url = f"{self.base}{path}"
        if params:
            url += "?" + urllib.parse.urlencode(params)
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {self.token}"})
        for attempt in range(self.retries + 1):
            try:
                with urllib.request.urlopen(req, context=self.ctx, timeout=self.timeout) as r:
                    return r.read(), r.headers.get("Content-Type", "")
            except urllib.error.HTTPError as e:
                body = e.read().decode("utf-8", errors="replace")[:500]
                if (e.code == 429 or e.code >= 500) and attempt < self.retries:
                    wait = e.headers.get("Retry-After", "")
                    time.sleep(int(wait) if wait.isdigit() else 2 ** attempt)
                    continue
                raise AcsError(e.code, " ".join(body.split())) from None
            except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
                if attempt < self.retries:
                    time.sleep(2 ** attempt)
                    continue
                raise AcsError(0, f"{type(e).__name__}: {getattr(e, 'reason', e)}") from None

    def list_apps(self):
        apps, offset = [], 0
        while True:
            data, _ = self.get("/apps/victoria", {"count": PAGE_SIZE, "offset": offset})
            payload = json.loads(data)
            page = payload.get("apps", []) if isinstance(payload, dict) else payload
            apps.extend(page)
            offset += len(page)
            if len(page) < PAGE_SIZE:
                return apps

    def export(self, app, include_default, include_users):
        params = {"local": "true",
                  "default": str(include_default).lower(),
                  "users": str(include_users).lower(),
                  "confs_only": "false"}
        return self.get(f"/apps/victoria/export/download/{urllib.parse.quote(app)}", params)


# --------------------------------------------------------------------------
# Archive handling
# --------------------------------------------------------------------------

def _safe_members(tf, dest):
    """Refuse absolute paths, '..' escapes and links that point outside dest."""
    root = os.path.realpath(dest)
    for m in tf.getmembers():
        target = os.path.realpath(os.path.join(root, m.name))
        if not (target == root or target.startswith(root + os.sep)):
            raise ValueError(f"unsafe path in archive: {m.name}")
        if m.issym() or m.islnk():
            link = os.path.realpath(os.path.join(os.path.dirname(target), m.linkname))
            if not link.startswith(root + os.sep):
                raise ValueError(f"unsafe link in archive: {m.name} -> {m.linkname}")
        if m.isdev():
            raise ValueError(f"device file in archive: {m.name}")
    return tf.getmembers()


def extract(data, dest):
    """Unpack a .tgz or .zip into dest. Returns 'tgz' or 'zip'."""
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
            members = _safe_members(tf, dest)
            if hasattr(tarfile, "data_filter"):  # 3.12+ (and 3.8-3.11 security releases)
                tf.extractall(dest, members=members, filter="data")
            else:
                tf.extractall(dest, members=members)
        return "tgz"
    except tarfile.ReadError:
        pass
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            root = os.path.realpath(dest)
            for name in zf.namelist():
                p = os.path.realpath(os.path.join(root, name))
                if not (p == root or p.startswith(root + os.sep)):
                    raise ValueError(f"unsafe path in archive: {name}")
            zf.extractall(dest)
        return "zip"
    except zipfile.BadZipFile:
        raise ValueError("response is neither a tar nor a zip archive") from None


def install(data, app, out_dir):
    """Extract into a scratch dir, then move into out_dir/app in one step, so
    an interrupted run never leaves a half-written app that looks complete."""
    scratch = tempfile.mkdtemp(prefix=f".{app}.", dir=out_dir)
    try:
        extract(data, scratch)
        entries = os.listdir(scratch)
        # Exports normally hold a single top-level folder named after the app.
        src = (os.path.join(scratch, entries[0])
               if len(entries) == 1 and os.path.isdir(os.path.join(scratch, entries[0]))
               else scratch)
        final = os.path.join(out_dir, app)
        if os.path.exists(final):
            shutil.rmtree(final)
        shutil.move(src, final)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def export_one(acs, app, args):
    """Returns (status, note)."""
    include_default = not args.no_default
    try:
        try:
            data, _ = acs.export(app, include_default, not args.no_users)
            note = ""
        except AcsError as e:
            if not include_default or not any(k in e.body for k in RETRY_WITHOUT_DEFAULT):
                raise
            data, _ = acs.export(app, False, not args.no_users)
            note = "default/ not exportable; local + users only"
        if args.keep_archive:
            with open(os.path.join(args.out, f"{app}.tgz"), "wb") as f:
                f.write(data)
        install(data, app, args.out)
        return "ok", note
    except AcsError as e:
        return "failed", str(e)
    except (ValueError, OSError, tarfile.TarError) as e:
        return "failed", f"{type(e).__name__}: {e}"


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    where = ap.add_mutually_exclusive_group(required=True)
    where.add_argument("--stack", help="Splunk Cloud stack name, e.g. 'acme'. For a "
                       "specific search head use its ACS prefix, e.g. 'sh-i-0abc.acme'")
    where.add_argument("--acs-base", help="full ACS base URL, e.g. "
                       "https://admin.splunk.com/acme/adminconfig/v2")

    tok = ap.add_argument_group("token (first match wins; else $SPLUNK_TOKEN)")
    tok.add_argument("--token", help="ACS/JWT token (visible in shell history)")
    tok.add_argument("--token-file", help="file containing the token")
    tok.add_argument("--token-cmd", help="shell command that prints the token, e.g. "
                     "\"aws ssm get-parameter --name /x --with-decryption "
                     "--query Parameter.Value --output text\"")

    sel = ap.add_argument_group("selection")
    sel.add_argument("--app", action="append", default=[],
                     help="export only this app (repeatable, case-insensitive)")
    sel.add_argument("--include", action="append", default=[], metavar="GLOB",
                     help="only apps matching this glob (repeatable)")
    sel.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                     help="skip apps matching this glob (repeatable)")
    sel.add_argument("--list", action="store_true", help="print the app inventory and exit")

    opt = ap.add_argument_group("output")
    opt.add_argument("--out", help="output directory (default: apps-<stack>)")
    opt.add_argument("--force", action="store_true", help="re-export apps already on disk")
    opt.add_argument("--keep-archive", action="store_true",
                     help="also keep the raw <app>.tgz next to the extracted folder")
    opt.add_argument("--no-default", action="store_true", help="omit the default/ layer")
    opt.add_argument("--no-users", action="store_true", help="omit users/ (private objects)")

    net = ap.add_argument_group("network")
    net.add_argument("--timeout", type=int, default=300, help="seconds per request (default 300)")
    net.add_argument("--retries", type=int, default=4, help="retries on 429/5xx (default 4)")
    net.add_argument("--insecure", action="store_true", help="skip TLS verification")
    args = ap.parse_args()

    base = args.acs_base or f"{ACS_HOST}/{args.stack}/adminconfig/v2"
    label = args.stack or urllib.parse.urlparse(base).path.strip("/").split("/")[0] or "stack"
    args.out = args.out or f"apps-{label}"

    token, token_src = resolve_token(args)
    acs = Acs(base, token, args.timeout, args.retries, args.insecure)

    print(f"ACS   {base}\nToken {token_src}")
    try:
        inventory = acs.list_apps()
    except AcsError as e:
        sys.exit(f"ERROR listing apps: {e}")
    by_lower = {a["name"].lower(): a for a in inventory if a.get("name")}
    print(f"Apps  {len(by_lower)} on stack")

    if args.app:
        missing = [a for a in args.app if a.lower() not in by_lower]
        if missing:
            sys.exit(f"ERROR: not on stack: {', '.join(missing)}")
        names = [by_lower[a.lower()]["name"] for a in args.app]
    else:
        names = sorted(a["name"] for a in by_lower.values())
    if args.include:
        names = [n for n in names if any(fnmatch.fnmatch(n, g) for g in args.include)]
    names = [n for n in names if not any(fnmatch.fnmatch(n, g) for g in args.exclude)]

    if args.list:
        for n in names:
            a = by_lower[n.lower()]
            print(f"  {n:<50} {a.get('version', ''):<12} {a.get('label', '')}")
        return

    os.makedirs(args.out, exist_ok=True)
    print(f"Out   {os.path.abspath(args.out)}  ({len(names)} selected)\n")

    results, width = [], len(str(len(names)))
    for i, app in enumerate(names, 1):
        prefix = f"  [{i:>{width}}/{len(names)}] {app}"
        if not args.force and os.path.isdir(os.path.join(args.out, app)):
            print(f"{prefix} ... skipped (exists)")
            results.append({"app": app, "status": "skipped"})
            continue
        print(f"{prefix} ... ", end="", flush=True)
        status, note = export_one(acs, app, args)
        print(status + (f" ({note})" if note else ""))
        results.append({"app": app, "status": status, "note": note,
                        "version": by_lower[app.lower()].get("version", "")})

    counts = {s: sum(r["status"] == s for r in results) for s in ("ok", "skipped", "failed")}
    with open(os.path.join(args.out, RESULTS_FILE), "w", encoding="utf-8") as f:
        json.dump({"acs_base": base, "exported_at": datetime.now().isoformat(timespec="seconds"),
                   "counts": counts, "apps": results}, f, indent=2)

    print(f"\n{counts['ok']} ok, {counts['skipped']} skipped, {counts['failed']} failed"
          f"  -> {os.path.join(args.out, RESULTS_FILE)}")
    for r in results:
        if r["status"] == "failed":
            print(f"  FAILED {r['app']}: {r['note']}")
    sys.exit(1 if counts["failed"] else 0)


if __name__ == "__main__":
    main()
