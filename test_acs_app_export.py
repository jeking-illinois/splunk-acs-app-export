#!/usr/bin/env python3
"""Offline tests: a fake ACS on localhost. Run: python -m unittest -v"""

import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import threading
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "acs_app_export.py")

# 205 apps -> three pages, the last one short.
APPS = [f"app_{i:03d}" for i in range(205)]
SEARCH_ONLY = "app_001"   # refuses default=true, like the real search app
EVIL = "app_002"          # archive tries to escape the output dir
BROKEN = "app_003"        # returns 500 forever


def tgz(entries):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, body in entries.items():
            info = tarfile.TarInfo(name)
            info.size = len(body)
            tf.addfile(info, io.BytesIO(body))
    return buf.getvalue()


def results(out):
    with open(os.path.join(out, "_export_results.json"), encoding="utf-8") as f:
        return json.load(f)


class FakeAcs(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def send(self, code, body, ctype="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.end_headers()
        self.wfile.write(body if isinstance(body, bytes) else body.encode())

    def do_GET(self):
        if self.headers.get("Authorization") != "Bearer t0k":
            return self.send(401, '{"code":"401"}')
        url = urllib.parse.urlparse(self.path)
        q = dict(urllib.parse.parse_qsl(url.query))
        if url.path.endswith("/apps/victoria"):
            count, offset = int(q["count"]), int(q["offset"])
            if count > 100:
                return self.send(400, '{"message":"invalid count"}')
            page = [{"name": n, "version": "1.0", "label": n} for n in APPS[offset:offset + count]]
            return self.send(200, json.dumps({"apps": page}))
        app = url.path.rsplit("/", 1)[-1]
        if app == BROKEN:
            return self.send(500, '{"message":"boom"}')
        if app == SEARCH_ONLY and q.get("default") == "true":
            return self.send(400, '{"code":"SEARCH_APPS_ONLY_LOCAL_AND_USERS_CONFIGS_ALLOWED"}')
        if app == EVIL:
            return self.send(200, tgz({"../escaped.txt": b"x"}), "application/gzip")
        files = {f"{app}/local/app.conf": b"[ui]\nlabel = x\n"}
        if q.get("default") == "true":
            files[f"{app}/default/app.conf"] = b"[launcher]\n"
        return self.send(200, tgz(files), "application/gzip")


class ExportTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = HTTPServer(("127.0.0.1", 0), FakeAcs)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.srv.server_port}/acme/adminconfig/v2"

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def run_cli(self, *args, token="t0k"):
        env = dict(os.environ, SPLUNK_TOKEN=token)
        return subprocess.run([sys.executable, SCRIPT, "--acs-base", self.base,
                               "--retries", "1", *args],
                              capture_output=True, text=True, env=env)

    def test_full_export(self):
        with tempfile.TemporaryDirectory() as out:
            r = self.run_cli("--out", out)
            self.assertEqual(r.returncode, 1, r.stdout + r.stderr)  # BROKEN + EVIL fail
            res = results(out)
            self.assertEqual(res["counts"], {"ok": 203, "skipped": 0, "failed": 2})
            self.assertTrue(os.path.isfile(os.path.join(out, "app_000", "default", "app.conf")))
            # search-only app retried without default/
            self.assertTrue(os.path.isfile(os.path.join(out, SEARCH_ONLY, "local", "app.conf")))
            self.assertFalse(os.path.exists(os.path.join(out, SEARCH_ONLY, "default")))
            # traversal refused, nothing written outside, no partial folder left
            self.assertFalse(os.path.exists(os.path.join(os.path.dirname(out), "escaped.txt")))
            self.assertFalse(os.path.exists(os.path.join(out, EVIL)))
            self.assertFalse([d for d in os.listdir(out) if d.startswith(".")])

            # second run skips what is already there and retries only failures
            r = self.run_cli("--out", out)
            res = results(out)
            self.assertEqual(res["counts"], {"ok": 0, "skipped": 203, "failed": 2})

    def test_single_app_case_insensitive(self):
        with tempfile.TemporaryDirectory() as out:
            r = self.run_cli("--out", out, "--app", "APP_010", "--keep-archive")
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertEqual(sorted(os.listdir(out)),
                             ["_export_results.json", "app_010", "app_010.tgz"])

    def test_filters_and_list(self):
        r = self.run_cli("--list", "--include", "app_1*", "--exclude", "app_19*")
        self.assertEqual(r.returncode, 0, r.stderr)
        listed = [l.split()[0] for l in r.stdout.splitlines() if l.startswith("  app_")]
        self.assertEqual(len(listed), 90)

    def test_unknown_app_and_bad_token(self):
        self.assertIn("not on stack", self.run_cli("--app", "nope").stderr)
        self.assertIn("HTTP 401", self.run_cli("--list", token="bad").stderr)


if __name__ == "__main__":
    unittest.main()
