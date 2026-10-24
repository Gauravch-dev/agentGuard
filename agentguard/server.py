"""Loopback-only authenticated control plane for the local policy workbench."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hmac
from pathlib import Path
import re
from urllib.parse import urlsplit

from .schema import ValidationError, canonical, strict_json
from .store import IntegrityError, local_secret
from .workbench import Workbench

ASSETS = Path(__file__).resolve().parent.parent / "dashboard"


def make_server(workbench: Workbench, port=8765):
    token = local_secret(workbench.store.root / "ui-access.key").hex()

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def setup(self):
            super().setup()
            self.connection.settimeout(5)

        def log_message(self, format, *args):
            # Request paths/tokens are not copied into ad hoc logs.
            pass

        def reply(self, status, body, content_type="application/json"):
            raw = body if isinstance(body, bytes) else canonical(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(raw)
            self.close_connection = True

        def context_valid(self):
            host = self.headers.get("Host", "")
            expected = f"127.0.0.1:{self.server.server_port}"
            if host != expected:
                return False
            origin = self.headers.get("Origin")
            return origin is None or origin == "http://" + expected

        def authenticated(self):
            supplied = self.headers.get("Authorization", "")
            return hmac.compare_digest(supplied.encode(), ("Bearer " + token).encode())

        def route(self, method):
            if not self.context_valid():
                self.reply(403, {"error": "invalid_host_or_origin"})
                return
            path = urlsplit(self.path).path
            assets = {"/": ("index.html", "text/html; charset=utf-8"), "/app.js": ("app.js", "text/javascript; charset=utf-8"), "/style.css": ("style.css", "text/css; charset=utf-8")}
            if method == "GET" and path in assets:
                filename, mime = assets[path]
                self.reply(200, (ASSETS / filename).read_bytes(), mime)
                return
            if not self.authenticated():
                self.reply(401, {"error": "local_access_key_required"})
                return
            try:
                body = None
                if method == "POST":
                    length = self.headers.get("Content-Length", "")
                    if self.headers.get("Transfer-Encoding") or not re.fullmatch(r"[0-9]{1,6}", length) or int(length) > 32_768:
                        self.reply(413, {"error": "bounded_content_length_required"})
                        return
                    if self.headers.get("Content-Type", "").split(";")[0] != "application/json":
                        self.reply(415, {"error": "application_json_required"})
                        return
                    raw = self.rfile.read(int(length))
                    if len(raw) != int(length):
                        raise ValidationError("incomplete body")
                    body = strict_json(raw)
                if method == "GET" and path == "/api/v1/health":
                    self.reply(200, {"application_ready": True, "protected_execution_ready": False})
                elif method == "GET" and path == "/api/v1/snapshot":
                    self.reply(200, workbench.snapshot())
                elif method == "POST" and path == "/api/v1/tasks":
                    self.reply(201, workbench.authority.approve(body))
                elif match := re.fullmatch(r"/api/v1/tasks/([A-Za-z0-9_-]+)(?:/(launch|harness|events|result))?", path):
                    task_id, action = match.groups()
                    if method == "POST" and action == "launch":
                        # There is deliberately no switch to silently run a harness here.
                        workbench.authority.load(task_id)
                        self.reply(409, {"error": "security_readiness_failed", "capsule_started": False,
                                         "reasons": ["Linux runtime/sensor/broker integration is not validated"],
                                         "policy_harness_route": f"/api/v1/tasks/{task_id}/harness"})
                    elif method == "POST" and action == "harness":
                        if body != {}:
                            raise ValidationError("harness accepts no agent code or runtime options")
                        self.reply(200, workbench.harness(task_id))
                    elif method == "GET" and action == "events":
                        workbench.authority.load(task_id, check_expiry=False)
                        workbench.store.verify()
                        self.reply(200, workbench.store.events(task_id=task_id))
                    elif method == "GET" and action == "result":
                        runs = workbench.store.runs(task_id)
                        if not runs:
                            raise KeyError("no runs")
                        self.reply(200, workbench.result(runs[0]["capsule_id"]))
                    elif method == "GET" and action is None:
                        self.reply(200, workbench.authority.load(task_id, check_expiry=False))
                    else:
                        self.reply(405, {"error": "method_not_allowed"})
                elif method == "GET" and (match := re.fullmatch(r"/api/v1/runs/(harness-[a-f0-9]{32})", path)):
                    self.reply(200, workbench.result(match.group(1)))
                else:
                    self.reply(404, {"error": "not_found"})
            except IntegrityError:
                self.reply(409, {"error": "evidence_or_contract_integrity_failure", "classification": "Unverified"})
            except (ValidationError, ValueError) as exc:
                self.reply(400, {"error": str(exc)[:1024]})
            except KeyError:
                self.reply(404, {"error": "not_found"})
            except Exception:
                self.reply(500, {"error": "trusted_service_failure", "classification": "Unverified"})

        def do_GET(self):
            self.route("GET")

        def do_POST(self):
            self.route("POST")

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.daemon_threads = True
    return server, token
