#!/usr/bin/env python3
"""Reproducible, OFFLINE pilot lab. No remote targets, no exploitation, no credentials.
This tests the control plane and a canary access path, not a real penetration test.
"""
from __future__ import annotations

import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import secrets
import threading
import time
from urllib import error, request

PHASES = (
    "mandate", "preflight", "recon", "assessment",
    "validation", "access", "impact", "report",
)

class LabHandler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        return

    def send_json(self, status: int, payload: dict):
        body = json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            self.send_json(200, {"service": "nandutest-isolated-lab", "ok": True})
        elif self.path == "/lab/spec":
            self.send_json(200, {"routes": ["/health", "/lab/spec", "/lab/proof"],
                                 "auth": "X-Lab-Authorization", "scope": "loopback"})
        elif self.path == "/lab/proof":
            if self.headers.get("X-Lab-Authorization") != self.server.lab_token:
                self.send_json(401, {"error": "access_denied"})
            else:
                self.send_json(200, {"proof": self.server.canary, "type": "synthetic-access-only"})
        else:
            self.send_json(404, {"error": "unknown_route"})


def _fetch(root: str, path: str, *, token: str | None = None):
    headers = {"Accept": "application/json"}
    if token is not None:
        headers["X-Lab-Authorization"] = token
    req = request.Request(root + path, headers=headers)
    try:
        with request.urlopen(req, timeout=2) as response:
            return response.status, json.load(response)
    except error.HTTPError as exc:
        return exc.code, json.load(exc)


def run_lab(authorized: bool) -> dict:
    """An actual access canary is checked only on an ephemeral 127.0.0.1 server."""
    result = {
        "mode": "isolated-loopback-lab",
        "network_scope": "127.0.0.1:ephemeral",
        "real_target_tested": False,
        "real_access_demonstrated": False,
        "continuous_pentest_verified": False,
        "human_reviewed_memory": False,
        "completed": False,
        "phases": [],
        "duration_ms": 0,
    }
    begun = time.monotonic()

    def stage(name, condition, evidence):
        result["phases"].append({"id": name, "state": "passed" if condition else "blocked",
                                 "evidence": evidence})
        if not condition:
            raise RuntimeError(f"Lab phase {name} failed")

    try:
        stage("mandate", authorized, "Operator explicitly supplied --authorize-lab")
        token = secrets.token_urlsafe(24)
        canary = "lab-proof-" + secrets.token_hex(12)
        with ThreadingHTTPServer(("127.0.0.1", 0), LabHandler) as server:
            server.lab_token, server.canary = token, canary
            host, port = server.server_address
            stage("preflight", host == "127.0.0.1" and port > 0,
                  "Ephemeral loopback-only HTTP server; no public listeners")
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                root = f"http://127.0.0.1:{port}"
                status, health = _fetch(root, "/health")
                _, spec = _fetch(root, "/lab/spec")
                stage("recon", status == 200 and health.get("ok") and
                      "/lab/proof" in spec.get("routes", []),
                      "Synthetic service inventory and API spec retrieved")
                stage("assessment", spec.get("auth") == "X-Lab-Authorization",
                      "Authentication required by synthetic API contract")
                unauthorized_status, unauthorized = _fetch(root, "/lab/proof")
                invalid_status, _ = _fetch(root, "/lab/proof", token="invalid-lab-token")
                stage("validation", unauthorized_status == 401 and invalid_status == 401 and
                      unauthorized.get("error") == "access_denied",
                      "Unauthorized access denied on both negative controls")
                allowed_status, allowed = _fetch(root, "/lab/proof", token=token)
                stage("access", allowed_status == 200 and allowed.get("proof") == canary,
                      "Valid ephemeral LAB credential obtained synthetic-access canary")
                proof_hash = hashlib.sha256(canary.encode()).hexdigest()
                stage("impact", len(proof_hash) == 64 and allowed.get("type") == "synthetic-access-only",
                      "Read-only marker hashed; no real records accessed or exfiltrated")
                stage("report", len(result["phases"]) == 7,
                      "Evidence of all preceding lab phases included in this report")
                result["completed"] = True
                result["synthetic_access_verified"] = True
                result["canary_sha256"] = proof_hash
            finally:
                server.shutdown()
                thread.join(timeout=3)
    except (RuntimeError, OSError, ValueError) as exc:
        result["error_type"] = type(exc).__name__
        result["synthetic_access_verified"] = False
    finally:
        result["duration_ms"] = round((time.monotonic() - begun) * 1000)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--authorize-lab", action="store_true",
                        help="Explicitly authorize the loopback-only canary lab")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = run_lab(args.authorize_lab)
    output = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output)
    print(output, end="")
    return 0 if result["completed"] else 3


if __name__ == "__main__":
    raise SystemExit(main())
