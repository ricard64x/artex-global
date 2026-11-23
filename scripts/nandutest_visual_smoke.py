#!/usr/bin/env python3
"""Non-invasive UI validation against the deployed Ñandutest frontend.

All /api/* browser traffic is intercepted with synthetic fixture responses.
No actual admin credentials, real tasks or pilot authorizations are used.
The only live API checks are unauthenticated HTTP responses.
"""
import base64
import json
import os
from pathlib import Path
import urllib.error
import urllib.request
from urllib.parse import urlparse

from playwright.sync_api import sync_playwright

BASE = "https://artex-global-py.fly.dev"
TASK_ID = "900090"
OUT = Path("artifacts/nandutest-visual")
OUT.mkdir(parents=True, exist_ok=True)
NEXT_CHECK = "2026-11-25T14:00:00Z"
EXPIRES = "2026-11-26T14:00:00Z"


def live_probes():
    for path, method, expected in [
        ("/api/health", "GET", 200),
        ("/api/runtime/autopilot", "GET", 401),
        ("/api/tasks/" + TASK_ID + "/pilot", "GET", 401),
        ("/api/tasks/" + TASK_ID + "/pilot/authorize", "POST", 401),
        ("/api/users", "GET", 401),
    ]:
        request = urllib.request.Request(BASE + path, method=method)
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                status, content = response.status, response.read(4096)
        except urllib.error.HTTPError as err:
            status, content = err.code, err.read(4096)
        assert status == expected, f"{path}: HTTP {status}, expected {expected}"
        if path == "/api/health":
            assert json.loads(content).get("version") == "nandutest-pilot"
        print("LIVE", method, path, status)


def token_for(role):
    payload = {"sub": "ARTEX" if role == "admin" else "qa-auditor", "role": "superadmin" if role == "admin" else "auditor"}
    enc = lambda x: base64.urlsafe_b64encode(json.dumps(x).encode()).decode().rstrip("=")
    return enc({"alg": "none", "typ": "JWT"}) + "." + enc(payload) + ".qa-fixture"


def run_ui(browser, role, width, height, mobile=False):
    authorization_requests = []
    state = {
        "task_id": int(TASK_ID),
        "pilot_enabled": False,
        "automation_enabled": True,
        "approval": None,
        "scope_error": "",
        "scoped_domains": ["qa.example.org"],
        "mode": "passive_https_only",
        "phases": [],
        "lab": None,
        "history": [],
        "metrics": {
            "tool_results": 0, "tool_errors": 0, "findings": 0,
            "confirmed_findings": 0, "human_reviewed_memory": 0,
            "passive_checks_30d": 0, "passive_ok_30d": 0,
            "status_changes_30d": 0, "local_llm_ok": 0,
            "local_llm_error": 0, "external_llm_ok": 0, "external_llm_error": 0,
        },
    }
    browser_context = browser.new_context(
        viewport={"width": width, "height": height},
        device_scale_factor=1,
        is_mobile=mobile,
        locale="es-PY",
    )
    fake_jwt = token_for(role)
    browser_context.add_cookies([{"name": "artex_token", "value": fake_jwt, "url": BASE}])
    browser_context.add_init_script("localStorage.setItem('artex_token', " + json.dumps(fake_jwt) + ");")

    def mocked_api(route):
        req = route.request
        path = urlparse(req.url).path
        method = req.method
        response = {"items": [], "sessions": [], "profiles": [], "tasks": [], "categories": [], "rules": [], "total": 0}
        if path == "/api/tasks/" + TASK_ID:
            response = {
                "id": TASK_ID, "name": "Revisión QA visual · sin escaneos",
                "description": "Revisión de demostración", "goal": "Validar el botón sin tocar objetivos reales",
                "status": "done", "created_at": "2026-11-23T20:00:00Z",
                "paused": True, "coverage_enabled": False,
            }
        elif path == "/api/tasks/" + TASK_ID + "/pilot":
            response = state
        elif path == "/api/tasks/" + TASK_ID + "/pilot/authorize" and method == "POST":
            request = json.loads(req.post_data or "{}")
            authorization_requests.append(request)
            assert request.get("domain") == "qa.example.org"
            assert request.get("mode") == "passive_https"
            assert len(request.get("ticket", "")) >= 8
            state["pilot_enabled"] = True
            state["approval"] = {
                "task_id": int(TASK_ID), "domain": request["domain"], "mode": "passive_https",
                "ticket": request["ticket"], "enabled": True,
                "interval_minutes": request["interval_minutes"],
                "approved_at": "2026-11-24T13:00:00Z",
                "expires_at": EXPIRES, "next_check": NEXT_CHECK,
                "last_check": None, "last_http": None, "last_latency_ms": None,
                "last_error": None, "checks": 0, "failure_streak": 0,
            }
            response = {"ok": True, "message": "QA mock"}
        elif path == "/api/tasks/" + TASK_ID + "/pilot/revoke" and method == "POST":
            state["pilot_enabled"] = False
            if state["approval"]:
                state["approval"]["enabled"] = False
            response = {"ok": True, "enabled": False}
        elif path == "/api/stats":
            response = {"active_task": None, "engine_mode": "idle"}
        elif path == "/api/llm/profiles":
            response = {"profiles": []}
        elif path.startswith("/api/intercept/"):
            response = {"items": []}
        route.fulfill(status=200, content_type="application/json", body=json.dumps(response))

    # Intercept every browser API request before anything can reach the real backend.
    browser_context.route("**/api/**", mocked_api)
    page = browser_context.new_page()
    js_errors = []
    page.on("pageerror", lambda error: js_errors.append(str(error)))
    target = BASE + "/function/tasks/detail?id=" + TASK_ID
    page.goto(target, wait_until="domcontentloaded", timeout=45000)
    page.wait_for_timeout(1800)

    if role == "admin":
        header = page.locator('header section[aria-label="Piloto automático"]')
        header.wait_for(state="visible", timeout=20000)
        assert "Desactivado" in header.inner_text(), "Inactive state not shown"
        button = header.get_by_role("button", name="Activar piloto automático")
        button.wait_for(state="visible", timeout=15000)
        bounding = button.bounding_box()
        assert bounding and bounding["x"] >= -1 and bounding["x"] + bounding["width"] <= width + 2, (
            "Button clipped outside viewport", bounding, width
        )
        page.screenshot(path=str(OUT / (("mobile" if mobile else "desktop") + "-inactive.png")), full_page=False)

        button.click()
        page.get_by_text("Dominio exacto aprobado").first.wait_for(state="visible", timeout=10000)
        page.get_by_label("Ticket o referencia de autorización").fill("QA-UI-2026-01123")
        page.locator("#pilot-approval-ticket").press("Tab")
        activate = page.get_by_role("button", name="Activar piloto automático")
        activate.last.click()
        page.wait_for_function(
            "() => document.querySelector('header section[aria-label=\"Piloto automático\"]')?.textContent?.includes('Activo')",
            timeout=15000,
        )
        assert authorization_requests, "Frontend did not submit approval request to the mock"
        assert "Próxima comprobación" in header.inner_text()
        page.screenshot(path=str(OUT / (("mobile" if mobile else "desktop") + "-active.png")), full_page=False)
        print("UI", role, "mobile" if mobile else "desktop", "button_visible=true", "open_tab=true", "state_active=true", "next_check=true", "request_mocked=true")

        # Stop remains an explicit user action and is also intercepted.
        page.get_by_role("button", name="Detener piloto").click()
        page.wait_for_function(
            "() => document.querySelector('header section[aria-label=\"Piloto automático\"]')?.textContent?.includes('Desactivado')",
            timeout=15000,
        )
        print("UI", role, "revoke_mocked=true")
    else:
        assert page.locator('header section[aria-label="Piloto automático"]').count() == 0
        page.get_by_role("tab", name="Piloto automático").click()
        page.get_by_text("Solo el administrador puede activar y gestionar el piloto automático.").wait_for(
            state="visible", timeout=10000
        )
        print("UI", role, "header_hidden=true", "authorization_ui_hidden=true")

    if js_errors:
        print("JS_ERRORS", json.dumps(js_errors[:6], ensure_ascii=False))
    browser_context.close()


if __name__ == "__main__":
    live_probes()
    with sync_playwright() as playwright:
        binary = os.environ.get("CHROME_BIN")
        opts = {"headless": True, "args": ["--no-sandbox", "--disable-dev-shm-usage"]}
        if binary:
            opts["executable_path"] = binary
        browser = playwright.chromium.launch(**opts)
        try:
            run_ui(browser, "admin", 1440, 900)
            run_ui(browser, "admin", 390, 844, mobile=True)
            run_ui(browser, "auditor", 1440, 900)
        finally:
            browser.close()
    print("VISUAL_SMOKE_PASSED")
