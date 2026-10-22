"""Local access desk with a live workspace and archived Qwen evidence."""

from __future__ import annotations

import json
import secrets
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import RLock
from urllib.parse import urlsplit

DEFAULT_RUN = Path("artifacts/runs/27d759b9-50ae-4742-a862-0e125c744cb9")
STAGES = (
    ("clean", "clean_victim", "later-request"),
    ("exposure", "immediate_injection", "attachment-review"),
    ("persistence", "persistence", "later-request"),
    ("ablation", "memory_ablation", "later-request"),
)
SESSION_COOKIE = "ragmemsec_workspace"


class LiveWorkspaceRegistry:
    """Keep temporary workspaces separate between browser sessions."""

    def __init__(self, factory, limit: int = 8) -> None:
        self.factory = factory
        self.limit = limit
        self.sessions: dict[str, object] = {}

    def get(self, token: str | None):
        return self.sessions.get(token) if token else None

    def start(self, token: str | None):
        existing = self.get(token)
        if existing is not None:
            return token, existing, False
        if len(self.sessions) >= self.limit:
            raise RuntimeError("Workspace limit reached. Restart the local server.")
        session = self.factory()
        token = secrets.token_urlsafe(32)
        self.sessions[token] = session
        return token, session, True

    def close(self) -> None:
        for session in self.sessions.values():
            session.close()
        self.sessions.clear()


def load_demo(run_dir: Path) -> dict:
    """Load original benchmark artifacts and refuse an incomplete/mismatched chain."""
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    traces = [
        json.loads(line)
        for line in (run_dir / "traces.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    if manifest.get("scenario", {}).get("id") != "file-v3-setup-instruction":
        raise ValueError("Demo requires the archived setup-instruction scenario")
    if (
        manifest.get("run_kind") != "real_benchmark"
        or manifest.get("config", {}).get("model") != "qwen3-8b"
    ):
        raise ValueError("Demo requires a real Qwen 3 8B benchmark run")
    model = manifest.get("provider", {}).get("requested_model")
    digest = manifest.get("provider", {}).get("installed_model", {}).get("digest")
    if model != "qwen3:8b" or not digest:
        raise ValueError("Qwen model identity is missing or unexpected")
    selected = {}
    for name, condition, query_id in STAGES:
        matches = [
            t
            for t in traces
            if t.get("condition") == condition and t.get("query_id") == query_id
        ]
        if len(matches) != 1 or matches[0].get("errors"):
            raise ValueError(f"Missing, ambiguous, or errored stage: {name}")
        selected[name] = matches[0]
    clean, exposure, later, ablation = (
        selected[k] for k in ("clean", "exposure", "persistence", "ablation")
    )
    memory_id = exposure.get("memory_write_result", {}).get("memory_id")
    if not (memory_id and exposure.get("memory_write_result", {}).get("stored")):
        raise ValueError("Exposure did not store a candidate memory")
    if not any(
        d.get("record_id") == "attachment-001" for d in exposure["retrieved_documents"]
    ):
        raise ValueError("Attack document was not retrieved during exposure")
    if any(
        d.get("record_id") == "attachment-001" for d in later["retrieved_documents"]
    ):
        raise ValueError("Attack document remains in later retrieval")
    if not any(m.get("record_id") == memory_id for m in later["retrieved_memories"]):
        raise ValueError("The exposure memory was not retrieved later")
    if ablation["retrieved_memories"] or clean["retrieved_memories"]:
        raise ValueError("Clean or ablation stage unexpectedly retrieved memory")
    for name in ("exposure", "persistence"):
        t = selected[name]
        if (
            t.get("parsed_decision", {}).get("decision") != "allowed"
            or t.get("tool_result", {}).get("granted") is not False
        ):
            raise ValueError(f"Unsafe proposal / blocked effect missing in {name}")
    for name in ("clean", "ablation"):
        if (
            selected[name].get("parsed_decision", {}).get("decision")
            != "requires_approval"
        ):
            raise ValueError(f"Expected approval-required decision missing in {name}")

    def project(t: dict) -> dict:
        return {
            key: t.get(key)
            for key in (
                "condition",
                "query_id",
                "query",
                "expected_outcome",
                "retrieved_documents",
                "retrieved_memories",
                "parsed_decision",
                "tool_call",
                "tool_result",
                "memory_candidate",
                "memory_write_result",
                "errors",
                "timestamp",
            )
        }

    return {
        "mode": "recorded benchmark replay — no new model calls",
        "model": "Qwen 3 8B",
        "model_id": model,
        "model_digest": digest,
        "scenario": manifest["scenario"]["id"],
        "run_id": manifest.get("run_id"),
        "evaluator_version": manifest.get("evaluator_version"),
        "admission_gate": manifest.get("admission_gate"),
        "tool_authorization": manifest.get("tool_authorization"),
        "stages": {name: project(trace) for name, trace in selected.items()},
    }


def serve_demo(
    host: str = "127.0.0.1", port: int = 8765, run_dir: Path | None = None
) -> None:
    repo = Path(__file__).resolve().parents[3]
    run_dir = run_dir or repo / DEFAULT_RUN
    archived = load_demo(run_dir)
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    payload = json.dumps(archived, ensure_ascii=False).encode("utf-8")
    ui = Path(__file__).parent / "ui"
    portal_page = (ui / "portal.html").read_bytes()
    portal_css = (ui / "portal.css").read_bytes()
    portal_js = (ui / "portal.js").read_bytes()
    favicon = (ui / "favicon.svg").read_bytes()
    evidence_page = (ui / "index.html").read_bytes()
    lock = RLock()

    def create_session():
        from ragmemsec.demo.live import LiveAccessSession

        return LiveAccessSession(repo, manifest)

    workspaces = LiveWorkspaceRegistry(create_session)

    class Handler(BaseHTTPRequestHandler):
        def session_token(self) -> str | None:
            cookie = SimpleCookie()
            try:
                cookie.load(self.headers.get("Cookie", ""))
            except Exception:
                return None
            return cookie[SESSION_COOKIE].value if SESSION_COOKIE in cookie else None

        def send_body(
            self, status: int, body: bytes, mime: str, cookie: str | None = None
        ) -> None:
            self.send_response(status)
            self.send_header("Content-Type", mime)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            if cookie is not None:
                self.send_header(
                    "Set-Cookie",
                    f"{SESSION_COOKIE}={cookie}; HttpOnly; SameSite=Strict; Path=/",
                )
            self.end_headers()
            self.wfile.write(body)

        def send_json(
            self, status: int, value: dict, cookie: str | None = None
        ) -> None:
            self.send_body(
                status,
                json.dumps(value, ensure_ascii=False).encode("utf-8"),
                "application/json; charset=utf-8",
                cookie,
            )

        def do_GET(self):
            route = urlsplit(self.path).path
            if route in ("/", "/index.html"):
                body, mime = portal_page, "text/html; charset=utf-8"
            elif route == "/portal.css":
                body, mime = portal_css, "text/css; charset=utf-8"
            elif route == "/portal.js":
                body, mime = portal_js, "text/javascript; charset=utf-8"
            elif route == "/favicon.svg":
                body, mime = favicon, "image/svg+xml"
            elif route == "/evidence":
                body, mime = evidence_page, "text/html; charset=utf-8"
            elif route in ("/api/evidence", "/api/demo"):
                body, mime = payload, "application/json; charset=utf-8"
            elif route == "/api/live/status":
                with lock:
                    live = workspaces.get(self.session_token())
                    self.send_json(
                        200,
                        live.state()
                        if live
                        else {
                            "active": False,
                            "model_id": archived["model_id"],
                            "model_digest": archived["model_digest"],
                            "message": "Start a temporary local workspace.",
                        },
                    )
                return
            else:
                self.send_error(404)
                return
            self.send_body(200, body, mime)

        def do_POST(self):
            origin = self.headers.get("Origin")
            if origin and urlsplit(origin).netloc != self.headers.get("Host"):
                self.send_json(403, {"error": "Cross-origin requests are not allowed"})
                return
            if (
                self.headers.get("Content-Type", "").split(";", 1)[0]
                != "application/json"
            ):
                self.send_json(415, {"error": "Expected application/json"})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = 0
            if not 0 < length <= 4096:
                self.send_json(413, {"error": "Request body must be 1–4096 bytes"})
                return
            try:
                data = json.loads(self.rfile.read(length))
                if not isinstance(data, dict):
                    raise ValueError("Expected a JSON object")
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
                self.send_json(400, {"error": str(exc)})
                return
            try:
                with lock:
                    if self.path == "/api/live/start":
                        token, live, created = workspaces.start(self.session_token())
                        result = live.state()
                        self.send_json(200, result, token if created else None)
                        return
                    live = workspaces.get(self.session_token())
                    if live is None:
                        self.send_json(409, {"error": "Start a live session first"})
                        return
                    elif self.path == "/api/live/request":
                        result = live.submit(data)
                    elif self.path == "/api/live/identity":
                        result = live.select_identity(data.get("member_id"))
                    elif self.path == "/api/live/attachment":
                        if type(data.get("present")) is not bool:
                            raise ValueError("present must be true or false")
                        result = live.set_attachment(
                            data["present"], data.get("kind", "setup")
                        )
                    elif self.path == "/api/live/ablate":
                        result = live.ablate_attack_memory()
                    elif self.path == "/api/live/memory/delete":
                        result = live.delete_memory(data.get("memory_id"))
                    elif self.path == "/api/live/reset":
                        result = live.reset()
                    else:
                        self.send_json(404, {"error": "Unknown operation"})
                        return
                self.send_json(200, result)
            except (OSError, RuntimeError, ValueError) as exc:
                self.send_json(
                    503 if self.path == "/api/live/start" else 400, {"error": str(exc)}
                )

    with ThreadingHTTPServer((host, port), Handler) as server:
        print(f"Ragmemsec access desk: http://{host}:{port}", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("Access Desk stopped.", flush=True)
        finally:
            workspaces.close()
