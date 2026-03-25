import json
import os
import time
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATE_PATH = os.path.join(BASE_DIR, "state.json")

DEFAULT_STATE = {
    "last_scan": None,
    "last_scan_at": None,
    "selected_guest_code": None,
    "selected_guest_at": None
}

def load_state():
    if not os.path.exists(STATE_PATH):
        return DEFAULT_STATE.copy()
    with open(STATE_PATH, "r", encoding="utf-8") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            return DEFAULT_STATE.copy()
    state = DEFAULT_STATE.copy()
    state.update(data or {})
    return state

def save_state(state):
    with open(STATE_PATH, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)

class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=BASE_DIR, **kwargs)

    def end_headers(self):
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        self.send_header("Access-Control-Allow-Origin", "*")
        super().end_headers()

    def _json_response(self, data, status=200):
        raw = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        if self.path.startswith("/api/state"):
            return self._json_response(load_state())
        return super().do_GET()

    def do_POST(self):
        if self.path not in ("/api/scan", "/api/select", "/api/reset"):
            self.send_error(404)
            return

        if self.path == "/api/reset":
            save_state(DEFAULT_STATE.copy())
            return self._json_response({"ok": True})

        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8") if length else "{}"
        try:
            data = json.loads(body or "{}")
        except json.JSONDecodeError:
            return self._json_response({"error": "invalid_json"}, 400)

        state = load_state()
        now = int(time.time() * 1000)

        if self.path == "/api/scan":
            code = str(data.get("code", "")).strip()
            if not code:
                return self._json_response({"error": "missing_code"}, 400)
            if len(code) < 3:
                code = code.zfill(3)
            state["last_scan"] = code
            state["last_scan_at"] = now
            save_state(state)
            return self._json_response({"ok": True, "last_scan": code, "last_scan_at": now})

        if self.path == "/api/select":
            code = str(data.get("code", "")).strip()
            if not code:
                return self._json_response({"error": "missing_code"}, 400)
            if len(code) < 3:
                code = code.zfill(3)
            state["selected_guest_code"] = code
            state["selected_guest_at"] = now
            save_state(state)
            return self._json_response({"ok": True, "selected_guest_code": code, "selected_guest_at": now})

if __name__ == "__main__":
    save_state(load_state())
    port = int(os.environ.get("PORT", 8000))
    print(f"Server running on http://0.0.0.0:{port}")
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
