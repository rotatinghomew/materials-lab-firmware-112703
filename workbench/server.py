"""放行工作台 HTTP 入口（标准库，无第三方依赖）。

路由：
  GET  /                 工作台单页
  GET  /static/<file>    静态资源
  GET  /api/state?at=    全部节点×包的可执行状态与依据链
  GET  /api/case?node=&image=&at=   单台逐依据复查
  GET  /api/events       来源事实 + 工作台日志的合并事件流
  GET  /api/journal      工作台追加日志（JSON Lines 内容的 JSON 数组）
  POST /api/apply        办理动作：{kind, actor, facts, at?}
"""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from .service import WorkbenchError, WorkbenchService

ROOT = Path(__file__).resolve().parent.parent
STATIC = Path(__file__).resolve().parent / "static"

_CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
}


def build_service(journal_path: Path | None = None) -> WorkbenchService:
    return WorkbenchService(ROOT, journal_path or (ROOT / "workbench_state" / "journal.jsonl"))


class WorkbenchHandler(BaseHTTPRequestHandler):
    service: WorkbenchService = None  # 由 make_server 注入

    def _send_json(self, payload, status: int = 200):
        blob = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(blob)))
        self.end_headers()
        self.wfile.write(blob)

    def _send_static(self, name: str):
        path = (STATIC / name).resolve()
        if STATIC not in path.parents or not path.is_file():
            self.send_error(404)
            return
        blob = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", _CONTENT_TYPES.get(path.suffix, "application/octet-stream"))
        self.send_header("Content-Length", str(len(blob)))
        self.end_headers()
        self.wfile.write(blob)

    def do_GET(self):
        url = urlsplit(self.path)
        query = parse_qs(url.query)
        try:
            at = int(query["at"][0]) if "at" in query else None
            if url.path == "/":
                self._send_static("index.html")
            elif url.path.startswith("/static/"):
                self._send_static(url.path.removeprefix("/static/"))
            elif url.path == "/api/state":
                self._send_json(self.service.view_dict(at))
            elif url.path == "/api/case":
                case = self.service.case(query["node"][0], query["image"][0], at)
                self._send_json(self.service._case_dict(case))
            elif url.path == "/api/events":
                events = self.service.events()
                self._send_json([
                    {"seq": e.seq, "at": e.at, "kind": e.kind, "actor": e.actor,
                     "facts": e.facts, "origin": e.origin} for e in events])
            elif url.path == "/api/journal":
                self._send_json(self.service.journal_lines())
            else:
                self.send_error(404)
        except (KeyError, ValueError) as exc:
            self._send_json({"error": f"请求参数无效: {exc}"}, status=400)
        except WorkbenchError as exc:
            self._send_json({"error": str(exc)}, status=409)

    def do_POST(self):
        url = urlsplit(self.path)
        if url.path != "/api/apply":
            self.send_error(404)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            body = json.loads(self.rfile.read(length) or b"{}")
            kind = body["kind"]
            actor = body["actor"]
            facts = body.get("facts") or {}
            at = body.get("at")
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            self._send_json({"error": f"请求体无效: {exc}"}, status=400)
            return
        try:
            result = self.service.apply(kind, actor, facts, at)
        except WorkbenchError as exc:
            self._send_json({"error": str(exc)}, status=409)
            return
        self._send_json(result, status=201)

    def log_message(self, fmt, *args):  # 控制台保持简洁
        pass


def make_server(host: str, port: int, journal_path: Path | None = None,
                source_through: int | None = None):
    service = build_service(journal_path)
    service.source_through = source_through
    handler = type("BoundHandler", (WorkbenchHandler,), {"service": service})
    return ThreadingHTTPServer((host, port), handler), service


def main():
    import argparse

    parser = argparse.ArgumentParser(description="固件上线双边放行工作台（本地合成）")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8766)
    parser.add_argument("--journal", type=Path, default=None,
                        help="工作台追加日志路径，默认 workbench_state/journal.jsonl")
    parser.add_argument("--source-through", type=int, default=None,
                        help="只纳入不晚于该时刻的来源事件，用于历史演练")
    args = parser.parse_args()
    server, service = make_server(args.host, args.port, args.journal,
                                  args.source_through)
    print(f"放行工作台: http://{args.host}:{args.port}/  日志: {service.journal.path}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
