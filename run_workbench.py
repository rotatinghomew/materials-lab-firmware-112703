#!/usr/bin/env python3
"""命令行入口：启动工作台或在终端直接打印逐台状态。

用法：
  python3 run_workbench.py serve [--port 8766] [--journal PATH]
  python3 run_workbench.py status [--at N] [--node N11 --image IMG-9B]
  python3 run_workbench.py apply --kind facility_approve --actor F-12 \
      --facts '{"image":"IMG-9C","group":"G2"}'
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from workbench.server import make_server  # noqa: E402
from workbench.service import WorkbenchError, WorkbenchService  # noqa: E402

ROOT = Path(__file__).resolve().parent
DEFAULT_JOURNAL = ROOT / "workbench_state" / "journal.jsonl"


def build_service(path: Path | None) -> WorkbenchService:
    return WorkbenchService(ROOT, path or DEFAULT_JOURNAL)


def print_status(service: WorkbenchService, at: int | None,
                 node: str | None, image: str | None) -> None:
    view = service.view(at)
    print(f"演练时刻 t={view.at}")
    for case in view.cases:
        if node and case.node_id != node:
            continue
        if image and case.image != image:
            continue
        print(f"\n== {case.node_id}（{case.facts['group']}） × {case.image} "
              f"v{case.facts['version']} {case.facts['basename']} ==")
        print(f"  阶段={case.phase} 状态=【{case.status}】 可办={list(case.allowed_actions)}")
        for basis in case.bases:
            mark = {"通过": "✓", "失效": "✗", "不适用": "·"}[basis.status.value]
            line = f"  [{mark}] {basis.side:8s} {basis.title}: {basis.detail}"
            print(line)
            if basis.status.value == "失效":
                print(f"        处置 → {basis.remedy}")
        if case.remediation:
            print("  综合处置:")
            for item in case.remediation:
                print(f"    - {item}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="固件上线双边放行工作台")
    sub = parser.add_subparsers(dest="cmd", required=True)

    serve = sub.add_parser("serve", help="启动 HTTP 工作台")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8766)
    serve.add_argument("--journal", type=Path, default=None)

    status = sub.add_parser("status", help="终端打印可执行状态与依据链")
    status.add_argument("--at", type=int, default=None)
    status.add_argument("--node", default=None)
    status.add_argument("--image", default=None)
    status.add_argument("--journal", type=Path, default=None)

    apply_p = sub.add_parser("apply", help="办理一个动作并写入工作台日志")
    apply_p.add_argument("--kind", required=True)
    apply_p.add_argument("--actor", required=True)
    apply_p.add_argument("--facts", required=True, help="JSON 对象字符串")
    apply_p.add_argument("--at", type=int, default=None)
    apply_p.add_argument("--journal", type=Path, default=None)

    args = parser.parse_args(argv)
    if args.cmd == "serve":
        server, service = make_server(args.host, args.port, args.journal)
        print(f"放行工作台: http://{args.host}:{args.port}/  日志: {service.journal.path}", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()
        return 0

    service = build_service(getattr(args, "journal", None))
    if args.cmd == "status":
        print_status(service, args.at, args.node, args.image)
        return 0

    if args.cmd == "apply":
        try:
            facts = json.loads(args.facts)
            result = service.apply(args.kind, args.actor, facts, args.at)
        except (json.JSONDecodeError, WorkbenchError) as exc:
            print(f"办理被拒绝: {exc}", file=sys.stderr)
            return 2
        print(json.dumps(result["stored"], ensure_ascii=False, indent=2))
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
