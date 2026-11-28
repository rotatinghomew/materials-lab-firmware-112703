"""工作台日志：设施方在演练中的全部动作按时间追加保存。

来源资料（replay 端 / data 目录）只读，设施方的批准、暂停、计划与节点回执
一律写入这个 JSON Lines 日志，保证身份—批准—执行链可以完整回放。
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

# 来源时间线中的中文事件名 -> 工作台规范事件名
SOURCE_KIND_ALIASES = {
    "提交": "vendor_submit",
    "批准": "facility_approve",
    "安装接受": "receipt",
    "开始": "receipt",
    "设备回报": "receipt",
    "节点暂停": "suspend",
    "岗位调离": "subject_disable",
    "信任冻结": "trust_freeze",
    "发布另一份": "vendor_submit",
}

# 工作台可追加的全部事件名
JOURNAL_KINDS = frozenset({
    "identity_enable",
    "identity_disable",
    "trust_freeze",
    "trust_thaw",
    "facility_approve",
    "suspend",
    "resume",
    "install_plan",
    "install_plan_revoke",
    "receipt",
    "writeoff",
    "note",
})

RECEIPT_RESULTS = frozenset({"accept", "start", "finish", "rollback"})


@dataclass(frozen=True)
class StoredEvent:
    seq: int
    at: int
    kind: str
    actor: str
    facts: dict
    origin: str  # source | journal


class Journal:
    def __init__(self, path: Path):
        self.path = Path(path)

    def read_journal(self) -> list[dict]:
        if not self.path.is_file():
            return []
        rows = []
        for line_no, line in enumerate(self.path.read_text(encoding="utf-8").splitlines(), 1):
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            for required in ("at", "kind", "actor", "facts"):
                if required not in row:
                    raise ValueError(f"日志第 {line_no} 行缺少字段 {required}")
            rows.append(row)
        return rows

    def append(self, at: int, kind: str, actor: str, facts: dict) -> dict:
        if kind not in JOURNAL_KINDS:
            raise ValueError(f"未知工作台事件: {kind}")
        if kind == "receipt" and facts.get("result") not in RECEIPT_RESULTS:
            raise ValueError("receipt 的 result 必须是 accept/start/finish/rollback")
        event = {"at": int(at), "kind": kind, "actor": actor, "facts": dict(facts)}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n")
        return event

    def next_at(self, source_events: list[dict]) -> int:
        latest = 0
        for event in source_events:
            latest = max(latest, int(event["at"]))
        for event in self.read_journal():
            latest = max(latest, int(event["at"]))
        return latest + 1


def normalize_source_event(event: dict) -> dict:
    """把来源时间线的中文记录转成规范事件，保留原始字段。"""
    kind = SOURCE_KIND_ALIASES.get(event["kind"], event["kind"])
    facts = dict(event["facts"])
    # 来源的设备回报用 result=finish；安装接受/开始转成规范回执
    if event["kind"] == "安装接受":
        facts.setdefault("result", "accept")
    elif event["kind"] == "开始":
        facts.setdefault("result", "start")
    return {"at": event["at"], "kind": kind, "actor": event["actor"], "facts": facts}


def load_events(bundle, journal: Journal, source_through: int | None = None) -> list[StoredEvent]:
    """合并来源事实与工作台日志，按 (时间, 序号) 排序。

    source_through 用于在历史时刻继续办理：只纳入不晚于该时刻的来源事件，
    工作台日志不受影响（日志时刻本身必须晚于被截断后的时钟）。
    """
    merged: list[StoredEvent] = []
    for raw in bundle.timeline:
        if source_through is not None and raw["at"] > source_through:
            continue
        norm = normalize_source_event(raw)
        merged.append(StoredEvent(len(merged), norm["at"], norm["kind"],
                                  norm["actor"], norm["facts"], "source"))
    for raw in journal.read_journal():
        merged.append(StoredEvent(len(merged), raw["at"], raw["kind"],
                                  raw["actor"], raw["facts"], "journal"))
    merged.sort(key=lambda e: (e.at, e.seq))
    return [StoredEvent(i, e.at, e.kind, e.actor, e.facts, e.origin)
            for i, e in enumerate(merged)]
