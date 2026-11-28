"""放行工作台服务层：查询视图与办理动作的唯一入口。

所有写入动作先做身份、角色、职责分离和状态转移校验，再追加进工作台日志；
校验不通过抛 WorkbenchError（中文原因），来源事实永远不会被改写。
"""
from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from .journal import Journal, StoredEvent, load_events
from .policy import BasisStatus, Engine, WorkbenchView
from .sources import Identity, SourceBundle, load_sources

APPROVE_VENDOR_BASES = (
    "VEND_PROOF_PRESENT", "VEND_SIGNATURE", "VEND_DIGEST",
    "VEND_ATTRIBUTION", "VEND_SUBMIT",
)


class WorkbenchError(Exception):
    """办理被拒绝，message 可直接展示给值班人员。"""


class WorkbenchService:
    def __init__(self, root: Path, journal_path: Path, source_through: int | None = None):
        self.root = Path(root).resolve()
        self.bundle: SourceBundle = load_sources(self.root)
        self.journal = Journal(journal_path)
        self.engine = Engine(self.bundle)
        # 历史演练时截断来源事件；生产/最新视图保持 None
        self.source_through = source_through

    def reload(self) -> None:
        self.bundle = load_sources(self.root)
        self.engine = Engine(self.bundle)

    # ---- 事件与视图 --------------------------------------------------
    def events(self) -> list[StoredEvent]:
        return load_events(self.bundle, self.journal, self.source_through)

    def view(self, at: int | None = None) -> WorkbenchView:
        return self.engine.view(self.events(), at)

    def case(self, node_id: str, image: str, at: int | None = None):
        if node_id not in self.bundle.nodes:
            raise WorkbenchError(f"未知设备节点 {node_id}")
        if image not in self.bundle.packages:
            raise WorkbenchError(f"未知包号 {image}")
        for case in self.view(at).cases:
            if case.node_id == node_id and case.image == image:
                return case
        raise WorkbenchError(f"没有 {node_id} × {image} 的评估结果")

    # ---- 办理动作 ----------------------------------------------------
    def apply(self, kind: str, actor: str, facts: dict, at: int | None = None) -> dict:
        facts = dict(facts)
        handler = getattr(self, f"_do_{kind}", None)
        if handler is None:
            raise WorkbenchError(f"未知动作 {kind}")
        events = self.events()
        clock = max((e.at for e in events), default=0)
        if at is None:
            at = clock + 1
        elif at < clock:
            raise WorkbenchError(f"演练时钟只能前进：当前 t={clock}，不能写入 t={at}")
        handler(actor, facts, events, at)
        stored = self.journal.append(at, kind, actor, facts)
        # 只回写受影响节点×包的最新评估，避免响应体过大
        affected = [c for c in self.view(at).cases
                    if self._case_affected(c, kind, facts)]
        return {"stored": stored,
                "affected": [self._case_dict(c) for c in affected]}

    @staticmethod
    def _case_affected(case, kind: str, facts: dict) -> bool:
        if kind in ("trust_freeze", "trust_thaw", "identity_disable",
                    "identity_enable", "note"):
            return True
        if kind == "receipt":
            return case.node_id == facts.get("node")
        return case.node_id == facts.get("node") or (
            facts.get("group") and case.facts["group"] == facts["group"])

    def _do_facility_approve(self, actor, facts, events, at):
        ident = self._require_facility(actor, "审批", at)
        image = facts.get("image")
        pkg = self.bundle.packages.get(image)
        if pkg is None:
            raise WorkbenchError(f"包号 {image} 未登记，无法批准")
        if not (facts.get("group") or facts.get("node")):
            raise WorkbenchError("批准必须给出 group 或 node 范围")
        if facts.get("node") and facts["node"] not in self.bundle.nodes:
            raise WorkbenchError(f"节点 {facts['node']} 不存在")
        if facts.get("group") and not any(
                n.group == facts["group"] for n in self.bundle.nodes.values()):
            raise WorkbenchError(f"设备组 {facts['group']} 不存在")
        # 双边授权：厂商侧依据当前必须全部成立，设施侧才允许批准
        snapshot = self.engine.view(events, at)
        probes = [c for c in snapshot.cases
                  if c.image == image and (
                      not facts.get("node") or c.node_id == facts["node"])]
        if not probes:
            raise WorkbenchError("批准范围内没有可评估的设备节点")
        bad_vendor = sorted({
            b.title for probe in probes for b in probe.bases
            if b.code in APPROVE_VENDOR_BASES and b.status is BasisStatus.FAIL
        })
        if bad_vendor:
            raise WorkbenchError(
                "厂商侧依据失效，不能满足双边授权：" + "；".join(bad_vendor))
        # 职责分离：提交该版本的同一自然人不得作设施方独立批准
        submitter = self.bundle.identity("vendor", pkg.proof["subject"])
        if submitter and submitter.person == ident.person:
            raise WorkbenchError(
                f"职责分离拒绝：{actor}（自然人 {ident.person}）与厂商提交人 "
                f"{pkg.proof['subject']} 是同一自然人，不得作同一次设施批准")
        # 批准绑定包号；重复批准直接拒绝，避免用新记录掩盖旧链
        if any(e.kind == "facility_approve" and e.facts.get("image") == image
               and (e.facts.get("group") == facts.get("group")
                    or e.facts.get("node") == facts.get("node"))
               for e in events):
            raise WorkbenchError("该范围对该包号已有批准记录；变更应走暂停/恢复或重新评估")

    def _do_suspend(self, actor, facts, events, at):
        self._suspend_resume(actor, facts, at, want_suspended=True)

    def _do_resume(self, actor, facts, events, at):
        self._suspend_resume(actor, facts, at, want_suspended=False)

    def _suspend_resume(self, actor, facts, at, want_suspended: bool):
        self._require_facility(actor, "审批", at)
        node, image = self._require_node_image(facts)
        current = self.view(at).state.suspensions.get((node, image))
        if current and current.get("suspended") == want_suspended:
            raise WorkbenchError(f"{node} 对 {image} 已是{'暂停' if want_suspended else '恢复'}状态")

    def _do_install_plan(self, actor, facts, events, at):
        # 建立计划要求当班安装权限；计划同样绑定节点 + 包号
        self._require_facility(actor, "安装", at)
        node, image = self._require_node_image(facts)
        active = [p for p in self.view(at).state.plans.get((node, image), []) if p.active]
        if active:
            raise WorkbenchError(f"{node} × {image} 已存在有效安装计划")

    def _do_install_plan_revoke(self, actor, facts, events, at):
        # 管理员撤销：在册设施账号即可；撤销只作废本计划，不产生任何其它授权
        self._require_facility(actor, None, at)
        node, image = self._require_node_image(facts)
        active = [p for p in self.view(at).state.plans.get((node, image), []) if p.active]
        if not active:
            raise WorkbenchError(f"{node} × {image} 没有可撤销的有效安装计划")

    def _do_receipt(self, actor, facts, events, at):
        node, image = self._require_node_image({**facts, "node": actor})
        result = facts.get("result")
        # 实际安装人必须是在册、未离组且持安装角色的设施账号（当班权限）
        installer = facts.get("actor")
        if result == "accept" and not installer:
            raise WorkbenchError("接收回执必须给出实际安装人 facts.actor")
        if installer:
            self._require_facility(installer, "安装", at)
        case = self.case(node, image, at)
        if result == "accept":
            if "accept" not in case.allowed_actions:
                raise WorkbenchError(
                    f"{node} 当前状态「{case.status}」不允许接收；"
                    f"失效依据：{self._fail_titles(case)}")
        elif result == "start":
            if "start" not in case.allowed_actions:
                raise WorkbenchError(
                    f"{node} 当前状态「{case.status}」不允许启动；"
                    f"旧接收回执不能越过暂停/窗口/失效依据")
        elif result in ("finish", "rollback"):
            if result not in case.allowed_actions:
                raise WorkbenchError(
                    f"{node} 当前状态「{case.status}」不允许 {result}；"
                    f"仅已开始的过程可完成或安全退回")
        else:
            raise WorkbenchError(f"未知回执结果 {result}")
        facts["node"] = node
        facts["image"] = image

    def _do_writeoff(self, actor, facts, events, at):
        self._require_facility(actor, "审批", at)
        node, image = self._require_node_image(facts)
        case = self.case(node, image, at)
        if "writeoff" not in case.allowed_actions:
            raise WorkbenchError(
                f"{node} × {image} 阶段为 {case.phase}，须完成安装或安全退回后才能核销")

    def _do_identity_disable(self, actor, facts, events, at):
        self._admin_identity(facts, at)

    def _do_identity_enable(self, actor, facts, events, at):
        self._admin_identity(facts, at)

    def _admin_identity(self, facts, at):
        subject = facts.get("subject")
        authority = facts.get("authority", "facility")
        if f"{authority}:{subject}" not in self.bundle.identities:
            raise WorkbenchError(f"身份 {authority}:{subject} 未登记")

    def _do_trust_freeze(self, actor, facts, events, at):
        if not facts.get("authority"):
            raise WorkbenchError("trust_freeze 必须指定 authority")

    def _do_trust_thaw(self, actor, facts, events, at):
        if not facts.get("authority"):
            raise WorkbenchError("trust_thaw 必须指定 authority")

    def _do_note(self, actor, facts, events, at):
        if not facts.get("text"):
            raise WorkbenchError("备注必须包含 text")

    # ---- 校验辅助 ----------------------------------------------------
    def _require_facility(self, subject: str, role: str | None, at: int) -> Identity:
        ident = self.bundle.identity("facility", subject)
        if ident is None:
            raise WorkbenchError(f"设施账号 {subject} 未登记，归属无法确定，授权不成立")
        state = self.view(at).state
        if state.is_disabled("facility", subject):
            raise WorkbenchError(f"{subject} 已离组/停用，不再具备当班权限")
        if role and role not in ident.roles:
            raise WorkbenchError(f"{subject} 的角色 {list(ident.roles)} 不含 {role}")
        return ident

    def _require_node_image(self, facts: dict) -> tuple[str, str]:
        node = facts.get("node")
        image = facts.get("image")
        if node not in self.bundle.nodes:
            raise WorkbenchError(f"节点 {node} 不存在")
        if image not in self.bundle.packages:
            raise WorkbenchError(f"包号 {image} 不存在")
        return node, image

    @staticmethod
    def _fail_titles(case) -> str:
        failed = case.failed_bases
        return "、".join(b.title for b in failed) if failed else "无"

    # ---- 序列化 ------------------------------------------------------
    def view_dict(self, at: int | None = None) -> dict:
        view = self.view(at)
        return {
            "at": view.at,
            "clock_max": max((e.at for e in view.events), default=0),
            "cases": [self._case_dict(c) for c in view.cases],
            "events": [
                {"seq": e.seq, "at": e.at, "kind": e.kind, "actor": e.actor,
                 "facts": e.facts, "origin": e.origin}
                for e in view.events
            ],
        }

    def _case_dict(self, case) -> dict:
        return {
            "node_id": case.node_id,
            "image": case.image,
            "phase": case.phase,
            "status": case.status,
            "allowed_actions": list(case.allowed_actions),
            "remediation": case.remediation,
            "facts": case.facts,
            "history": case.history,
            "receipts": [asdict(r) for r in case.receipts],
            "bases": [asdict(b) for b in case.bases],
        }

    def journal_lines(self) -> list[dict]:
        return self.journal.read_journal()

    def export_jsonl(self) -> str:
        return "\n".join(json.dumps(e, ensure_ascii=False, sort_keys=True)
                         for e in self.view_dict()["events"])
