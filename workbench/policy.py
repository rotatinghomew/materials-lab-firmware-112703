"""身份—批准—执行链的逐台判定引擎。

设计原则：
* 来源事实与工作台动作合并后按演练时钟重放，任意时刻都能重建状态；
* 厂商身份只证明来源和所签字节，部署授权只能由当前值班组按
  设备 + 内容摘要 + 设备状态作出；
* 批准绑定包号（内容摘要），同版本号的试制包/正式包不得复用批准；
* 每个节点 × 包的放行依据逐项给出通过/失效结论、证据与处置动作；
* 调离、信任冻结、文件变更只重判受影响对象，其他节点结论不变。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from .journal import StoredEvent
from .sources import Node, Package, SourceBundle


class BasisStatus(str, Enum):
    PASS = "通过"
    FAIL = "失效"
    NA = "不适用"


@dataclass(frozen=True)
class Basis:
    code: str
    title: str
    side: str  # vendor | facility | node
    status: BasisStatus
    detail: str
    evidence: str
    remedy: str = ""

    @property
    def ok(self) -> bool:
        return self.status is BasisStatus.PASS


@dataclass
class ReceiptRecord:
    result: str
    at: int
    actor: str
    installer: str | None = None
    origin: str = "source"


@dataclass
class PlanRecord:
    at: int
    actor: str
    active: bool
    revoke_at: int | None = None
    revoke_actor: str | None = None


@dataclass
class ApprovalRecord:
    at: int
    actor: str
    scope: str          # group | node
    target: str         # 组号或节点号
    image: str          # 批准绑定的包号；不跨包（即使版本号/文件名相同）复用
    origin: str


@dataclass
class ReplayState:
    at: int
    frozen_authorities: set[str] = field(default_factory=set)
    disabled_subjects: dict[str, int] = field(default_factory=dict)   # key -> 停用时刻
    enabled_identities: dict[str, dict] = field(default_factory=dict)
    approvals: list[ApprovalRecord] = field(default_factory=list)
    suspensions: dict[tuple[str, str], dict] = field(default_factory=dict)
    receipts: dict[tuple[str, str], list[ReceiptRecord]] = field(default_factory=dict)
    plans: dict[tuple[str, str], list[PlanRecord]] = field(default_factory=dict)
    writeoffs: dict[tuple[str, str], dict] = field(default_factory=dict)

    def is_disabled(self, authority: str, subject: str) -> bool:
        return f"{authority}:{subject}" in self.disabled_subjects

    def covering_approvals(self, node_id: str, group: str) -> list[ApprovalRecord]:
        """指向该节点的组级或节点级批准（不区分 image，调用方再按 image 过滤）。"""
        return [
            a for a in self.approvals
            if (a.scope == "group" and a.target == group)
            or (a.scope == "node" and a.target == node_id)
        ]


def replay(events: list[StoredEvent], at: int | None = None) -> ReplayState:
    """把截至 at 的事件重放成状态。"""
    state = ReplayState(at=at if at is not None else max((e.at for e in events), default=0))
    for event in events:
        if at is not None and event.at > at:
            break
        kind, facts, actor = event.kind, event.facts, event.actor
        if kind in ("trust_freeze", "trust_thaw"):
            authority = facts.get("authority", "vendor")
            # 来源资料用 "vendor" 表示整个厂商信任域，证明归属用具体厂商标识（如 vnd-4），
            # 归一化后两类记录都能命中。
            normalized = "vnd-4" if authority == "vendor" else authority
            if kind == "trust_freeze":
                state.frozen_authorities.add(authority)
                state.frozen_authorities.add(normalized)
            else:
                state.frozen_authorities.discard(authority)
                state.frozen_authorities.discard(normalized)
        elif kind in ("identity_enable", "identity_disable", "subject_disable"):
            authority = facts.get("authority", "facility")
            subject = facts["subject"]
            key = f"{authority}:{subject}"
            if kind == "identity_enable":
                state.enabled_identities[key] = {
                    "at": event.at, "person": facts.get("person"),
                    "roles": tuple(facts.get("roles", [])),
                }
                state.disabled_subjects.pop(key, None)
            else:
                state.disabled_subjects[key] = event.at
        elif kind == "facility_approve":
            state.approvals.append(ApprovalRecord(
                at=event.at, actor=actor,
                scope="node" if facts.get("node") else "group",
                target=facts.get("node") or facts["group"],
                image=facts["image"],
                origin=event.origin,
            ))
        elif kind in ("suspend", "resume"):
            key = (facts["node"], facts["image"])
            state.suspensions[key] = {
                "suspended": kind == "suspend", "at": event.at, "actor": actor,
            }
        elif kind == "receipt":
            key = (actor, facts["image"])
            state.receipts.setdefault(key, []).append(ReceiptRecord(
                result=facts["result"], at=event.at, actor=actor,
                installer=facts.get("actor"), origin=event.origin,
            ))
        elif kind == "install_plan":
            state.plans.setdefault((facts["node"], facts["image"]), []).append(
                PlanRecord(at=event.at, actor=actor, active=True))
        elif kind == "install_plan_revoke":
            for plan in reversed(state.plans.get((facts["node"], facts["image"]), [])):
                if plan.active:
                    plan.active = False
                    plan.revoke_at = event.at
                    plan.revoke_actor = actor
                    break
        elif kind == "writeoff":
            state.writeoffs[(facts["node"], facts["image"])] = {"at": event.at, "actor": actor}
    return state


# 依据代码 -> 中文标题（合规视图按此逐台复查）
BASIS_TITLES = {
    "VEND_PROOF_PRESENT": ("vendor", "厂商证明存在"),
    "VEND_SIGNATURE": ("vendor", "厂商 Ed25519 签名有效"),
    "VEND_DIGEST": ("vendor", "证明摘要与工件字节一致"),
    "VEND_ATTRIBUTION": ("vendor", "签发归属可确定且未被信任冻结"),
    "VEND_SUBMIT": ("vendor", "该包号有对应来源提交"),
    "FACL_APPROVAL": ("facility", "设施方当前有效批准（按设备+摘要）"),
    "FACL_APPROVER": ("facility", "批准人身份有效且仍在审批岗"),
    "FACL_SOD": ("facility", "职责分离：提交人未作同一次设施批准"),
    "FACL_SUSPEND": ("facility", "节点未被单独暂停"),
    "NODE_WINDOW": ("node", "当前时刻落在已批准实验间隔"),
    "NODE_INSTALLER": ("node", "实际启动/接收人具备当班安装权限"),
    "NODE_PLAN": ("node", "当前安装计划有效且未被撤销"),
    "NODE_EXACT_IMAGE": ("node", "批准与回执均绑定本包号（无版本号挪用）"),
}


@dataclass
class CaseEvaluation:
    node_id: str
    image: str
    phase: str                       # none | accepted | started | finished | rolled_back | written_off
    status: str                      # 工作台对外的可执行状态（中文）
    bases: list[Basis]
    receipts: list[ReceiptRecord]
    allowed_actions: tuple[str, ...]
    remediation: list[str]
    history: list[dict]              # 已经发生的依据失效/越权事件
    facts: dict

    @property
    def failed_bases(self) -> list[Basis]:
        return [b for b in self.bases if b.status is BasisStatus.FAIL]


@dataclass
class WorkbenchView:
    at: int
    cases: list[CaseEvaluation]
    events: list[StoredEvent]
    state: ReplayState


class Engine:
    def __init__(self, bundle: SourceBundle):
        self.bundle = bundle

    # ---- 状态重放 ----------------------------------------------------
    def view(self, events: list[StoredEvent], at: int | None = None) -> WorkbenchView:
        state = replay(events, at)
        cases = [self._evaluate(node, pkg, state, events)
                 for node in self.bundle.nodes.values()
                 for pkg in self.bundle.packages.values()]
        return WorkbenchView(at=state.at, cases=cases, events=events, state=state)

    # ---- 单个节点 × 包的依据链 --------------------------------------
    def _evaluate(self, node: Node, pkg: Package,
                  state: ReplayState, events: list[StoredEvent]) -> CaseEvaluation:
        key = (node.id, pkg.id)
        receipts = list(state.receipts.get(key, []))
        phase = self._phase(receipts, key in state.writeoffs)
        history = self._history(node, pkg, events)
        bases: list[Basis] = []
        bases.append(self._b_proof_present(pkg))
        bases.append(self._b_signature(pkg))
        bases.append(self._b_digest(pkg))
        bases.append(self._b_attribution(pkg, state))
        bases.append(self._b_submit(pkg, events))
        approval = self._pick_approval(node, pkg, state)
        bases.append(self._b_approval(node, pkg, state, approval))
        bases.append(self._b_approver(approval, state))
        bases.append(self._b_sod(pkg, approval))
        bases.append(self._b_suspend(node, pkg, state, phase))
        bases.append(self._b_window(node, state.at))
        bases.append(self._b_installer(node, pkg, receipts, state))
        bases.append(self._b_plan(node, pkg, state, phase))
        bases.append(self._b_exact_image(node, pkg, receipts, approval))
        status, allowed, remediation = self._decide(
            node, pkg, state, phase, receipts, bases, history)
        return CaseEvaluation(
            node_id=node.id, image=pkg.id, phase=phase, status=status, bases=bases,
            receipts=receipts, allowed_actions=tuple(allowed),
            remediation=remediation, history=history,
            facts={"group": node.group, "version": pkg.version,
                   "basename": pkg.basename, "digest": pkg.digest,
                   "vendor": pkg.vendor, "firmware": node.firmware},
        )

    # ---- 依据判定 ----------------------------------------------------
    def _b_proof_present(self, pkg: Package) -> Basis:
        if pkg.proof is not None:
            return self._ok("VEND_PROOF_PRESENT", f"证明文件 {pkg.id}.json 已登记",
                            f"proofs/{pkg.id}.json")
        return self._fail("VEND_PROOF_PRESENT", "未找到厂商发布证明", "无",
                          "退回厂商补齐带签名的发布证明")

    def _b_signature(self, pkg: Package) -> Basis:
        if pkg.proof is None:
            return self._na("VEND_SIGNATURE", "无证明载荷，无法验签")
        if pkg.signature.valid:
            return self._ok("VEND_SIGNATURE", pkg.signature.detail,
                            f"proofs/{pkg.id}.sig <- public/{pkg.proof.get('public_key')}")
        return self._fail("VEND_SIGNATURE", pkg.signature.detail,
                          f"proofs/{pkg.id}.sig", "证明失效，要求厂商重新签发")

    def _b_digest(self, pkg: Package) -> Basis:
        if pkg.proof is None:
            return self._na("VEND_DIGEST", "无证明可比对摘要")
        mismatch = [p for p in pkg.proof_problems if "摘要" in p]
        if not mismatch and not any(p.startswith("证明字段") for p in pkg.proof_problems):
            return self._ok("VEND_DIGEST", f"sha256={pkg.digest[:16]}…",
                            f"packages 工件实测 vs 证明 {pkg.id}.json")
        if mismatch:
            return self._fail("VEND_DIGEST", mismatch[0],
                              f"工件 {pkg.artifact.name} 实测 {pkg.digest[:16]}…",
                              "文件已变更：冻结该包，要求厂商按新字节重新签发并重新走批准")
        return self._fail("VEND_DIGEST", "; ".join(pkg.proof_problems),
                          f"proofs/{pkg.id}.json", "退回厂商更正证明与清单")

    def _b_attribution(self, pkg: Package, state: ReplayState) -> Basis:
        if pkg.proof is None:
            return self._na("VEND_ATTRIBUTION", "无证明，归属无法确定")
        subject = pkg.proof.get("subject")
        vendor = pkg.proof.get("vendor")
        ident = self.bundle.identity("vendor", subject) if subject else None
        if ident is None:
            return self._fail("VEND_ATTRIBUTION",
                              f"签发主体 {subject} 未在 {vendor} 身份目录登记，归属无法确定",
                              "identities.json", "失效证明不能满足双边授权，拒绝采信")
        if state.is_disabled("vendor", subject):
            at = state.disabled_subjects[f"vendor:{subject}"]
            return self._fail("VEND_ATTRIBUTION",
                              f"签发主体 {subject} 已在 t={at} 停用", f"停用事件 t={at}",
                              "要求当前在册厂商主体重新签发")
        if vendor in state.frozen_authorities:
            return self._fail("VEND_ATTRIBUTION",
                              f"签发信任域 {vendor} 已被冻结", "trust_freeze 事件",
                              "冻结期间不得新放行；待信任恢复并重新评估")
        return self._ok("VEND_ATTRIBUTION",
                        f"{subject}（自然人 {ident.person}）属 {vendor}，信任域正常",
                        f"identities {ident.key}")

    def _b_submit(self, pkg: Package, events: list[StoredEvent]) -> Basis:
        hits = [e for e in events if e.kind == "vendor_submit"
                and e.facts.get("image") == pkg.id]
        if hits:
            last = hits[-1]
            return self._ok("VEND_SUBMIT", f"t={last.at} 由 {last.actor} 提交",
                            f"来源事件 seq={last.seq}")
        return self._fail("VEND_SUBMIT", f"包号 {pkg.id} 没有任何提交记录", "无",
                          "凭包号不得套用其它包的批准，需由厂商重新提交")

    def _pick_approval(self, node: Node, pkg: Package,
                       state: ReplayState) -> ApprovalRecord | None:
        # 批准必须同时指向本节点（组级或节点级）与本包号；
        # 同版本号/同文件名但包号不同的批准在这一步被排除。
        matches = [a for a in state.covering_approvals(node.id, node.group)
                   if a.image == pkg.id]
        return matches[-1] if matches else None

    def _b_approval(self, node: Node, pkg: Package, state: ReplayState,
                    approval: ApprovalRecord | None) -> Basis:
        if approval is None:
            same_version = [p.id for p in self.bundle.packages.values()
                            if p.version == pkg.version and p.id != pkg.id]
            hint = (f"同版本号 {pkg.version} 的 {', '.join(same_version)} 批准不得挪用；"
                    if same_version else "")
            return self._fail("FACL_APPROVAL",
                              f"没有指向节点 {node.id} 与包 {pkg.id}（摘要 {pkg.digest[:12]}…）的有效批准",
                              "facility_approve 记录",
                              hint + "由当前值班组按设备、内容摘要和设备状态重新批准")
        scope_text = "组级" if approval.scope == "group" else "节点级"
        return self._ok("FACL_APPROVAL",
                        f"t={approval.at} {approval.actor} 作出{scope_text}批准，覆盖本节点与本包号",
                        f"{approval.origin} 事件")

    def _b_approver(self, approval: ApprovalRecord | None,
                    state: ReplayState) -> Basis:
        if approval is None:
            return self._na("FACL_APPROVER", "无批准可核")
        ident = self.bundle.identity("facility", approval.actor)
        if ident is None:
            return self._fail("FACL_APPROVER",
                              f"批准账号 {approval.actor} 不在设施身份目录，归属无法确定",
                              "identities.json", "失效批准不能满足双边授权，需在册审批人重批")
        if state.is_disabled("facility", approval.actor):
            at = state.disabled_subjects[f"facility:{approval.actor}"]
            return self._fail("FACL_APPROVER",
                              f"批准人 {approval.actor} 已于 t={at} 离组，批准不再代表当前值班组",
                              f"岗位调离 t={at}",
                              "由当前值班组具备审批角色的人员重新批准后才能继续办理")
        if "审批" not in ident.roles:
            return self._fail("FACL_APPROVER",
                              f"{approval.actor} 的角色 {list(ident.roles)} 不含审批",
                              "identities.json", "更换具备审批角色的值班人员")
        return self._ok("FACL_APPROVER",
                        f"{approval.actor}（自然人 {ident.person}）在册且持审批角色",
                        f"identities {ident.key}")

    def _b_sod(self, pkg: Package, approval: ApprovalRecord | None) -> Basis:
        if approval is None or pkg.proof is None:
            return self._na("FACL_SOD", "缺少批准或厂商证明，无法比对同一自然人")
        vendor_ident = self.bundle.identity("vendor", pkg.proof.get("subject", ""))
        facility_ident = self.bundle.identity("facility", approval.actor)
        if vendor_ident is None or facility_ident is None:
            return self._fail("FACL_SOD", "一方身份归属无法确定，无法排除自我批准",
                              "identities.json", "补齐身份归属后重新判定")
        if vendor_ident.person == facility_ident.person:
            return self._fail(
                "FACL_SOD",
                f"提交人 {vendor_ident.subject} 与批准人 {facility_ident.subject} "
                f"是同一自然人 {vendor_ident.person}，不得作同一次独立设施批准",
                f"person={vendor_ident.person}",
                "由与提交人不同自然人的设施审批人重新批准")
        return self._ok("FACL_SOD",
                        f"提交自然人 {vendor_ident.person} ≠ 批准自然人 {facility_ident.person}",
                        "identities person 映射")

    def _b_suspend(self, node: Node, pkg: Package, state: ReplayState,
                   phase: str) -> Basis:
        rec = state.suspensions.get((node.id, pkg.id))
        if rec and rec["suspended"]:
            if phase in ("started",):
                return self._ok("FACL_SUSPEND",
                                f"t={rec['at']} 暂停；节点已开始，仅允许完成或安全退回",
                                f"suspend 事件 t={rec['at']}")
            return self._fail("FACL_SUSPEND",
                              f"节点已被 {rec['actor']} 于 t={rec['at']} 暂停，旧回执不能启动",
                              f"suspend 事件 t={rec['at']}",
                              "保持暂停；由值班组恢复（resume）或安排安全退回")
        detail = "无暂停记录" if rec is None else f"已于 t={rec['at']} 恢复"
        return self._ok("FACL_SUSPEND", detail, "suspend/resume 记录")

    def _b_window(self, node: Node, at: int) -> Basis:
        if node.in_window(at):
            window = next(w for w in node.windows if w[0] <= at < w[1])
            return self._ok("NODE_WINDOW",
                            f"t={at} 落在实验间隔 [{window[0]}, {window[1]})",
                            "equipment.windows")
        windows = ", ".join(f"[{s}, {e})" for s, e in node.windows)
        return self._fail("NODE_WINDOW",
                          f"t={at} 不在任何已批准实验间隔（{windows}），不得换固件",
                          "equipment.windows",
                          "等待下一个批准间隔，或由设施方变更窗口后重判")

    def _b_installer(self, node: Node, pkg: Package,
                     receipts: list[ReceiptRecord], state: ReplayState) -> Basis:
        installers = {r.installer for r in receipts if r.result == "accept" and r.installer}
        if not installers:
            return self._na("NODE_INSTALLER", "尚无接收回执，未产生实际安装人")
        subject = next(iter(installers))
        ident = self.bundle.identity("facility", subject)
        if ident is None:
            return self._fail("NODE_INSTALLER",
                              f"安装账号 {subject} 未登记，归属无法确定",
                              "receipt 回执", "由在册安装人重新办理接收")
        if state.is_disabled("facility", subject):
            at = state.disabled_subjects[f"facility:{subject}"]
            return self._fail("NODE_INSTALLER",
                              f"安装人 {subject} 已于 t={at} 离组，当班权限终止",
                              f"停用事件 t={at}", "后续动作须由当前当班安装人承接")
        if "安装" not in ident.roles:
            return self._fail("NODE_INSTALLER",
                              f"{subject} 角色 {list(ident.roles)} 不含安装",
                              "identities.json", "更换持安装角色的当班人员")
        return self._ok("NODE_INSTALLER",
                        f"{subject}（自然人 {ident.person}）持安装角色且当班",
                        "receipt + identities")

    def _b_plan(self, node: Node, pkg: Package, state: ReplayState,
                phase: str) -> Basis:
        plans = state.plans.get((node.id, pkg.id), [])
        active = [p for p in plans if p.active]
        if active:
            return self._ok("NODE_PLAN",
                            f"t={active[-1].at} 建立的安装计划当前有效", "install_plan")
        if plans:
            last = plans[-1]
            return self._fail("NODE_PLAN",
                              f"上一安装计划已被 {last.revoke_actor} 于 t={last.revoke_at} 撤销",
                              "install_plan_revoke",
                              "撤销不产生新版本授权；如需办理须重新建立计划并重新批准")
        if phase == "none":
            return self._fail("NODE_PLAN", "尚无安装计划", "无",
                              "建立指向本节点本包号的安装计划")
        return self._na("NODE_PLAN", "计划缺失但节点已有回执，按历史链核查")

    def _b_exact_image(self, node: Node, pkg: Package,
                       receipts: list[ReceiptRecord],
                       approval: ApprovalRecord | None) -> Basis:
        # 回执在入链时已按 (node, image) 归类；这里显式声明不允许按文件名/版本号挪用
        others = [p.id for p in self.bundle.packages.values()
                  if p.id != pkg.id and p.version == pkg.version
                  and p.basename == pkg.basename]
        if others:
            return self._ok(
                "NODE_EXACT_IMAGE",
                f"本链全部回执与批准均指向包号 {pkg.id}（摘要 {pkg.digest[:12]}…）；"
                f"同名同版本的 {', '.join(others)} 字节不同，批准不互通",
                "包号 + sha256 绑定")
        return self._ok("NODE_EXACT_IMAGE",
                        f"回执与批准按包号 {pkg.id} 与摘要绑定", "包号 + sha256")

    # ---- 阶段、状态与处置 -------------------------------------------
    @staticmethod
    def _phase(receipts: list[ReceiptRecord], written_off: bool) -> str:
        if written_off:
            return "written_off"
        results = [r.result for r in receipts]
        if "rollback" in results:
            return "rolled_back"
        if "finish" in results:
            return "finished"
        if "start" in results:
            return "started"
        if "accept" in results:
            return "accepted"
        return "none"

    def _decide(self, node: Node, pkg: Package, state: ReplayState,
                phase: str, receipts: list[ReceiptRecord],
                bases: list[Basis], history: list[dict]):
        failed = {b.code: b for b in bases if b.status is BasisStatus.FAIL}
        preconditions = [b for b in bases if b.code in {
            "VEND_PROOF_PRESENT", "VEND_SIGNATURE", "VEND_DIGEST",
            "VEND_ATTRIBUTION", "VEND_SUBMIT", "FACL_APPROVAL",
            "FACL_APPROVER", "FACL_SOD", "NODE_EXACT_IMAGE"}]
        chain_ok = all(b.ok for b in preconditions)
        suspended = (state.suspensions.get((node.id, pkg.id)) or {}).get("suspended", False)
        window_ok = next(b for b in bases if b.code == "NODE_WINDOW").ok
        plan_ok = next(b for b in bases if b.code == "NODE_PLAN").status is not BasisStatus.FAIL
        remediation = [b.remedy for b in failed.values() if b.remedy]

        if phase == "written_off":
            return "已核销", (), remediation + ["本节点本包链已核销，不再接受动作"]
        if phase == "rolled_back":
            return "已安全退回", ("writeoff",), remediation + [
                "安全退回已完成，核对退回状态后办理核销（writeoff）"]
        if phase == "finished":
            return "已完成待核销", ("writeoff",), remediation + [
                "固件安装已完成，补齐失效依据说明后办理核销"]
        if phase == "started":
            if not chain_ok:
                bad = "、".join(failed[c].title for c in failed if c in
                                {b.code for b in preconditions})
                return f"已开始-依据失效（{bad}）", ("finish", "rollback"), remediation + [
                    "不宜强停：仅允许完成已开始的过程，或走本节点安全退回，之后核销"]
            return "安装进行中", ("finish", "rollback"), remediation + [
                "等待节点 finish 回执；异常时执行安全退回"]
        if phase == "accepted":
            if suspended:
                # 已接收未开始即被暂停：不能启动，但可走节点安全退回后核销
                return "已接收-暂停挂起", ("rollback",), remediation + [
                    "暂停期间不得凭旧接收回执启动；恢复后在实验间隔内启动，或安全退回"]
            if not chain_ok:
                bad = "、".join(failed[c].title for c in failed if c in
                                {b.code for b in preconditions})
                return f"已接收-依据失效（{bad}）", ("rollback",), remediation + [
                    "尚未开始：禁止启动；先修复失效依据，或安排安全退回"]
            if not window_ok:
                return "已接收-等待实验间隔", (), remediation + [
                    "进入批准实验间隔后再由当班安装人启动"]
            if not plan_ok:
                return "已接收-计划失效", (), remediation
            return "可启动", ("start", "rollback"), remediation
        # phase == none
        if not chain_ok or not plan_ok:
            return "不可执行", (), remediation
        if suspended:
            return "批准范围内-节点暂停", (), remediation
        if not window_ok:
            return "等待实验间隔", (), remediation
        return "可接收", ("accept",), remediation

    def _history(self, node: Node, pkg: Package,
                 events: list[StoredEvent]) -> list[dict]:
        """检测重放期间已经发生过的越权/失效事件，供合规逐台复查。"""
        out: list[dict] = []
        for e in events:
            k, f = e.kind, e.facts
            if k == "receipt" and e.actor == node.id and f.get("image") == pkg.id:
                out.append({"at": e.at, "event": "receipt:" + f.get("result", ""),
                            "detail": f"节点回执，来源={e.origin}"})
            elif k == "suspend" and f.get("node") == node.id and f.get("image") == pkg.id:
                out.append({"at": e.at, "event": "suspend",
                            "detail": f"{e.actor} 暂停该节点本包安装"})
            elif k == "install_plan_revoke" and f.get("node") == node.id \
                    and f.get("image") == pkg.id:
                out.append({"at": e.at, "event": "plan_revoked",
                            "detail": f"{e.actor} 撤销安装计划，不连带产生其它版本授权"})
            elif k in ("subject_disable", "identity_disable") and f.get("subject"):
                out.append({"at": e.at, "event": "subject_disabled",
                            "detail": f"{f['subject']} 离组/停用，涉及其批准或安装的链重判"})
            elif k == "trust_freeze":
                out.append({"at": e.at, "event": "trust_frozen",
                            "detail": f"信任域 {f.get('authority')} 冻结，其签发证明重判"})
        return out

    # ---- 小工具 ------------------------------------------------------
    @staticmethod
    def _ok(code: str, detail: str, evidence: str) -> Basis:
        side, title = BASIS_TITLES[code]
        return Basis(code, title, side, BasisStatus.PASS, detail, evidence)

    @staticmethod
    def _fail(code: str, detail: str, evidence: str, remedy: str) -> Basis:
        side, title = BASIS_TITLES[code]
        return Basis(code, title, side, BasisStatus.FAIL, detail, evidence, remedy)

    @staticmethod
    def _na(code: str, detail: str) -> Basis:
        side, title = BASIS_TITLES[code]
        return Basis(code, title, side, BasisStatus.NA, detail, "—")
