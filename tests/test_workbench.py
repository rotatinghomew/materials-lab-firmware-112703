"""放行工作台策略测试：身份、双边批准、暂停与回执链的硬规则。"""
import hashlib
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from workbench.policy import BasisStatus  # noqa: E402
from workbench.service import WorkbenchError, WorkbenchService  # noqa: E402


class WorkbenchTestBase(unittest.TestCase):
    # 默认在来源事件 t=39（发布另一份）之后、t=45 离组之前的演练窗口办理
    source_through = 40

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="wb-test-"))
        self.src = self.tmp / "src"
        shutil.copytree(ROOT / "data", self.src / "data")
        shutil.copytree(ROOT / "packages", self.src / "packages")
        shutil.copytree(ROOT / "proofs", self.src / "proofs")
        self.journal = self.tmp / "journal.jsonl"
        self.service = WorkbenchService(self.src, self.journal, self.source_through)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def case(self, node, image, at=None):
        return self.service.case(node, image, at)

    def basis(self, case, code):
        return next(b for b in case.bases if b.code == code)

    def apply(self, kind, actor, facts, at=None):
        return self.service.apply(kind, actor, facts, at)

    def fresh_service(self, source_through=None):
        return WorkbenchService(self.src, self.journal,
                                source_through if source_through is not None
                                else self.source_through)

    def prepare_startable(self, node, image, group, at):
        """批准 + 计划，使一个节点×包进入可接收状态（需落在窗口内）。"""
        self.apply("facility_approve", "F-12", {"image": image, "group": group}, at=at)
        self.apply("install_plan", "F-31", {"node": node, "image": image}, at=at + 1)


class SourceAndProofTests(WorkbenchTestBase):
    source_through = None  # 用完整来源

    def test_proofs_verify_and_bind_to_exact_bytes(self):
        for pkg in self.service.bundle.packages.values():
            self.assertTrue(pkg.signature.valid, pkg.signature.detail)
            self.assertEqual(pkg.proof["sha256"], pkg.digest)
            self.assertEqual(pkg.proof_problems, ())

    def test_tampered_artifact_fails_digest_basis(self):
        artifact = self.src / "packages" / "IMG-9B.txt"
        artifact.write_bytes(artifact.read_bytes() + b"tampered")
        self.service.reload()
        case = self.case("N11", "IMG-9B")
        digest = self.basis(case, "VEND_DIGEST")
        self.assertIs(digest.status, BasisStatus.FAIL)
        self.assertIn("文件已变更", digest.remedy)
        # 签名覆盖 proof JSON 本身，仍有效；失效的是字节-摘要绑定
        self.assertIs(self.basis(case, "VEND_SIGNATURE").status, BasisStatus.PASS)

    def test_tampered_signature_fails_signature_basis(self):
        sig = self.src / "proofs" / "IMG-9C.sig"
        raw = sig.read_bytes()
        sig.write_bytes(raw[:-1] + bytes([raw[-1] ^ 0x01]))
        self.service.reload()
        case = self.case("N21", "IMG-9C")
        self.assertIs(self.basis(case, "VEND_SIGNATURE").status, BasisStatus.FAIL)
        self.assertEqual(case.status, "不可执行")

    def test_missing_proof_is_unusable(self):
        (self.src / "proofs" / "IMG-9C.json").unlink()
        (self.src / "proofs" / "IMG-9C.sig").unlink()
        self.service.reload()
        case = self.case("N21", "IMG-9C")
        for code in ("VEND_PROOF_PRESENT", "VEND_SIGNATURE", "VEND_DIGEST",
                     "VEND_ATTRIBUTION"):
            self.assertIn(self.basis(case, code).status,
                          (BasisStatus.FAIL, BasisStatus.NA))
        self.assertEqual(case.status, "不可执行")

    def test_same_version_different_digest(self):
        pkgs = list(self.service.bundle.packages.values())
        self.assertEqual({p.version for p in pkgs}, {"2.1.5"})
        self.assertNotEqual(pkgs[0].digest, pkgs[1].digest)


class ApprovalSeparationTests(WorkbenchTestBase):
    def test_same_natural_person_cannot_approve_on_facility_side(self):
        # P8 在厂商是 acct-a（提交人），在设施是 F-88（审批角色）
        with self.assertRaises(WorkbenchError) as ctx:
            self.apply("facility_approve", "F-88",
                       {"image": "IMG-9C", "group": "G2"}, at=41)
        self.assertIn("同一自然人", str(ctx.exception))
        self.assertEqual(self.service.journal_lines(), [])

    def test_independent_person_can_approve_and_binds_image(self):
        self.apply("facility_approve", "F-12",
                   {"image": "IMG-9C", "group": "G2"}, at=41)
        c9c = self.case("N21", "IMG-9C")
        self.assertIs(self.basis(c9c, "FACL_APPROVAL").status, BasisStatus.PASS)
        # 同版本号的另一个包拿不到这次批准
        c9b = self.case("N21", "IMG-9B")
        self.assertIs(self.basis(c9b, "FACL_APPROVAL").status, BasisStatus.FAIL)
        self.assertIn("不得挪用", self.basis(c9b, "FACL_APPROVAL").remedy)

    def test_vendor_failure_blocks_facility_approval(self):
        artifact = self.src / "packages" / "IMG-9C.txt"
        artifact.write_bytes(artifact.read_bytes() + b"x")
        self.service.reload()
        with self.assertRaises(WorkbenchError) as ctx:
            self.apply("facility_approve", "F-12",
                       {"image": "IMG-9C", "group": "G2"}, at=41)
        self.assertIn("双边授权", str(ctx.exception))

    def test_unknown_identity_cannot_approve(self):
        with self.assertRaises(WorkbenchError):
            self.apply("facility_approve", "F-ghost",
                       {"image": "IMG-9C", "group": "G2"}, at=41)

    def test_wrong_role_cannot_approve(self):
        with self.assertRaises(WorkbenchError) as ctx:
            self.apply("facility_approve", "F-31",
                       {"image": "IMG-9C", "group": "G2"}, at=41)
        self.assertIn("审批", str(ctx.exception))


class LifecycleReplayTests(WorkbenchTestBase):
    source_through = None  # 需要完整来源验证暂停/离组/冻结的重放

    def test_source_chain_states(self):
        # t=40：N11 已开始
        self.assertEqual(self.case("N11", "IMG-9B", 40).phase, "started")
        # t=36：N12 已接收、未暂停、在窗口内 → 可启动
        self.assertEqual(self.case("N12", "IMG-9B", 36).status, "可启动")
        # t=38：N12 已暂停，旧接收回执不能启动
        suspended = self.case("N12", "IMG-9B", 38)
        self.assertIs(self.basis(suspended, "FACL_SUSPEND").status, BasisStatus.FAIL)
        self.assertNotIn("start", suspended.allowed_actions)

    def test_started_node_after_failure_may_only_finish_or_rollback(self):
        # t=44：已开始，批准人尚未离组、信任未冻结
        going = self.case("N11", "IMG-9B", 44)
        self.assertEqual(going.phase, "started")
        # t=46：批准人 F-12 已离组（t=45），已开始的链不宜强停
        broken = self.case("N11", "IMG-9B", 46)
        self.assertIs(self.basis(broken, "FACL_APPROVER").status, BasisStatus.FAIL)
        self.assertEqual(set(broken.allowed_actions), {"finish", "rollback"})
        # t=71：信任冻结叠加，仍然只允许完成或安全退回；t=52 完成后则只能核销
        frozen = self.case("N11", "IMG-9B", 71)
        self.assertIs(self.basis(frozen, "VEND_ATTRIBUTION").status, BasisStatus.FAIL)
        self.assertEqual(frozen.phase, "finished")
        self.assertEqual(set(frozen.allowed_actions), {"writeoff"})
        self.assertIn("核销", frozen.status)

    def test_suspended_accepted_node_cannot_start_but_can_rollback(self):
        case = self.case("N12", "IMG-9B", 60)
        self.assertEqual(case.phase, "accepted")
        svc40 = self.fresh_service(source_through=40)
        with self.assertRaises(WorkbenchError):
            svc40.apply("receipt", "N12",
                        {"image": "IMG-9B", "result": "start"}, at=41)
        svc40.apply("receipt", "N12",
                    {"image": "IMG-9B", "result": "rollback", "actor": "F-31"}, at=42)
        rb = svc40.case("N12", "IMG-9B")
        self.assertEqual(rb.phase, "rolled_back")
        self.assertIn("writeoff", rb.allowed_actions)

    def test_window_half_open_interval(self):
        svc = self.fresh_service(source_through=40)
        before = self.basis(svc.case("N21", "IMG-9C", 74), "NODE_WINDOW")
        self.assertIs(before.status, BasisStatus.FAIL)
        self.assertIn("不在任何", before.detail)
        self.assertIs(self.basis(svc.case("N21", "IMG-9C", 75),
                                 "NODE_WINDOW").status, BasisStatus.PASS)
        self.assertIs(self.basis(svc.case("N21", "IMG-9C", 130),
                                 "NODE_WINDOW").status, BasisStatus.FAIL)

    def test_plan_revoke_does_not_grant_other_version(self):
        svc = self.fresh_service(source_through=40)
        svc.apply("facility_approve", "F-12",
                  {"image": "IMG-9C", "group": "G2"}, at=76)
        svc.apply("install_plan", "F-31",
                  {"node": "N21", "image": "IMG-9C"}, at=77)
        svc.apply("install_plan_revoke", "F-12",
                  {"node": "N21", "image": "IMG-9C"}, at=78)
        case = svc.case("N21", "IMG-9C", 79)
        self.assertIs(self.basis(case, "NODE_PLAN").status, BasisStatus.FAIL)
        # 同版本号的 9B 依然没有任何授权
        self.assertEqual(svc.case("N21", "IMG-9B", 79).status, "不可执行")
        with self.assertRaises(WorkbenchError):
            svc.apply("receipt", "N21",
                      {"image": "IMG-9C", "result": "accept", "actor": "F-31"}, at=80)

    def test_installer_must_hold_active_install_role(self):
        svc = self.fresh_service(source_through=40)
        svc.apply("facility_approve", "F-12",
                  {"image": "IMG-9C", "group": "G2"}, at=76)
        svc.apply("install_plan", "F-31",
                  {"node": "N21", "image": "IMG-9C"}, at=77)
        # 无安装角色的账号不能接收（F-12 此时仍在册）
        with self.assertRaises(WorkbenchError) as ctx:
            svc.apply("receipt", "N21",
                      {"image": "IMG-9C", "result": "accept", "actor": "F-12"}, at=78)
        self.assertIn("安装", str(ctx.exception))
        # F-31 离组后当班权限终止
        svc.apply("identity_disable", "registry",
                  {"subject": "F-31", "authority": "facility"}, at=79)
        with self.assertRaises(WorkbenchError) as ctx:
            svc.apply("receipt", "N21",
                      {"image": "IMG-9C", "result": "accept", "actor": "F-31"}, at=80)
        self.assertIn("当班权限", str(ctx.exception))
        # 离组后恢复启用，权限恢复即可继续办理
        svc.apply("identity_enable", "registry",
                  {"subject": "F-31", "authority": "facility"}, at=81)
        svc.apply("receipt", "N21",
                  {"image": "IMG-9C", "result": "accept", "actor": "F-31"}, at=82)
        self.assertEqual(svc.case("N21", "IMG-9C").phase, "accepted")

    def test_writeoff_requires_finish_or_rollback(self):
        svc = self.fresh_service(source_through=40)
        with self.assertRaises(WorkbenchError):
            svc.apply("writeoff", "F-12",
                      {"node": "N21", "image": "IMG-9C"}, at=80)

    def test_full_happy_path_then_writeoff(self):
        svc = self.fresh_service(source_through=40)
        svc.apply("facility_approve", "F-12",
                  {"image": "IMG-9C", "group": "G2"}, at=76)
        svc.apply("install_plan", "F-31",
                  {"node": "N21", "image": "IMG-9C"}, at=77)
        accepted = svc.case("N21", "IMG-9C", 78)
        self.assertEqual(accepted.status, "可接收")
        svc.apply("receipt", "N21",
                  {"image": "IMG-9C", "result": "accept", "actor": "F-31"}, at=79)
        self.assertEqual(svc.case("N21", "IMG-9C", 80).status, "可启动")
        svc.apply("receipt", "N21", {"image": "IMG-9C", "result": "start"}, at=81)
        svc.apply("receipt", "N21",
                  {"image": "IMG-9C", "result": "finish", "actor": "F-31"}, at=82)
        svc.apply("writeoff", "F-12",
                  {"node": "N21", "image": "IMG-9C"}, at=83)
        self.assertEqual(svc.case("N21", "IMG-9C").phase, "written_off")
        self.assertEqual(svc.case("N21", "IMG-9C").status, "已核销")


class ChangeReevaluationTests(WorkbenchTestBase):
    source_through = None

    def test_approver_transfer_invalidates_their_approval(self):
        before = self.case("N11", "IMG-9B", 44)
        self.assertIs(self.basis(before, "FACL_APPROVER").status, BasisStatus.PASS)
        after = self.case("N11", "IMG-9B", 46)  # t=45 F-12 离组
        self.assertIs(self.basis(after, "FACL_APPROVER").status, BasisStatus.FAIL)
        self.assertIn("重新批准", self.basis(after, "FACL_APPROVER").remedy)
        # 厂商侧依据不随设施人员离组而变化
        self.assertIs(self.basis(after, "VEND_SIGNATURE").status, BasisStatus.PASS)

    def test_file_change_rejudges_only_that_image(self):
        svc = self.fresh_service(source_through=40)
        svc.apply("facility_approve", "F-12",
                  {"image": "IMG-9C", "group": "G2"}, at=41)
        artifact = self.src / "packages" / "IMG-9C.txt"
        artifact.write_bytes(artifact.read_bytes() + b"changed")
        svc.reload()
        self.assertIs(self.basis(svc.case("N21", "IMG-9C"),
                                 "VEND_DIGEST").status, BasisStatus.FAIL)
        self.assertIs(self.basis(svc.case("N11", "IMG-9B"),
                                 "VEND_DIGEST").status, BasisStatus.PASS)

    def test_resign_required_after_change(self):
        artifact = self.src / "packages" / "IMG-9C.txt"
        new_bytes = artifact.read_bytes() + b"v2"
        artifact.write_bytes(new_bytes)
        proof_path = self.src / "proofs" / "IMG-9C.json"
        proof = json.loads(proof_path.read_text(encoding="utf-8"))
        proof["sha256"] = hashlib.sha256(new_bytes).hexdigest()
        proof_path.write_text(json.dumps(proof, ensure_ascii=False, indent=2),
                              encoding="utf-8")
        # 摘要更新后旧签名不再覆盖该载荷 → 签名依据失效，必须厂商重签
        self.service.reload()
        case = self.case("N21", "IMG-9C")
        self.assertIs(self.basis(case, "VEND_SIGNATURE").status, BasisStatus.FAIL)


class JournalAndDeterminismTests(WorkbenchTestBase):
    source_through = 40

    def test_journal_persists_and_rebuilds_identically(self):
        self.prepare_startable("N21", "IMG-9C", "G2", 76)
        first = self.service.view_dict()
        restarted = self.fresh_service()
        self.assertEqual(restarted.view_dict(), first)
        lines = self.journal.read_text(encoding="utf-8").splitlines()
        self.assertTrue(lines)
        for line in lines:
            self.assertIn("kind", json.loads(line))

    def test_clock_only_moves_forward(self):
        self.apply("note", "F-12", {"text": "x"}, at=100)
        with self.assertRaises(WorkbenchError):
            self.apply("note", "F-12", {"text": "y"}, at=50)

    def test_deterministic_snapshot(self):
        self.prepare_startable("N21", "IMG-9C", "G2", 76)
        v1 = self.service.view(at=90)
        v2 = self.service.view(at=90)
        self.assertEqual(
            [b.status for c in v1.cases for b in c.bases],
            [b.status for c in v2.cases for b in c.bases])


if __name__ == "__main__":
    unittest.main()
