"""只读来源资料的加载与基础核对。

来源（data/、packages/、proofs/）是各参与方提交的事实，工作台不回写。
写入侧动作统一进入可审计的工作台日志（journal），与来源事实分开保存。
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .crypto import SignatureResult, load_proof, sha256_file, verify_ed25519


@dataclass(frozen=True)
class Package:
    id: str
    vendor: str
    version: str
    basename: str
    artifact: Path
    digest: str
    proof: dict | None
    signature: SignatureResult
    proof_problems: tuple[str, ...]


@dataclass(frozen=True)
class Identity:
    authority: str
    subject: str
    person: str
    roles: tuple[str, ...]

    @property
    def key(self) -> str:
        return f"{self.authority}:{self.subject}"


@dataclass(frozen=True)
class Node:
    id: str
    group: str
    firmware: str
    windows: tuple[tuple[int, int], ...]

    def in_window(self, at: int) -> bool:
        # 时间窗左闭右开
        return any(start <= at < end for start, end in self.windows)


@dataclass(frozen=True)
class SourceBundle:
    root: Path
    packages: dict[str, Package]
    identities: dict[str, Identity]
    nodes: dict[str, Node]
    timeline: tuple[dict, ...]
    # (authority, person) -> 该自然人在该信任域内的全部 subject
    person_subjects: dict[tuple[str, str], tuple[str, ...]] = field(default_factory=dict)

    def identity(self, authority: str, subject: str) -> Identity | None:
        return self.identities.get(f"{authority}:{subject}")


def _load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def load_sources(root: Path) -> SourceBundle:
    root = root.resolve()
    proofs_dir = root / "proofs"
    public_dir = proofs_dir / "public"

    packages: dict[str, Package] = {}
    for row in _load_json(root / "data" / "packages.json"):
        artifact = root / row["artifact"]
        digest = sha256_file(artifact)
        proof = load_proof(proofs_dir, row["id"])
        problems: list[str] = []
        if proof is None:
            signature = SignatureResult(False, "厂商证明缺失")
        else:
            public_key = public_dir / str(proof.get("public_key", ""))
            signature = verify_ed25519(
                proofs_dir / f"{row['id']}.json",
                proofs_dir / f"{row['id']}.sig",
                public_key,
            )
            # 签名只覆盖 proof JSON 本身；清单与工件仍要逐项比对，
            # 防止证明被挪用到另一个清单条目或另一份字节。
            for field_name in ("id", "vendor", "version", "basename", "artifact"):
                if proof.get(field_name) != row[field_name]:
                    problems.append(f"证明字段 {field_name} 与包清单不一致")
            if proof.get("sha256") != digest:
                problems.append("证明摘要与工件实际字节不一致（文件已变更）")
        packages[row["id"]] = Package(
            id=row["id"], vendor=row["vendor"], version=row["version"],
            basename=row["basename"], artifact=artifact, digest=digest,
            proof=proof, signature=signature, proof_problems=tuple(problems),
        )

    identities: dict[str, Identity] = {}
    person_subjects: dict[tuple[str, str], list[str]] = {}
    for row in _load_json(root / "data" / "identities.json"):
        ident = Identity(
            authority=row["authority"], subject=row["subject"],
            person=row["person"], roles=tuple(row["roles"]),
        )
        identities[ident.key] = ident
        person_subjects.setdefault((ident.authority, ident.person), []).append(ident.subject)

    nodes: dict[str, Node] = {}
    for row in _load_json(root / "data" / "equipment.json"):
        nodes[row["id"]] = Node(
            id=row["id"], group=row["group"], firmware=row["firmware"],
            windows=tuple(tuple(w) for w in row["windows"]),
        )

    timeline = tuple(_load_json(root / "data" / "timeline.json"))
    return SourceBundle(
        root=root, packages=packages, identities=identities, nodes=nodes,
        timeline=timeline,
        person_subjects={k: tuple(v) for k, v in person_subjects.items()},
    )
