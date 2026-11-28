"""厂商发布证明的字节级核对（OpenSSL 3 Ed25519）。

证明文件本身是不可信输入：签名只在通过 OpenSSL 验证后才被采信，
验证失败、公钥缺失或字段对不上都视为证明失效，不能满足双边授权。
"""
from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class SignatureResult:
    valid: bool
    detail: str


def sha256_bytes(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def verify_ed25519(payload: Path, signature: Path, public_key: Path) -> SignatureResult:
    """用 OpenSSL 3 验证 Ed25519 分离签名（与现有资料核对方式一致）。"""
    if not payload.is_file():
        return SignatureResult(False, f"证明载荷缺失: {payload.name}")
    if not signature.is_file():
        return SignatureResult(False, f"签名缺失: {signature.name}")
    if not public_key.is_file():
        return SignatureResult(False, f"签发公钥未登记: {public_key.name}")
    result = subprocess.run(
        [
            "openssl", "pkeyutl", "-verify", "-rawin", "-pubin",
            "-inkey", str(public_key),
            "-in", str(payload),
            "-sigfile", str(signature),
        ],
        capture_output=True,
    )
    if result.returncode == 0:
        return SignatureResult(True, "Ed25519 签名验证通过")
    return SignatureResult(False, result.stderr.decode(errors="replace").strip()
                           or "Ed25519 签名验证失败")


def load_proof(proofs_dir: Path, package_id: str) -> dict | None:
    path = proofs_dir / f"{package_id}.json"
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))
