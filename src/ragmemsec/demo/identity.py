"""Server-only live-workspace directory validated against benchmark policy."""

from __future__ import annotations

import json
import re
from pathlib import Path

LIVE_POLICY = Path("src/ragmemsec/demo/access_policy.json")
SUPPORTED_ROLES = {"engineering", "analyst", "security_review", "administrator"}


def load_live_policy(repo: Path, trusted_policy: str) -> dict:
    """Read the editable directory without exposing its file through HTTP."""
    policy = json.loads((repo / LIVE_POLICY).read_text(encoding="utf-8"))
    members = policy.get("members")
    if not isinstance(members, list) or not members:
        raise ValueError("Live access policy has no members")
    ids = [member.get("member_id") for member in members]
    if len(ids) != len(set(ids)):
        raise ValueError("Live access policy has duplicate member IDs")
    for member in members:
        if not all(
            isinstance(member.get(key), str) and member[key]
            for key in ("member_id", "display_name", "role")
        ):
            raise ValueError("Every policy member needs an ID, name, and role")
        if member["role"] not in SUPPORTED_ROLES:
            raise ValueError(f"Unsupported role: {member['role']}")
        if member["member_id"] not in {"user-001", "user-002", "user-003"} and not re.fullmatch(
            r"[a-z_]+\d{3}", member["member_id"]
        ):
            raise ValueError(f"New member ID must use role<number>: {member['member_id']}")
        if member.get("administrator", False) and member["role"] != "administrator":
            raise ValueError("Administrator status conflicts with role")
        if member["role"] == "administrator" and not member.get("administrator"):
            raise ValueError("Administrator role requires administrator status")
    frozen_roles = dict(
        re.findall(r"\b(user-\d{3})\s+as\s+(engineering|analyst)\b", trusted_policy)
    )
    indexed = {member["member_id"]: member for member in members}
    for member_id, role in frozen_roles.items():
        if indexed.get(member_id, {}).get("role") != role:
            raise ValueError(f"Live policy must preserve benchmark role for {member_id}")
    if not frozen_roles:
        raise ValueError("Benchmark policy has no recognized members")
    return policy
