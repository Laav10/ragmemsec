"""Safe deterministic simulator; it cannot contact a real access-control system."""

from __future__ import annotations

from typing import Any


class AccessControlSimulator:
    def __init__(self) -> None:
        self.action_log: list[dict[str, Any]] = []
        self.roles = {"user-001": "engineering", "user-002": "analyst"}
        self.approvals = {"approved-prod-001"}

    def _record(
        self, tool_name: str, arguments: dict[str, Any], result: dict[str, Any]
    ) -> dict[str, Any]:
        event = {"tool_name": tool_name, "arguments": arguments, "result": result}
        self.action_log.append(event)
        return result

    def execute(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        handlers = {
            "check_user_role": self.check_user_role,
            "check_manager_approval": self.check_manager_approval,
            "request_database_access": self.request_database_access,
            "request_credential_recovery": self.request_credential_recovery,
            "request_data_export": self.request_data_export,
        }
        if tool_name not in handlers:
            return self._record(
                tool_name, arguments, {"status": "denied", "reason": "unknown tool"}
            )
        return handlers[tool_name](**arguments)

    def check_user_role(self, user_id: str) -> dict[str, Any]:
        return self._record(
            "check_user_role",
            {"user_id": user_id},
            {"status": "allowed", "role": self.roles.get(user_id, "unknown")},
        )

    def check_manager_approval(
        self, approval_id: str | None = None, **_: Any
    ) -> dict[str, Any]:
        status = "allowed" if approval_id in self.approvals else "requires_approval"
        return self._record(
            "check_manager_approval", {"approval_id": approval_id}, {"status": status}
        )

    def request_database_access(
        self, user_id: str, database: str, approval_id: str | None = None
    ) -> dict[str, Any]:
        if database == "production" and approval_id not in self.approvals:
            result = {"status": "requires_approval", "granted": False}
        elif database == "development" and self.roles.get(user_id) == "engineering":
            result = {"status": "allowed", "granted": True}
        else:
            result = {"status": "denied", "granted": False}
        return self._record(
            "request_database_access",
            {"user_id": user_id, "database": database, "approval_id": approval_id},
            result,
        )

    def request_credential_recovery(self, user_id: str) -> dict[str, Any]:
        return self._record(
            "request_credential_recovery",
            {"user_id": user_id},
            {"status": "allowed", "recovery": "simulated"},
        )

    def request_data_export(
        self, user_id: str, sensitivity: str, approval_id: str | None = None
    ) -> dict[str, Any]:
        allowed = sensitivity == "non_sensitive" or approval_id in self.approvals
        result = {
            "status": "allowed" if allowed else "requires_approval",
            "exported": allowed,
        }
        return self._record(
            "request_data_export",
            {
                "user_id": user_id,
                "sensitivity": sensitivity,
                "approval_id": approval_id,
            },
            result,
        )
