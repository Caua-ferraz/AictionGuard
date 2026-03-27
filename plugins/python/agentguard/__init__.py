"""
AgentGuard Python SDK

Lightweight client for checking actions against AgentGuard policies.

Usage:
    from agentguard import Guard

    guard = Guard("http://localhost:8080")
    result = guard.check("shell", command="rm -rf ./data")

    if result.allowed:
        execute(command)
    elif result.needs_approval:
        print(f"Approve at: {result.approval_url}")
    else:
        print(f"Blocked: {result.reason}")
"""

import json
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib import request, error


@dataclass
class CheckResult:
    """Result of a policy check."""
    decision: str
    reason: str
    matched_rule: str = ""
    approval_id: str = ""
    approval_url: str = ""

    @property
    def allowed(self) -> bool:
        return self.decision == "ALLOW"

    @property
    def denied(self) -> bool:
        return self.decision == "DENY"

    @property
    def needs_approval(self) -> bool:
        return self.decision == "REQUIRE_APPROVAL"


class Guard:
    """Client for the AgentGuard proxy."""

    def __init__(self, base_url: str = "http://localhost:8080", agent_id: str = ""):
        self.base_url = base_url.rstrip("/")
        self.agent_id = agent_id

    def check(
        self,
        scope: str,
        *,
        action: str = "",
        command: str = "",
        path: str = "",
        domain: str = "",
        url: str = "",
        meta: Optional[dict] = None,
    ) -> CheckResult:
        """Check an action against the policy.

        Args:
            scope: The rule scope (filesystem, shell, network, browser, cost, data)
            action: Action type (read, write, delete) — used with filesystem scope
            command: Shell command string — used with shell scope
            path: File path — used with filesystem scope
            domain: Target domain — used with network/browser scope
            url: Full URL — used with network scope
            meta: Additional metadata

        Returns:
            CheckResult with the policy decision
        """
        payload = {
            "scope": scope,
            "agent_id": self.agent_id,
        }
        if action:
            payload["action"] = action
        if command:
            payload["command"] = command
        if path:
            payload["path"] = path
        if domain:
            payload["domain"] = domain
        if url:
            payload["url"] = url
        if meta:
            payload["meta"] = meta

        data = json.dumps(payload).encode("utf-8")
        req = request.Request(
            f"{self.base_url}/v1/check",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with request.urlopen(req, timeout=5) as resp:
                body = json.loads(resp.read())
                return CheckResult(
                    decision=body.get("decision", "DENY"),
                    reason=body.get("reason", ""),
                    matched_rule=body.get("matched_rule", ""),
                    approval_id=body.get("approval_id", ""),
                    approval_url=body.get("approval_url", ""),
                )
        except error.URLError as e:
            # If AgentGuard is unreachable, default to deny (fail closed)
            return CheckResult(
                decision="DENY",
                reason=f"AgentGuard unreachable: {e}",
            )

    def approve(self, approval_id: str) -> bool:
        """Approve a pending action."""
        req = request.Request(
            f"{self.base_url}/v1/approve/{approval_id}",
            method="POST",
        )
        try:
            with request.urlopen(req, timeout=5):
                return True
        except error.URLError:
            return False

    def deny(self, approval_id: str) -> bool:
        """Deny a pending action."""
        req = request.Request(
            f"{self.base_url}/v1/deny/{approval_id}",
            method="POST",
        )
        try:
            with request.urlopen(req, timeout=5):
                return True
        except error.URLError:
            return False

    def wait_for_approval(self, approval_id: str, timeout: int = 300, poll_interval: int = 2) -> CheckResult:
        """Block until a pending action is approved or denied (or timeout)."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            # Poll the status endpoint for resolution
            req = request.Request(
                f"{self.base_url}/v1/status/{approval_id}",
                method="GET",
            )
            try:
                with request.urlopen(req, timeout=5) as resp:
                    body = json.loads(resp.read())
                    if body.get("status") == "resolved" and body.get("decision") in ("ALLOW", "DENY"):
                        return CheckResult(
                            decision=body["decision"],
                            reason=body.get("reason", "resolved"),
                        )
            except error.URLError:
                pass
            time.sleep(poll_interval)

        return CheckResult(decision="DENY", reason="Approval timed out")


# Convenience decorator for guarding functions
def guarded(scope: str, guard: Optional[Guard] = None, **check_kwargs):
    """Decorator that checks policy before executing a function.

    Usage:
        guard = Guard("http://localhost:8080")

        @guarded("shell", guard=guard)
        def run_command(cmd: str):
            os.system(cmd)
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            g = guard or Guard()
            # Try to extract meaningful info from args
            cmd = args[0] if args else kwargs.get("command", kwargs.get("cmd", ""))
            result = g.check(scope, command=str(cmd), **check_kwargs)
            if result.allowed:
                return func(*args, **kwargs)
            elif result.needs_approval:
                raise PermissionError(
                    f"Action requires approval. Approve at: {result.approval_url}"
                )
            else:
                raise PermissionError(f"Action denied by AgentGuard: {result.reason}")
        return wrapper
    return decorator
