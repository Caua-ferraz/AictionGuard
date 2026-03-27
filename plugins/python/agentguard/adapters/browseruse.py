"""
AgentGuard browser-use Adapter

Wraps browser-use actions so navigation, clicks, and form inputs pass through
AgentGuard policy checks before execution.

Usage:
    from agentguard.adapters.browseruse import GuardedBrowser

    browser = GuardedBrowser(
        guard_url="http://localhost:8080",
        agent_id="my-browser-agent",
    )

    # Check before navigating
    result = browser.check_navigation("https://example.com")
    if result.allowed:
        await page.goto("https://example.com")
"""

from typing import Any, Optional
from urllib.parse import urlparse
from agentguard import Guard, CheckResult


class GuardedBrowser:
    """Policy-enforced wrapper for browser-use automation.

    browser-use exposes a Browser/BrowserContext that agents drive. This class
    provides guard methods that should be called before performing browser actions.
    It can also wrap a browser-use Browser instance to intercept calls automatically.
    """

    def __init__(
        self,
        guard: Optional[Guard] = None,
        guard_url: str = "http://localhost:8080",
        agent_id: str = "",
        browser: Any = None,
    ):
        self._guard = guard or Guard(guard_url, agent_id=agent_id)
        self._browser = browser

    def check_navigation(self, url: str) -> CheckResult:
        """Check if navigation to a URL is allowed by policy."""
        domain = ""
        try:
            parsed = urlparse(url)
            domain = parsed.hostname or ""
        except Exception:
            pass

        return self._guard.check("browser", url=url, domain=domain)

    def check_action(self, action: str, target: str = "", meta: Optional[dict] = None) -> CheckResult:
        """Check a browser action (click, type, etc.) against policy.

        Args:
            action: The action type (e.g., "click", "type", "screenshot")
            target: The target selector or URL
            meta: Additional context
        """
        return self._guard.check(
            "browser",
            command=f"{action} {target}".strip(),
            meta=meta,
        )

    def check_form_input(self, url: str, field_name: str, value: str) -> CheckResult:
        """Check if typing into a form field is allowed.

        This is useful for preventing PII or credential leakage into web forms.
        """
        domain = ""
        try:
            parsed = urlparse(url)
            domain = parsed.hostname or ""
        except Exception:
            pass

        return self._guard.check(
            "data",
            domain=domain,
            command=f"input:{field_name}",
            meta={"field": field_name, "url": url},
        )

    def wrap_page(self, page: Any) -> "GuardedPage":
        """Wrap a browser-use Page object with policy enforcement.

        Returns a GuardedPage that intercepts goto() and other navigation methods.
        """
        return GuardedPage(page, self._guard)


class GuardedPage:
    """Wraps a browser-use Page to enforce policies on navigation."""

    def __init__(self, page: Any, guard: Guard):
        self._page = page
        self._guard = guard

    async def goto(self, url: str, **kwargs) -> Any:
        """Navigate to a URL after policy check."""
        domain = ""
        try:
            parsed = urlparse(url)
            domain = parsed.hostname or ""
        except Exception:
            pass

        result = self._guard.check("browser", url=url, domain=domain)

        if result.allowed:
            return await self._page.goto(url, **kwargs)
        elif result.needs_approval:
            raise PermissionError(
                f"[AgentGuard] Navigation requires approval. "
                f"Approve at: {result.approval_url}"
            )
        else:
            raise PermissionError(
                f"[AgentGuard] Navigation denied: {result.reason}"
            )

    def __getattr__(self, name: str) -> Any:
        """Proxy all other attributes to the wrapped page."""
        return getattr(self._page, name)
