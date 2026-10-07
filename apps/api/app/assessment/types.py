from dataclasses import dataclass, field
from typing import Any, Protocol

from app.core.enums import CheckStatus, FindingCategory, Severity
from app.services.ssh_client import CommandResult

MAX_EVIDENCE_CHARS = 4000


class Runner(Protocol):
    """Anything that can run a fixed command on the target (SSHSession, or a fake in tests)."""

    async def run(self, command: str, *, input: str | None = None, timeout: int | None = None,
                  max_output_bytes: int | None = None) -> CommandResult: ...


@dataclass
class CheckResult:
    """Standardised check result (PRD 40). WARNING/FAIL results become findings."""

    check: str
    category: FindingCategory
    status: CheckStatus
    title: str
    severity: Severity = Severity.INFO
    value: str | None = None
    target: str | None = None
    evidence: Any = field(default_factory=dict)
    recommendation: str | None = None
    description: str | None = None
    confidence: float = 1.0
    duration_ms: int | None = None

    @property
    def is_issue(self) -> bool:
        return self.status in (CheckStatus.WARNING, CheckStatus.FAIL)


def clip(text: str | None, limit: int = MAX_EVIDENCE_CHARS) -> str:
    """Keep evidence bounded; server output and web content are untrusted and unbounded."""
    if not text:
        return ""
    return text if len(text) <= limit else text[:limit] + f"\n… [{len(text) - limit} karakter dipotong]"


def passed(check: str, category: FindingCategory, title: str, **kw) -> CheckResult:
    return CheckResult(check, category, CheckStatus.PASS, title, **kw)


def issue(check: str, category: FindingCategory, title: str, severity: Severity, **kw) -> CheckResult:
    status = CheckStatus.FAIL if severity in (Severity.HIGH, Severity.CRITICAL) else CheckStatus.WARNING
    return CheckResult(check, category, status, title, severity=severity, **kw)


def error(check: str, category: FindingCategory, message: str, **kw) -> CheckResult:
    return CheckResult(check, category, CheckStatus.ERROR, f"Check gagal dijalankan: {message}"[:255], **kw)


def skipped(check: str, category: FindingCategory, reason: str, **kw) -> CheckResult:
    return CheckResult(check, category, CheckStatus.SKIPPED, reason[:255], **kw)
