"""Controlled tool layer (PRD 23-24).

Every action against a managed server goes through a registered tool with fixed commands
and risk metadata. Nothing here accepts arbitrary shell input.
"""

from dataclasses import dataclass, field

from app.core.enums import RiskLevel
from app.core.rbac import Permission


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    risk_level: RiskLevel
    requires_approval: bool
    permission: Permission
    timeout: int
    rollback_available: bool = False
    audit_enabled: bool = True
    commands: tuple[str, ...] = field(default_factory=tuple)


CHECK_CONNECTIVITY = ToolSpec(
    name="check_connectivity",
    description="Verify SSH access and read basic OS information",
    risk_level=RiskLevel.SAFE,
    requires_approval=False,
    permission=Permission.TOOL_RUN_SAFE,
    timeout=60,
    commands=("uname -srm", "cat /etc/os-release"),
)

SERVER_ASSESSMENT = ToolSpec(
    name="server_assessment",
    description="Read-only health & security checks (load, memory, disk, services, ports, sshd, processes)",
    risk_level=RiskLevel.SAFE,
    requires_approval=False,
    permission=Permission.ASSESSMENT_RUN,
    timeout=600,
)

WEBSITE_ASSESSMENT = ToolSpec(
    name="website_assessment",
    description="HTTP/TLS/header/exposed-file/content checks plus document-root malware scan "
                "(grep heuristics, ClamAV, YARA). Read-only; YARA rules go to a mktemp file that is removed.",
    risk_level=RiskLevel.SAFE,
    requires_approval=False,
    permission=Permission.ASSESSMENT_RUN,
    timeout=3600,
)

TOOLS: dict[str, ToolSpec] = {t.name: t for t in (CHECK_CONNECTIVITY, SERVER_ASSESSMENT, WEBSITE_ASSESSMENT)}
