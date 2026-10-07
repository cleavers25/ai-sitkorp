import enum

from app.core.enums import Role


class Permission(str, enum.Enum):
    DASHBOARD_VIEW = "dashboard:view"
    ASSET_VIEW = "asset:view"
    ASSET_MANAGE = "asset:manage"
    CREDENTIAL_VIEW = "credential:view"
    CREDENTIAL_MANAGE = "credential:manage"
    TOOL_RUN_SAFE = "tool:run_safe"
    ASSESSMENT_RUN = "assessment:run"
    FINDING_TRIAGE = "finding:triage"  # acknowledge / mark false positive
    AUDIT_VIEW = "audit:view"
    USER_MANAGE = "user:manage"
    AI_CONFIG = "ai:config"
    MEMORY_MANAGE = "memory:manage"
    ACTION_REQUEST = "action:request"  # ask for a remediation action
    ACTION_APPROVE = "action:approve"  # approve/reject remediation (PRD 25)
    BACKUP_RUN = "backup:run"
    BACKUP_DOWNLOAD = "backup:download"  # archives can contain secrets (.env, wp-config)
    NOTIFY_MANAGE = "notify:manage"  # notification channels (SMTP, webhook, Telegram)
    INTEGRATION_MANAGE = "integration:manage"  # Wazuh connection settings


P = Permission

# Derived from PRD section 44. Secret *values* are never readable by any role;
# CREDENTIAL_VIEW only exposes metadata (name, username, fingerprint).
ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.ADMIN: frozenset(Permission),
    Role.INFRA: frozenset({
        P.DASHBOARD_VIEW, P.ASSET_VIEW, P.ASSET_MANAGE, P.CREDENTIAL_VIEW,
        P.CREDENTIAL_MANAGE, P.TOOL_RUN_SAFE, P.ASSESSMENT_RUN, P.FINDING_TRIAGE,
        P.MEMORY_MANAGE, P.ACTION_REQUEST, P.BACKUP_RUN,
    }),
    Role.SECURITY: frozenset({
        P.DASHBOARD_VIEW, P.ASSET_VIEW, P.TOOL_RUN_SAFE, P.ASSESSMENT_RUN,
        P.FINDING_TRIAGE, P.AUDIT_VIEW, P.AI_CONFIG,
        P.MEMORY_MANAGE, P.ACTION_REQUEST, P.ACTION_APPROVE, P.NOTIFY_MANAGE, P.INTEGRATION_MANAGE,
    }),
    Role.OPERATOR: frozenset({
        P.DASHBOARD_VIEW, P.ASSET_VIEW, P.TOOL_RUN_SAFE, P.ASSESSMENT_RUN,
    }),
    Role.VIEWER: frozenset({P.DASHBOARD_VIEW, P.ASSET_VIEW}),
    Role.AUDITOR: frozenset({P.DASHBOARD_VIEW, P.ASSET_VIEW, P.AUDIT_VIEW}),
}


def has_permission(role: Role, permission: Permission) -> bool:
    return permission in ROLE_PERMISSIONS.get(role, frozenset())


def permissions_for(role: Role) -> list[str]:
    return sorted(p.value for p in ROLE_PERMISSIONS.get(role, frozenset()))
