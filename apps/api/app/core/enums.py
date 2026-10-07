import enum


class Role(str, enum.Enum):
    ADMIN = "ADMIN"
    INFRA = "INFRA"
    SECURITY = "SECURITY"
    OPERATOR = "OPERATOR"
    VIEWER = "VIEWER"
    AUDITOR = "AUDITOR"


class AssetType(str, enum.Enum):
    SERVER = "SERVER"
    WEBSITE = "WEBSITE"
    # Planned asset types (PRD section 7); not implemented in Phase 1.
    DOMAIN = "DOMAIN"
    VM = "VM"
    CONTAINER = "CONTAINER"
    DATABASE = "DATABASE"
    STORAGE = "STORAGE"
    CLOUD_RESOURCE = "CLOUD_RESOURCE"


class AssetStatus(str, enum.Enum):
    UNKNOWN = "UNKNOWN"  # not assessed yet
    GREEN = "GREEN"
    YELLOW = "YELLOW"
    RED = "RED"


class Criticality(str, enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Severity(str, enum.Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RiskLevel(str, enum.Enum):
    SAFE = "SAFE"
    LOW = "LOW"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ConnectivityStatus(str, enum.Enum):
    UNKNOWN = "UNKNOWN"
    PENDING = "PENDING"
    OK = "OK"
    FAILED = "FAILED"
    HOST_KEY_MISMATCH = "HOST_KEY_MISMATCH"


class CredentialKind(str, enum.Enum):
    SSH_PRIVATE_KEY = "SSH_PRIVATE_KEY"
    SSH_PASSWORD = "SSH_PASSWORD"
    API_KEY = "API_KEY"


class AuditResult(str, enum.Enum):
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    DENIED = "DENIED"


class AssessmentState(str, enum.Enum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class CheckStatus(str, enum.Enum):
    PASS = "PASS"
    WARNING = "WARNING"
    FAIL = "FAIL"
    ERROR = "ERROR"  # the check itself could not run
    SKIPPED = "SKIPPED"  # not applicable / prerequisite missing


class FindingStatus(str, enum.Enum):
    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class FindingCategory(str, enum.Enum):
    CONNECTIVITY = "CONNECTIVITY"
    SYSTEM = "SYSTEM"
    STORAGE = "STORAGE"
    SERVICE = "SERVICE"
    NETWORK = "NETWORK"
    WEB = "WEB"
    SSL = "SSL"
    MALWARE = "MALWARE"
    CONFIGURATION = "CONFIGURATION"
    VULNERABILITY = "VULNERABILITY"
    BACKUP = "BACKUP"
    SECURITY_EVENT = "SECURITY_EVENT"  # SIEM alerts (Wazuh)
    FIM = "FIM"  # file integrity monitoring


class AIProviderKind(str, enum.Enum):
    OPENAI_COMPATIBLE = "OPENAI_COMPATIBLE"
    ANTHROPIC = "ANTHROPIC"


class ScheduleFrequency(str, enum.Enum):
    HOURLY = "HOURLY"
    DAILY = "DAILY"
    WEEKLY = "WEEKLY"


class ScheduleTarget(str, enum.Enum):
    ALL_WEBSITES = "ALL_WEBSITES"
    ALL_SERVERS = "ALL_SERVERS"
    ALL_ASSETS = "ALL_ASSETS"
    SELECTED = "SELECTED"


class RunState(str, enum.Enum):
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class MemoryKind(str, enum.Enum):
    ASSET = "ASSET"  # permanent facts about the asset
    OPERATIONAL = "OPERATIONAL"  # history: migrations, disk-full incidents, known issues
    SECURITY = "SECURITY"  # past incidents, IOCs, accepted false positives


class ActionKind(str, enum.Enum):
    QUARANTINE_FILE = "QUARANTINE_FILE"
    RESTORE_QUARANTINE = "RESTORE_QUARANTINE"
    RESTRICT_FILE = "RESTRICT_FILE"
    RESTORE_PERMISSIONS = "RESTORE_PERMISSIONS"
    RESTART_SERVICE = "RESTART_SERVICE"


class ActionState(str, enum.Enum):
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    REJECTED = "REJECTED"
    CANCELLED = "CANCELLED"


class BackupState(str, enum.Enum):
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"


class JobKind(str, enum.Enum):
    ASSESSMENT = "ASSESSMENT"
    BACKUP = "BACKUP"


class ChannelKind(str, enum.Enum):
    EMAIL = "EMAIL"
    WEBHOOK = "WEBHOOK"
    TELEGRAM = "TELEGRAM"


class DeliveryState(str, enum.Enum):
    PENDING = "PENDING"
    SENT = "SENT"
    FAILED = "FAILED"
