"""Central configuration loaded from environment variables."""
import os


class AuditConfig:
    """Read-only configuration resolved at import time from env vars."""

    model: str = os.environ.get("AUDIT_MODEL", "claude-opus-4-7")
    web_host: str = os.environ.get("AUDIT_WEB_HOST", "0.0.0.0")
    web_port: int = int(os.environ.get("AUDIT_WEB_PORT", "5000"))
    web_debug: bool = os.environ.get("AUDIT_WEB_DEBUG", "false").lower() == "true"
    max_upload_kb: int = int(os.environ.get("AUDIT_MAX_UPLOAD_KB", "512"))

    SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

    @classmethod
    def severity_rank(cls, severity: str) -> int:
        return cls.SEVERITY_ORDER.get(severity.upper(), 99)

    @classmethod
    def filter_by_min_severity(cls, findings: list, min_severity: str) -> list:
        threshold = cls.severity_rank(min_severity)
        return [f for f in findings if cls.severity_rank(f.severity) <= threshold]
