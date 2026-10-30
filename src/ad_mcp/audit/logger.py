"""
Structured JSON audit logging for Active Directory MCP Server.
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from ad_mcp.config import settings

# Sensitive parameter names that must be redacted in audit logs
REDACTED_KEYS = {"password", "secret", "confirmation_token", "hash", "key", "cert"}


class AuditLogger:
    """Writes immutable structured JSON audit events."""

    def __init__(self, log_path: Optional[str] = None):
        self.log_path = Path(log_path or settings.audit_log_file)
        self._ensure_log_dir()

    def _ensure_log_dir(self) -> None:
        try:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass

    def _mask_sensitive(self, data: Any) -> Any:
        """Recursively redact passwords and tokens from logged dictionaries."""
        if isinstance(data, dict):
            masked = {}
            for k, v in data.items():
                if any(red in k.lower() for red in REDACTED_KEYS):
                    masked[k] = "[REDACTED]"
                else:
                    masked[k] = self._mask_sensitive(v)
            return masked
        elif isinstance(data, list):
            return [self._mask_sensitive(item) for item in data]
        return data

    def log_event(
        self,
        tool_name: str,
        correlation_id: str,
        params: Dict[str, Any],
        success: bool,
        execution_time_ms: float,
        error: Optional[str] = None,
        warnings: Optional[list] = None,
        operator: Optional[str] = None,
    ) -> None:
        """Append an audit record in JSON Lines format."""
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "correlation_id": correlation_id,
            "tool_name": tool_name,
            "operator": operator or settings.username or "Anonymous/System",
            "server": settings.server,
            "domain": settings.domain,
            "mode": settings.mcp_mode.value,
            "success": success,
            "execution_time_ms": round(execution_time_ms, 2),
            "parameters": self._mask_sensitive(params),
            "error": error,
            "warnings": warnings or [],
        }

        line = json.dumps(event, ensure_ascii=False) + "\n"
        try:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(line)
        except Exception as e:
            logging.getLogger("ad_mcp.audit").error(f"Failed to write audit event: {e}")


audit_logger = AuditLogger()
