"""
Approval Token Manager for Active Directory MCP Server.
Implements secure write confirmation flow with expiration and single-use enforcement.
"""

import hashlib
import json
import secrets
import time
from dataclasses import dataclass
from threading import Lock
from typing import Any, Dict


@dataclass
class PendingApproval:
    token: str
    tool_name: str
    params: Dict[str, Any]
    target_object: str
    created_at: float
    expires_at: float
    description: str


class ApprovalManager:
    """Thread-safe manager for operation approval tokens."""

    def __init__(self, ttl_seconds: int = 300):
        self.ttl_seconds = ttl_seconds
        self._pending: Dict[str, PendingApproval] = {}
        self._lock = Lock()

    def generate_token(
        self,
        tool_name: str,
        params: Dict[str, Any],
        target_object: str,
        description: str,
    ) -> PendingApproval:
        """Create a new time-bound single-use confirmation token."""
        now = time.time()
        expires_at = now + self.ttl_seconds

        # Sanitize parameters (exclude existing tokens)
        sanitized = {k: v for k, v in params.items() if k not in ("confirmation_token", "dry_run")}
        raw_seed = f"{tool_name}:{target_object}:{json.dumps(sanitized, sort_keys=True)}:{now}:{secrets.token_hex(8)}"
        token = "CONFIRM-" + hashlib.sha256(raw_seed.encode("utf-8")).hexdigest()[:16].upper()

        approval = PendingApproval(
            token=token,
            tool_name=tool_name,
            params=sanitized,
            target_object=target_object,
            created_at=now,
            expires_at=expires_at,
            description=description,
        )

        with self._lock:
            # Purge expired tokens
            self._purge_expired()
            self._pending[token] = approval

        return approval

    def validate_and_consume(
        self,
        token: str,
        tool_name: str,
        params: Dict[str, Any],
    ) -> bool:
        """Validate token and consume it if valid. Single-use only."""
        with self._lock:
            self._purge_expired()
            approval = self._pending.get(token)
            if not approval:
                return False

            # Tool name must match exactly
            if approval.tool_name != tool_name:
                return False

            # Parameters must match
            current_sanitized = {k: v for k, v in params.items() if k not in ("confirmation_token", "dry_run")}
            if approval.params != current_sanitized:
                return False

            # Token consumed (single-use)
            del self._pending[token]
            return True

    def _purge_expired(self) -> None:
        """Remove expired tokens from store."""
        now = time.time()
        expired = [k for k, v in self._pending.items() if v.expires_at < now]
        for k in expired:
            del self._pending[k]


approval_manager = ApprovalManager()
