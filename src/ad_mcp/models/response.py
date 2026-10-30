"""
Standard response models for the Active Directory MCP Server.
"""

from typing import Any, Dict, List, Optional
from uuid import uuid4

from pydantic import BaseModel, Field


class ToolResponse(BaseModel):
    """Unified response format for all 100 AD MCP tools."""

    success: bool = Field(
        ...,
        description="Whether the requested operation succeeded",
    )
    data: Optional[Any] = Field(
        default=None,
        description="Structured payload containing results or entity details",
    )
    error: Optional[str] = Field(
        default=None,
        description="Human-readable error message if operation failed",
    )
    error_code: Optional[str] = Field(
        default=None,
        description="Standardized error code (e.g. AUTH_FAILED, PERMISSION_DENIED, OBJECT_NOT_FOUND)",
    )
    warnings: List[str] = Field(
        default_factory=list,
        description="Operational warnings, deprecations or security notes",
    )
    execution_time_ms: float = Field(
        default=0.0,
        description="Execution duration in milliseconds",
    )
    correlation_id: str = Field(
        default_factory=lambda: str(uuid4()),
        description="Unique correlation ID for tracing and audit logging",
    )
    mode: str = Field(
        default="READ_ONLY",
        description="Active operating mode at time of execution",
    )
    dry_run: bool = Field(
        default=False,
        description="Whether this execution was a simulation (dry run)",
    )
    requires_approval: bool = Field(
        default=False,
        description="True if operation was intercepted because mode requires explicit confirmation",
    )
    confirmation_token: Optional[str] = Field(
        default=None,
        description="Token to submit along with tool call to confirm pending write",
    )
    action_preview: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Preview of changes when approval or dry-run is triggered",
    )

    def to_mcp_content(self) -> Dict[str, Any]:
        """Serialize into clean dictionary for MCP response."""
        return self.model_dump(exclude_none=True)
