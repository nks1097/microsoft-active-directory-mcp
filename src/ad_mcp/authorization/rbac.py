"""
Authorization and RBAC engine for Active Directory MCP Server.
"""

from typing import Any, Dict, Optional, Tuple

from ad_mcp.authorization.approvals import approval_manager
from ad_mcp.authorization.guardrails import is_critical_ad_object
from ad_mcp.authorization.modes import ActionType, get_tool_action_type
from ad_mcp.config import OperationMode, settings
from ad_mcp.models.response import ToolResponse


class AuthorizationEngine:
    """Evaluates whether an operation is permitted under active mode and security policies."""

    @staticmethod
    def authorize_execution(
        tool_name: str,
        params: Dict[str, Any],
        target_object: Optional[str] = None,
    ) -> Tuple[bool, Optional[ToolResponse]]:
        """
        Check if tool execution is authorized.
        Returns:
            (is_authorized, response_if_blocked)
        """
        action_type = get_tool_action_type(tool_name)
        mode = settings.mcp_mode

        # 1. READ operations are always allowed in all modes
        if action_type == ActionType.READ:
            return True, None

        # 2. Check critical object protection
        target = target_object or str(
            params.get("identity") or params.get("distinguished_name") or params.get("name") or ""
        )
        if target and is_critical_ad_object(target):
            if action_type == ActionType.DESTRUCTIVE or not settings.protect_critical_objects:
                if settings.protect_critical_objects:
                    return False, ToolResponse(
                        success=False,
                        error=f"Operation on protected critical AD object '{target}' is blocked by security policy.",
                        error_code="CRITICAL_OBJECT_PROTECTED",
                        mode=mode.value,
                    )

        # 3. Check READ_ONLY mode
        if mode == OperationMode.READ_ONLY:
            return False, ToolResponse(
                success=False,
                error=(
                    f"Tool '{tool_name}' performs {action_type.value} actions, but the server is running in READ_ONLY mode. "
                    "To enable write operations, set AD_MCP_MODE=WRITE_APPROVAL or AD_MCP_MODE=FULL_ADMIN."
                ),
                error_code="MODE_READ_ONLY",
                mode=mode.value,
            )

        # 4. Check Dry-Run requested by caller
        if params.get("dry_run") is True:
            return False, ToolResponse(
                success=True,
                dry_run=True,
                data={
                    "status": "SIMULATION_ONLY",
                    "tool": tool_name,
                    "target": target,
                    "parameters": {k: v for k, v in params.items() if k not in ("password", "confirmation_token")},
                    "message": "Dry-run execution completed. No changes were made to Active Directory.",
                },
                mode=mode.value,
            )

        # 5. Check Destructive Operations Policy
        if (
            action_type == ActionType.DESTRUCTIVE
            and not settings.allow_destructive_operations
            and mode != OperationMode.FULL_ADMIN
        ):
            # Requires explicit confirmation even in WRITE_APPROVAL
            token = params.get("confirmation_token")
            if not token:
                pending = approval_manager.generate_token(
                    tool_name=tool_name,
                    params=params,
                    target_object=target,
                    description=f"Destructive action: {tool_name} on '{target}'",
                )
                return False, ToolResponse(
                    success=False,
                    requires_approval=True,
                    confirmation_token=pending.token,
                    action_preview={
                        "tool": tool_name,
                        "action": action_type.value,
                        "target": target,
                        "description": pending.description,
                        "expires_in_seconds": settings.approval_token_ttl_seconds,
                    },
                    error="Destructive operation requires explicit confirmation token.",
                    error_code="APPROVAL_REQUIRED",
                    mode=mode.value,
                )

        # 6. Check WRITE_APPROVAL mode
        if mode == OperationMode.WRITE_APPROVAL:
            token = params.get("confirmation_token")
            if not token:
                pending = approval_manager.generate_token(
                    tool_name=tool_name,
                    params=params,
                    target_object=target,
                    description=f"Administrative action: {tool_name} on '{target}'",
                )
                return False, ToolResponse(
                    success=False,
                    requires_approval=True,
                    confirmation_token=pending.token,
                    action_preview={
                        "tool": tool_name,
                        "action": action_type.value,
                        "target": target,
                        "description": pending.description,
                        "parameters": {k: v for k, v in params.items() if k not in ("password", "confirmation_token")},
                        "expires_in_seconds": settings.approval_token_ttl_seconds,
                    },
                    error=(
                        f"Action '{tool_name}' requires approval in WRITE_APPROVAL mode. "
                        f"Review the preview and re-execute passing confirmation_token='{pending.token}'."
                    ),
                    error_code="APPROVAL_REQUIRED",
                    mode=mode.value,
                )
            # Token provided: validate & consume
            if not approval_manager.validate_and_consume(token, tool_name, params):
                return False, ToolResponse(
                    success=False,
                    error="Invalid or expired confirmation token. Approval tokens are single-use and expire in 5 minutes.",
                    error_code="INVALID_TOKEN",
                    mode=mode.value,
                )

        # 7. FULL_ADMIN mode allows execution directly
        return True, None


auth_engine = AuthorizationEngine()
