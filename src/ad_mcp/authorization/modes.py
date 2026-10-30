"""
Operation modes and tool classification for Active Directory MCP Server.
"""

from enum import Enum
from typing import Set


class ToolCategory(str, Enum):
    DOMAIN = "Domain & Domain Controllers"
    USERS = "Users"
    GROUPS = "Groups & Members"
    COMPUTERS = "Computers & Devices"
    OUS = "Organizational Units"
    GPOS = "Group Policy Objects"
    DNS = "DNS & Infrastructure"
    SECURITY = "Security & Audit"
    REPLICATION = "Replication, Health & Diagnostics"
    REPORTS = "Reports, Inventory & Automation"


class ActionType(str, Enum):
    READ = "READ"
    WRITE = "WRITE"
    DESTRUCTIVE = "DESTRUCTIVE"
    ACTION = "ACTION"


# Classification of destructive tools requiring confirmation
DESTRUCTIVE_TOOLS: Set[str] = {
    "ad_delete_user",
    "ad_delete_group",
    "ad_delete_computer",
    "ad_delete_ou",
    "ad_delete_gpo",
    "ad_delete_dns_record",
    "ad_reset_user_password",
}

# Classification of write tools
WRITE_TOOLS: Set[str] = {
    "ad_create_user",
    "ad_update_user",
    "ad_disable_user",
    "ad_enable_user",
    "ad_unlock_user",
    "ad_create_group",
    "ad_update_group",
    "ad_add_group_member",
    "ad_remove_group_member",
    "ad_create_computer",
    "ad_update_computer",
    "ad_disable_computer",
    "ad_enable_computer",
    "ad_move_computer",
    "ad_create_ou",
    "ad_update_ou",
    "ad_move_object",
    "ad_set_ou_protection",
    "ad_create_gpo",
    "ad_update_gpo",
    "ad_link_gpo",
    "ad_unlink_gpo",
    "ad_create_dns_record",
    "ad_update_dns_record",
    "ad_sync_replication",
} | DESTRUCTIVE_TOOLS


def get_tool_action_type(tool_name: str) -> ActionType:
    """Classify tool into READ, WRITE, or DESTRUCTIVE."""
    if tool_name in DESTRUCTIVE_TOOLS:
        return ActionType.DESTRUCTIVE
    if tool_name in WRITE_TOOLS:
        return ActionType.WRITE
    return ActionType.READ

