"""
Unit tests for authorization engine, modes, approval tokens, and dry-run execution.
"""

from ad_mcp.authorization.rbac import auth_engine
from ad_mcp.config import OperationMode, settings


def test_read_operations_allowed_in_read_only_mode():
    settings.mcp_mode = OperationMode.READ_ONLY
    allowed, resp = auth_engine.authorize_execution("ad_get_user", {"identity": "jdoe"})
    assert allowed is True
    assert resp is None


def test_write_operations_blocked_in_read_only_mode():
    settings.mcp_mode = OperationMode.READ_ONLY
    allowed, resp = auth_engine.authorize_execution(
        "ad_create_user", {"sam_account_name": "newuser", "path": "OU=Test"}
    )
    assert allowed is False
    assert resp is not None
    assert resp.error_code == "MODE_READ_ONLY"


def test_write_approval_mode_requires_token():
    settings.mcp_mode = OperationMode.WRITE_APPROVAL
    params = {"sam_account_name": "testuser", "path": "OU=Dev,DC=test,DC=local"}
    allowed, resp = auth_engine.authorize_execution("ad_create_user", params, target_object="testuser")

    assert allowed is False
    assert resp is not None
    assert resp.requires_approval is True
    assert resp.confirmation_token is not None
    assert resp.confirmation_token.startswith("CONFIRM-")

    # Now attempt with the token provided
    params_with_token = dict(params)
    params_with_token["confirmation_token"] = resp.confirmation_token
    allowed_second, resp_second = auth_engine.authorize_execution(
        "ad_create_user", params_with_token, target_object="testuser"
    )
    assert allowed_second is True
    assert resp_second is None

    # Reusing the consumed token must fail (single-use)
    allowed_third, resp_third = auth_engine.authorize_execution(
        "ad_create_user", params_with_token, target_object="testuser"
    )
    assert allowed_third is False
    assert resp_third.error_code == "INVALID_TOKEN"


def test_dry_run_intercepts_without_modifications():
    settings.mcp_mode = OperationMode.WRITE_APPROVAL
    params = {"sam_account_name": "simulate_user", "path": "OU=Test", "dry_run": True}
    allowed, resp = auth_engine.authorize_execution("ad_create_user", params, target_object="simulate_user")

    assert allowed is False
    assert resp is not None
    assert resp.dry_run is True
    assert resp.data["status"] == "SIMULATION_ONLY"


def test_full_admin_mode_allows_direct_writes():
    settings.mcp_mode = OperationMode.FULL_ADMIN
    params = {"sam_account_name": "direct_user", "path": "OU=Test"}
    allowed, resp = auth_engine.authorize_execution("ad_create_user", params, target_object="direct_user")
    assert allowed is True
    assert resp is None
