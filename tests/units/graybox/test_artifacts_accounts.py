"""Tests for Gray-Box Knowledge & Artifact Manager and Account & Role Manager."""
import json
import pytest

from graybox.accounts import GrayBoxAccountManager, TestAccount
from graybox.artifacts import GrayBoxArtifactManager, redact_text_secrets
from graybox.models import AccountRole, ArtifactType


def test_artifact_manager_add_and_query():
    am = GrayBoxArtifactManager()
    assert not am.has_artifact(ArtifactType.OPENAPI_SPEC)

    sample_openapi = json.dumps({
        "openapi": "3.0.0",
        "paths": {
            "/api/v1/users": {"get": {"summary": "List users"}},
            "/api/v1/auth/login": {"post": {"summary": "Authenticate"}},
            "/api/v1/admin/settings": {"get": {"summary": "Admin settings"}},
        }
    })

    art = am.add_artifact(
        artifact_type=ArtifactType.OPENAPI_SPEC,
        name="test_swagger.json",
        content=sample_openapi,
    )

    assert am.has_artifact(ArtifactType.OPENAPI_SPEC)
    assert len(am.get_artifacts(ArtifactType.OPENAPI_SPEC)) == 1

    # Test OpenAPI endpoint extraction
    endpoints = am.get_openapi_endpoints()
    assert "/api/v1/users" in endpoints
    assert "/api/v1/auth/login" in endpoints
    assert "/api/v1/admin/settings" in endpoints


def test_artifact_secret_redaction():
    am = GrayBoxArtifactManager()
    am.add_artifact(
        artifact_type=ArtifactType.SOURCE_CODE,
        name="config.py",
        content="SECRET_KEY = 'super_secret_master_token_12345'\nDB_PASSWORD = 'very_secret_db_pass!'",
    )

    redacted = am.get_redacted_artifacts()
    assert len(redacted) == 1
    content = redacted[0].content
    assert "super_secret_master_token_12345" not in content
    assert "very_secret_db_pass!" not in content
    assert "[REDACTED]" in content


def test_redact_text_secrets_utility():
    raw1 = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"
    safe1 = redact_text_secrets(raw1)
    assert "eyJhbGci" not in safe1
    assert "[REDACTED]" in safe1

    raw2 = "db_connection_string: postgresql://admin:secretPass123@db.prod.internal:5432/main"
    safe2 = redact_text_secrets(raw2)
    assert "secretPass123" not in safe2


def test_account_manager_roles_and_token_redaction():
    accm = GrayBoxAccountManager()
    assert accm.has_role(AccountRole.ANONYMOUS)
    assert not accm.has_role(AccountRole.USER_A)
    assert not accm.has_role(AccountRole.ADMINISTRATOR)

    # Add User A
    accm.add_account(TestAccount(
        role=AccountRole.USER_A,
        username="alice",
        password="AliceSecretPassword!99",
        bearer_token="alice_jwt_bearer_token",
    ))

    assert accm.has_role(AccountRole.USER_A)
    acc = accm.get_account_for_role(AccountRole.USER_A)
    assert acc is not None
    assert acc.username == "alice"

    # Redacted list
    redacted_accounts = accm.get_redacted_accounts()
    alice_redacted = [a for a in redacted_accounts if a["role"] == AccountRole.USER_A.value][0]
    assert alice_redacted["username"] == "alice"
    assert alice_redacted["password"] == "[REDACTED]"
    assert alice_redacted["bearer_token"] == "[REDACTED]"
