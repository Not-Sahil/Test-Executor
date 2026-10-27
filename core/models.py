from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Sequence


class TargetType(str, Enum):
    """The logical role of a discovered or configured testing target."""
    APPLICATION = "APPLICATION"
    LOGIN_PAGE = "LOGIN_PAGE"
    IDENTITY_PROVIDER = "IDENTITY_PROVIDER"
    CALLBACK = "CALLBACK"
    PROTECTED_RESOURCE = "PROTECTED_RESOURCE"


class ScopeStatus(str, Enum):
    """Scope validation verdict for an origin or URL."""
    IN_SCOPE = "IN_SCOPE"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"
    EXCLUDED = "EXCLUDED"


class AuthProtocolHint(str, Enum):
    """Identified candidate authentication flow architecture."""
    TRADITIONAL_FORM = "traditional_form"
    CENTRALIZED_IDP = "centralized_idp"
    OIDC_AUTHORIZATION_CODE = "oidc_authorization_code"
    OAUTH2_AUTHORIZATION_FLOW = "oauth2_authorization_flow"
    SAML_SSO = "saml_sso"
    SINGLE_SIGN_ON = "single_sign_on"
    UNKNOWN_OR_UNRESOLVED = "unknown_or_unresolved"


@dataclass
class AuthFlowMetadata:
    """Metadata describing the observed authentication flow and protocol hints."""
    protocol_hint: str = AuthProtocolHint.UNKNOWN_OR_UNRESOLVED.value
    confidence: str = "low"  # low, medium, high
    evidence: list[str] = field(default_factory=list)
    confirmed: bool = False
    idp_host: str | None = None
    authorization_endpoint: str | None = None
    token_endpoint: str | None = None
    callback_url: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "protocol_hint": self.protocol_hint,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "confirmed": self.confirmed,
            "idp_host": self.idp_host,
            "authorization_endpoint": self.authorization_endpoint,
            "token_endpoint": self.token_endpoint,
            "callback_url": self.callback_url,
        }


@dataclass
class LoginFormControls:
    """Discovered HTML/DOM authentication controls."""
    has_form: bool = False
    action_url: str = ""
    method: str = "POST"
    username_field: str | None = None
    password_field: str | None = None
    submit_button: str | None = None
    captcha_detected: bool = False
    captcha_indicator: str | None = None
    mfa_detected: bool = False
    remember_me_detected: bool = False
    password_reset_detected: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "has_form": self.has_form,
            "action_url": self.action_url,
            "method": self.method,
            "username_field": self.username_field,
            "password_field": self.password_field,
            "submit_button": self.submit_button,
            "captcha_detected": self.captcha_detected,
            "captcha_indicator": self.captcha_indicator,
            "mfa_detected": self.mfa_detected,
            "remember_me_detected": self.remember_me_detected,
            "password_reset_detected": self.password_reset_detected,
        }


@dataclass
class DiscoveredTargetModel:
    """Complete inventory of discovered targets and origin scopes for an assessment."""
    original_url: str
    application_origin: str
    login_url: str | None = None
    login_origin: str | None = None
    identity_provider_origin: str | None = None
    callback_url: str | None = None
    callback_origin: str | None = None
    protected_resource_url: str | None = None
    additional_in_scope_origins: list[str] = field(default_factory=list)
    scope_map: dict[str, str] = field(default_factory=dict)
    auth_flow: AuthFlowMetadata = field(default_factory=AuthFlowMetadata)
    login_controls: LoginFormControls = field(default_factory=LoginFormControls)
    redirect_chain: list[str] = field(default_factory=list)
    spa_fallback_detected: bool = False
    waf_detected: bool = False
    discovery_evidence: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "original_url": self.original_url,
            "application_origin": self.application_origin,
            "login_url": self.login_url,
            "login_origin": self.login_origin,
            "identity_provider_origin": self.identity_provider_origin,
            "callback_url": self.callback_url,
            "callback_origin": self.callback_origin,
            "protected_resource_url": self.protected_resource_url,
            "additional_in_scope_origins": self.additional_in_scope_origins,
            "scope": self.scope_map,
            "authentication_flow": self.auth_flow.as_dict() if hasattr(self.auth_flow, "as_dict") else self.auth_flow,
            "login_controls": self.login_controls.as_dict() if hasattr(self.login_controls, "as_dict") else self.login_controls,
            "redirect_chain": self.redirect_chain,
            "spa_fallback_detected": self.spa_fallback_detected,
            "waf_detected": self.waf_detected,
            "discovery_evidence": self.discovery_evidence,
        }


# TargetInventory is an alias for DiscoveredTargetModel
TargetInventory = DiscoveredTargetModel


@dataclass
class ScanResult:
    """Shared structured result used by every security testcase."""
    key: str
    name: str
    status: str
    summary: str
    raw_output: str = ""
    evidence: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)
    execution_status: str | None = None
    assessment_status: str | None = None
    target_resolution_status: str | None = None
    resolved_target: str | None = None

    def as_dict(self) -> dict[str, Any]:
        data = {
            "key": self.key,
            "name": self.name,
            "status": self.status,
            "summary": self.summary,
            "raw_output": self.raw_output,
            "evidence": self.evidence,
            "details": self.details,
        }
        if self.execution_status is not None:
            data["execution_status"] = self.execution_status
        if self.assessment_status is not None:
            data["assessment_status"] = self.assessment_status
        if self.target_resolution_status is not None:
            data["target_resolution_status"] = self.target_resolution_status
        if self.resolved_target is not None:
            data["resolved_target"] = self.resolved_target
        return data
