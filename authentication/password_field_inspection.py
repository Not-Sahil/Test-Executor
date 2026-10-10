from __future__ import annotations

from html.parser import HTMLParser
from typing import Any

from .password_validation_models import PasswordFieldRules


class _PasswordInputParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.fields: list[dict[str, Any]] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag.lower() != "input":
            return
        data = {str(k).lower(): (v or "") for k, v in attrs}
        if str(data.get("type", "text")).lower() != "password":
            return
        self.fields.append(data)


def inspect_password_field_rules(html: str) -> list[PasswordFieldRules]:
    parser = _PasswordInputParser()
    try:
        parser.feed(html or "")
        parser.close()
    except Exception:
        return []

    results: list[PasswordFieldRules] = []
    for field in parser.fields:
        evidence = [
            f"password_field name={field.get('name') or '(unnamed)'}",
            f"type={field.get('type') or 'password'}",
            f"required={bool(field.get('required'))}",
        ]
        minlength = None
        maxlength = None
        try:
            if str(field.get("minlength", "")).strip():
                minlength = int(field["minlength"])
        except (TypeError, ValueError):
            evidence.append("invalid minlength attribute")
        try:
            if str(field.get("maxlength", "")).strip():
                maxlength = int(field["maxlength"])
        except (TypeError, ValueError):
            evidence.append("invalid maxlength attribute")

        pattern = str(field.get("pattern") or "").strip() or None
        autocomplete = str(field.get("autocomplete") or "").strip().lower() or None
        if minlength is not None:
            evidence.append(f"minlength={minlength}")
        if maxlength is not None:
            evidence.append(f"maxlength={maxlength}")
        if pattern:
            evidence.append("pattern_present=true")
        if autocomplete:
            evidence.append(f"autocomplete={autocomplete}")

        results.append(
            PasswordFieldRules(
                found=True,
                input_type=str(field.get("type") or "password"),
                required=bool(field.get("required")),
                minlength=minlength,
                maxlength=maxlength,
                pattern=pattern,
                autocomplete=autocomplete,
                source="static_html",
                evidence=tuple(evidence),
            )
        )
    return results
