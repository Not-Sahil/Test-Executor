# TC01 — Autocomplete Security Test

## 1. Objective

Assess whether the application's login form exposes credential fields through unsafe or semantically incorrect browser autocomplete metadata, while avoiding the false-positive assumption that browser/password-manager autofill is inherently insecure.

The scanner evaluates both source HTML and the rendered DOM when Playwright is available.

## 2. In scope

1. Form-level `autocomplete`.
2. Username/email field `autocomplete`.
3. Password field `autocomplete`.
4. Effective field configuration after form-level inheritance.
5. Correct semantic login tokens: `username` and `current-password`.
6. Incorrect login token: `new-password`.
7. Unrelated sensitive-data tokens on credential fields.
8. Unknown/malformed autocomplete tokens.
9. Multiple login forms.
10. JavaScript-generated forms.
11. Forms inside browser frames.
12. Login-vs-registration/reset/change-password context.
13. SPA pages where the credential controls exist without a conventional `<form>`.
14. Evidence showing which source produced each observation.

## 3. Explicitly out of scope

- Browser memory extraction — TC07.
- Remember-me/session persistence — TC10.
- HTTP/HTTPS transport — TC08/TC09.
- Password strength/validation — TC05.
- Password storage, hashing, credential database controls.
- General HTTP caching policy unless another testcase explicitly covers it.

## 4. Browser/standards model

Modern browser behavior means `autocomplete="off"` should not be treated as a reliable control for disabling password-manager behavior. Correct semantic tokens such as `username` and `current-password` are preferred.

Therefore:

- `autocomplete="current-password"` on a login password field: expected.
- `autocomplete="username"` on a username field: expected.
- `autocomplete="new-password"` on registration/change/reset password fields: expected.
- `autocomplete="new-password"` on an ordinary sign-in password field: review finding.
- Missing autocomplete on login credential fields: informational/configuration observation, not automatically a vulnerability.
- `autocomplete="on"`: not automatically a vulnerability.
- `autocomplete="off"`: not automatically a vulnerability.
- Unrelated tokens such as payment-card tokens on username/password fields: review because the field semantics are inconsistent and could cause unintended autofill behavior.

## 5. Discovery strategy

### Phase A — Static HTTP

Fetch the configured login page, follow redirects, verify an HTML/XHTML response, and parse:

- all forms
- form action/method
- form autocomplete
- all inputs
- input type/name/id/ARIA/placeholder
- input autocomplete
- hidden/disabled/read-only state

### Phase B — Rendered browser DOM

When Playwright is available:

- load the login page
- wait for DOM content and a bounded network-idle interval
- allow a short JavaScript stabilization period
- inspect every available frame
- inspect normal forms
- inspect SPA credential inputs when no conventional form exists

Browser-rendered evidence takes precedence when the static source and rendered DOM differ.

### Phase C — Form-context classification

Classify forms as:

- login
- registration
- password reset/change
- ambiguous

The scanner must never apply login rules blindly to a registration or password-change form.

## 6. Required condition matrix

| Condition | Classification |
|---|---|
| username + `autocomplete=username` | SAFE / expected |
| password + `autocomplete=current-password` on login | SAFE / expected |
| password + `autocomplete=new-password` on registration/reset | SAFE / expected |
| password + `autocomplete=new-password` on login | REVIEW REQUIRED |
| credential field has no autocomplete | INFO observation; not a confirmed vulnerability |
| password + `autocomplete=on` | INFO observation at most |
| password + `autocomplete=off` | INFO observation at most; not automatically vulnerable |
| username/password use unrelated sensitive token | REVIEW REQUIRED |
| unknown token on password field | REVIEW REQUIRED |
| multiple login forms with mixed configurations | analyze each form separately |
| JS-only login form | browser lane required |
| login form inside frame | inspect frame and record frame origin |
| only registration/reset forms found | NOT APPLICABLE |
| no usable form even after browser rendering | INCOMPLETE |

## 7. False-positive controls

The scanner must not:

- mark all `autocomplete="on"` password fields unsafe;
- mark every missing `autocomplete` attribute unsafe;
- mark every `autocomplete="off"` configuration safe merely because the attribute exists;
- treat registration or change-password forms as login forms;
- treat password-manager support itself as credential exposure;
- convert a semantic mismatch directly into HIGH/CRITICAL severity;
- assign severity to REVIEW, INCOMPLETE, or NOT_APPLICABLE outcomes.

## 8. Severity integration

TC01 should call the application's own severity engine only when a security-relevant condition has been independently confirmed.

For ordinary metadata observations, severity remains `null`.

For a confirmed credential-exposure condition established by an additional safe verification lane, the scanner should provide evidence and metric inputs to `core/severity_engine.py` instead of hardcoding a score in the testcase.

## 9. JSON shape

Each result should contain:

```json
{
  "key": "TC01",
  "name": "Autocomplete",
  "status": "SAFE",
  "assessment_state": "NOT_A_FINDING",
  "severity": null,
  "risk_score": null,
  "severity_rationale": "",
  "severity_components": {},
  "severity_metrics": {},
  "summary": "...",
  "details": {},
  "evidence": []
}
```

## 10. Production implementation principle

Prefer evidence over heuristics:

Static source → rendered DOM → effective autocomplete → form context → condition classification → assessment state → severity engine only for confirmed findings.
