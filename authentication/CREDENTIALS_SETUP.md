# Authorized authentication test inputs

The executor intentionally does not ship a list of common username/password pairs
and does not guess credentials. Such a list can cause account lockouts and turns
TC02 into password-guessing against whichever target is entered.

1. Copy `credentials.example.json` to `credentials.json`.
2. Replace the placeholders with credentials supplied or explicitly approved by
   the system owner for this engagement.
3. For TC02, use only default/product credentials that the owner has authorized
   for this target; include `product_hint` when relevant.
4. For TC04, candidate usernames are derived from the authorized entries. Use
   dedicated test accounts and obtain approval before testing account existence.
5. For TC05, TC06, TC10 and TC17, mark one verified test account with
   `known_valid_username: true`. The same account must have a valid non-empty
   password. Do not use an assumed/default pair as the valid control.
6. Do not commit `credentials.json` to source control. Keep the file local and
   restrict its filesystem permissions.

Example shape (replace every value before running):

```json
[
  {
    "username": "REPLACE_WITH_AUTHORIZED_TEST_USERNAME",
    "password": "REPLACE_WITH_AUTHORIZED_TEST_PASSWORD",
    "credential_type": "operator_supplied",
    "product_hint": "generic",
    "known_valid_username": true,
    "account_hint": "approved test account"
  }
]
```

An empty credential store is a valid configuration for unauthenticated
black-box checks. Credential-dependent tests must report their missing
prerequisite; they must not be labelled SAFE merely because they could not run.
