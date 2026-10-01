---
name: usage
description: Use Secure ENV for Telegram login/password, payment card storage or code entry. Choose HTTPS forms for Vault credentials, passcodes, .env secrets and trusted operations.
---

# Secure ENV: choose the right protected form

This plugin provides Telegram HTTPS forms. It is separate from native interactive Vault prompts. Load the installed `browser_vault` tool schema before calling it. Search for `Secure ENV login password` or `Secure ENV verification code` when tools are deferred. Do not conclude that the plugin is unavailable because a native prompt returned `prompt_unavailable`.

## Login and password — not code mode

For saving a login, password and optional authenticator setup key, use:

```json
{"origin":"https://example.com","label":"Example login","mode":"login"}
```

Omitting `mode` also selects login. The user enters secrets in the HTTPS form, never in chat or arguments. Saving works without an open browser or login page. It stores a login for the exact HTTPS origin in the current profile's encrypted Vault; it does NOT fill the page or sign in.

For actual browser login, inspect the current origin and use native Vault listing first. Reuse a matching saved entry rather than requesting the password again. If a login must be saved and the native save prompt is unavailable in Telegram, use the plugin login form above. After `saved`, recheck the page, obtain the public username from native Vault listing, enter only that identifier using ordinary browser input, and fill the password using native Vault fill. Never read passwords or TOTP keys back. Follow the site's username-first or password-only flow rather than forcing both fields onto one page. Storing an entry does not prove that a site's login form can be filled: verify that step separately. Code mode is NOT a fallback for arbitrary account passwords.

## Payment card storage (0.7.0)

```json
{"origin":"https://example.com","label":"Example card","mode":"payment"}
```

This distinct mode saves a card without an open browser or checkout. The authorized Telegram owner enters card number, optional cardholder name, expiry month/year, CVC and optional billing postal code only on the one-time HTTPS form. Number and CVC are masked; other fields use labeled text inputs. Number must be 12–19 ASCII digits with a valid Luhn checksum, month 1–12, year four digits, expiry not in the past and at most 20 years ahead, CVC 3–4 ASCII digits. No spaces or separators are accepted in numeric fields. Name is limited to 120 characters and postal code to 32; control/format characters are rejected. Validation does not establish card validity, available funds, or authorization.

Native `VaultStore.add_item('payment', ...)` appends an encrypted entry with canonical `card_number`, `cardholder_name`, `exp_month`, `exp_year`, `cvc`, `billing_postal_code` fields. CVC storage is deliberately supported by the native contract; this is a personal Vault feature, **not a PCI-compliance claim** or merchant card-processing service. Empty optional fields are omitted. Exact HTTPS origin/profile are bound at issuance and never taken from submitted values. Storage does not consult a browser, request payment-fill consent, fill checkout fields, submit a site form or authorize payment. `saved` is reported only after native metadata readback; no card value or last-four value is returned. Links retain the login flow's at-most-240-second TTL, one-use, cancel/supersession and safe unknown-write handling. Duplicate requests append entries, never overwrite.

After saving, recheck the intended checkout and its exact origin, use native Vault listing, and call native `browser_vault_fill`. **Native filling requires a separate human confirmation**, routed by Hermes to the active approval surface (Telegram gateway callback or interactive CLI). Missing/unresolved/declined approval fails closed; never retry a decline automatically. This confirmation permits field filling, not a later Pay click. Some sites react to input automatically: verify the page and payment intent before filling. The native fill is not implemented or weakened by this plugin. Cross-origin hosted-payment iframes are outside the native top-document fill path; do not bypass origin checks, read card details back or manually inject them. Unsupported checkout controls need a separately supported native integration.

Never put card details in chat/tool arguments, `.env`, logs, or ordinary browser inputs. Use a public nonsensitive label without card numbers. `unknown` means inspect native metadata before retrying, not proof of either success or failure. This release does not unlock third-party managers or resume secret forms after restart.

## Standalone code or recognized access-passcode field

For an open verification-code/passcode form, use:

```json
{"origin":"https://example.com","label":"Example verification","mode":"code"}
```

First establish the current task's supported browser connection and inspect the intended page without reading secret values. This mode fills a recognized field, including recognized password-type passcode fields; it does not save a Vault entry or submit the site form. It accepts 4–16 printable ASCII characters including punctuation, but no whitespace, control characters or Unicode. Do not assume every field called password is a code field, strip characters, or weaken target checks to make a value fit.

A single candidate is automatic. For `selection_required`, the agent chooses from issued candidates using its browser-task context, then calls again with the selection token and the same origin/label. Do not ask users to identify tabs they cannot see. If candidates are indistinguishable, resolve the browser context without submitting secrets. Selection tokens do not establish isolation between tabs sharing a CDP endpoint.

A native code prompt returning `prompt_unavailable` does not rule out this plugin's code form. Neither the login nor the code mode needs a registered operation for each website.

## Other destinations

- Secret deliberately destined for an ENV file: `/senv <profile> <FIELD1,FIELD2>`. Do not use an ENV file as a workaround for browser filling and then read the secret back.
- Secret for an administrator-registered trusted action: `secure_operation`. This is a different workflow, not a prerequisite for ordinary login/password or code entry. Do not invent handlers or register arbitrary execution merely to fill a browser field.
- Installation/TLS configuration: `secure-env-ingress:setup`, not this usage skill.

## Failure handling and verification

- `saved`: login/card storage completed; browser filling/sign-in/payment approval remains separate.
- `filled`: code fill reported; inspect the site without reading the value, then submit only if authorized and needed.
- `expired`: do not reuse the link. Reissue when the user is ready. The code/login/payment link lifetime is at most 240 seconds and may be shorter by configuration.
- `unknown`: inspect the target before retrying; do not claim success or assume nothing happened.
- `no_code_form` / `browser_binding`: check the intended page and current task's supported connection, not arbitrary endpoints. Login storage does not require a browser.
- `runtime_preflight`: this identifies a broad failure stage, NOT a root cause. Check configuration, TLS, listener ownership and target checks; report only verified findings. Do not repeat identical calls indefinitely or declare all protected input unavailable.

Only call tools actually available for the session. An authorized Telegram context, working delivery and valid HTTPS remain requirements; this fallback does not bypass them. Never request secrets in chat, echo a secret the user already sent, or type it through ordinary browser/terminal tools. Links are bearer capabilities: use only a trusted authorized chat, do not forward or log them. Do not claim that a form was delivered or a login succeeded without the corresponding result. No core modifications are required for these workflows.
