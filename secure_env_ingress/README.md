# Secure Env Ingress

Platform-independent, profile-scoped HTTPS forms for adding missing dotenv variables from Hermes messaging gateways. `/senv name KEY1,KEY2` defines a form; `/senv name` reopens it; `/senv status`, `/senv cancel`, and `/senv setup` provide readiness, invalidation and installation assistance. Never put values in chat. Form values travel browser → HTTPS → add-only target, not through the agent.

This is the runtime-only catalog distribution, without privileged certificate installers. Python 3.11+, Linux/POSIX and trusted IP-address TLS material are required. Registration uses the normalized `pre_gateway_dispatch` hook plus the generic plugin slash command; no Telegram-specific handler is installed. Set `allowed_owners: {discord: ["exact-opaque-user-id"]}` for platform-specific owners, or keep legacy `allowed_telegram_user_ids: [123456789]` for Telegram. Chat allowlists alone do not grant ownership. Ordinary browser forms need no Telegram token; Telegram Mini App launch is unavailable through this generic command path.

**Bearer-link warning:** the one-use HTTPS URL is returned to the originating chat. Anyone who reads the link can use it. Send `/senv` only in private or operator-trusted groups/threads, never in public or untrusted rooms. Never forward or log links. If the agent is busy, the host may queue, steer, interrupt or interpret the command; wait for completion or use `/stop` first, then send a fresh `/senv`. Do not assume busy commands avoid the model. A missing plugin cannot protect values already pasted into chat.

`/senv setup` sends a fixed installation-only request using the host's existing injection permission, or supplies copyable ordinary-message text when injection is denied. Privileged changes need separate approval. No listener starts on import; TLS, target binding and owner authorization are checked before issuing a capability. Existing keys are never overwritten.

## Retained login/password and saved TOTP (0.8.3)

List the native Vault first; handles and public identifiers are metadata, not secrets. Reuse a matching login. Type the public username separately **before** binding, including username-first flows. Then use the plugin route, not stock native fill:

```json
{"handle":"vault_example","parent":"EXACT_EXISTING_SELECTED_PAGE_ID","origin":"https://example.com","mode":"login"}
```

This is `secure_login_fill`, distinct from storage-only `secure_env_vault`. It accepts no password, code, endpoint or executable JS. Ordinary passwords use the native login classifier, never transient-code semantics; a unique current-password field is retained across top-level, bounded nested/OOPIF and open/closed custom Shadow documents. Password-only pages are supported. Optional `field_selector` and login-only original `frame` are discovery descriptors, not setter destinations. Ambiguous forms refuse; identifiers are not forced into a new page.

For a saved authenticator key, call the same `secure_login_fill` with `mode:"totp"`. The native backend's metadata origin/allowed_origins must match the retained exact OTP document **before** `resolve_otp` (and before `resolve_password` for login). A wrong-origin handle never resolves a secret or invokes a setter. TOTP uses the existing retained OTP guard, not native `enter_code`; absent stored code refuses and must not fall back to an unbound prompt. Standalone human-entered codes still use `secure_env_vault(mode="code",parent=...)`.

Dynamic LOGIN support is deliberately bounded. Synchronous handlers may reflect the exact selected password value, update supported validation/state classes and enable the same-form submit button; controlled React passwords and the retained public input-updater transaction are covered. Original account values (including restored changes observed at beforeinput/input/change boundaries), controls, form association/action and selected iframe visibility/inert ancestry remain guarded. Arbitrary or asynchronous name/type/class changes, unsafe or scoped CSS dependencies and unsupported reconciliation still refuse rather than redirecting a secret.

Locked/unavailable manager providers refuse without resolver access. Unlock only with the native supported unlock flow and its surface constraints, then start a new exact-parent request; this plugin never bypasses an unavailable prompt. Metadata is rechecked before secret resolution. Redaction is registered before secret dispatch, and results contain only fixed outcomes/metadata. Navigation, clone/reparent, form action changes, focus redirection, cancellation/expiry, reconnect and profile/human-lease epoch changes refuse. Each setter targets the original retained control after focus validation; no retry, recapture, native fallback or form submission occurs. Sites may act on input. An `unknown` result may be partial and must not be retried automatically. This is not a browser-wide atomicity or compromised-right-origin-script guarantee.

See the [full setup, security boundaries and test instructions](https://github.com/web3blind/hermes-secure-env-plugin#readme). Administrative helpers are separately reviewed operator tools, not catalog contents. Never run privileged helpers from a runtime-user-writable checkout.
