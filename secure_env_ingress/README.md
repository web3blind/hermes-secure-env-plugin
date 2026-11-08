# Secure Env Ingress

Implicit native OTP/payment fills skip individually unavailable slots and report success for a positive native write count, not an artificial complete-control census. An entirely empty count fails. Explicitly declared layouts require their complete requested mapping; transport/cancellation uncertainty still stops the asynchronous request without retry.

Discovery and writes use the native `window.location.origin` policy, not a separate `self.origin`/sandbox-attribute veto. Selection is the native nonce/index stamp, not immutable element identity: a replacement that retains the stamp can be selected, as in Browser Vault. Same-origin scripts can already read filled values; CSS and DOM history are not a security boundary against them.

Platform-independent, profile-scoped HTTPS forms for adding missing dotenv variables from Hermes messaging gateways. `/senv name KEY1,KEY2` defines a form; `/senv name` reopens it; `/senv status`, `/senv cancel`, and `/senv setup` provide readiness, invalidation and installation assistance. Never put values in chat. Form values travel browser → HTTPS → add-only target, not through the agent.

This is the runtime-only catalog distribution, without privileged certificate installers. Python 3.11+, Linux/POSIX and trusted IP-address TLS material are required. Registration uses the normalized `pre_gateway_dispatch` hook plus the generic plugin slash command; no Telegram-specific handler is installed. Set `allowed_owners: {discord: ["exact-opaque-user-id"]}` for platform-specific owners, or keep legacy `allowed_telegram_user_ids: [123456789]` for Telegram. Chat allowlists alone do not grant ownership. Ordinary browser forms need no Telegram token; Telegram Mini App launch is unavailable through this generic command path.

**Bearer-link warning:** the one-use HTTPS URL is returned to the originating chat. Anyone who reads the link can use it. Send `/senv` only in private or operator-trusted groups/threads, never in public or untrusted rooms. Never forward or log links. If the agent is busy, the host may queue, steer, interrupt or interpret the command; wait for completion or use `/stop` first, then send a fresh `/senv`. Do not assume busy commands avoid the model. A missing plugin cannot protect values already pasted into chat.

`/senv setup` sends a fixed installation-only request using the host's existing injection permission, or supplies copyable ordinary-message text when injection is denied. Privileged changes need separate approval. No listener starts on import; TLS, target binding and owner authorization are checked before issuing a capability. Existing keys are never overwritten.

## Browser Vault parity (0.8.7)

Browser destination checks deliberately follow default Hermes Browser Vault:
exact saved `origin`/`allowed_origins`, native inspection and login/OTP/checkout
classification, a per-inspection nonce/index DOM stamp, and `type=password` for
current-password setters. Login chooses the highest native score, then DOM
order. Inspection excludes disabled/read-only, hidden/non-input controls and
controls whose computed display/visibility/rects fail native visibility checks.
Filling uses the native value setter and bubbling input/change events; selects
match native value/text rules. CSS is not parsed or retained.

There are **no CSS, geometry, class/attribute/value history, form-action, account
value, competing-control or static-presentation locks**. Same-origin SPA routes,
framework updates and reverted presentation mutations are not refusal reasons.
A script on the correct origin can already read the entered secret, just as
with native Vault; this plugin does not claim protection from that script.
Missing/changed selection stamps, destroyed contexts and wrong origins cannot
select an unrelated replacement destination. A current-password field changed
to another type before the native-equivalent write is refused.

### Plugin-specific boundaries retained

The authorized agent supplies an **exact existing parent page**, not an origin
search. The plugin attaches its own session to that parent through the public
captured transport. A different supervisor default tab is irrelevant. Bounded
frame/Shadow traversal extends native document lookup without broadening that
parent. Frame owners establish the requested parent/child relationship. There
is no sibling-tab search, stock-fill fallback, recapture, site exception or
model-supplied CDP endpoint/JavaScript.

Profile and configured owner/session authorization, opaque native handles,
Vault-home binding, native manager unlock, original connection/generation,
human-control lease, expiry/cancellation and synchronous public `before_send`
admission remain required. These bind an asynchronous protected request to its
initiator; they are not presentation checks. Redaction is registered before
secret dispatch. Responses contain outcomes/counts/public metadata, never
passwords, codes or card bytes. No form is submitted or Pay button clicked.
Sites may act on input. `unknown` can mean a partial write: inspect without
reading secrets and never retry automatically.

### Login storage and fill

Use native `browser_vault` listing first. Public identifiers/handles are
metadata; type the public identifier with ordinary browser input. To store a
missing login use `secure_env_vault` with `mode:"login"`, exact HTTPS `origin`
and public `label`. The authorized owner enters username/password/optional
TOTP key only in the one-use HTTPS form. Storage does not require an open tab
and does not fill or sign in. Never paste a password into chat or tool args.

Then call `secure_login_fill`:

```json
{"handle":"vault_example","parent":"EXACT_EXISTING_SELECTED_PAGE_ID","origin":"https://example.com","mode":"login"}
```

Optional `field_selector` and login-only `frame` (`top` or an existing frame ID)
narrow discovery, never re-resolve a setter destination. Top-level, bounded
nested/OOPIF and open/closed Shadow documents are supported. Password-only and
username-first forms use the same native classifier; public identifiers are
not rewritten by this tool. Locked managers require the native supported
unlock flow, then a fresh request. An unavailable unlock surface is not bypassed.

For a saved authenticator key use `mode:"totp"`. Saved TOTP uses native OTP
classification and native whole-code/split-box selection, not a human code
prompt. Handle metadata must match the destination **before** `resolve_otp`
or `resolve_password`. Missing stored TOTP returns `otp_unavailable`; it does
not fall back to an unbound prompt.

### Human-entered transient codes

`secure_env_vault(mode:"code", origin=..., parent=..., label=...)` retains a
recognized verification-code destination before sending the owner a one-use
HTTPS form. Missing/ambiguous purpose refuses before that prompt. The code is
not stored in Vault or `.env`. This route deliberately keeps **code-purpose**
policy: selecting a password, recovery key, payment field or generic secret
field is not permission to solicit it as a transient code. Native saved TOTP
classification is separate from this human-entry interaction.

An optional discovery-only `field_selector` can hint a recognized field or
an unambiguous split-code group. For explicitly requested nonstandard inputs,
use the closed `target_spec` schema exposed by the tool. `single`,
`ordered_cells` and `indexed_cells` map the owner's explicit length/charset
policy to original selected controls. The separate `parent` argument remains mandatory;
selectors, layout, field/count and validation descriptors are public metadata,
not secret values or executable JS. Textarea/plaintext editing adapters are
explicit plugin features, not a claim of native support for arbitrary editors.
Only declared adapters and code-purpose/value validation remain; no history,
CSS/geometry or retained label/account/action snapshots are used.

### Payment storage and human-approved fill

Use `secure_env_vault(mode:"payment", origin=..., label=...)` for protected
card storage. Entry validates the declared card format and stores it in the
native encrypted Vault. Storage is **not fill consent**.

`secure_payment_fill` accepts the opaque saved handle, exact provider HTTPS
origin and agent-selected parent. Automatic exact-parent document/direct-child discovery uses
native checkout classification and highest-score/DOM-order selection per
available saved role; it does not demand an entire card form. Explicit
`target_spec` additionally supports multi-frame and declared
textarea/plaintext card adapters. It binds `parent`, `merchant_origin` and
per-field `frame`, `selector`, `role`/format descriptors. Role formatting and
split-field layout are explicit plugin mapping semantics.

The **native human payment approval** identifies merchant/provider origins
and the public card label. Declined, unresolved or unavailable approval means
`payment_declined`, without secret resolution or setters. Revalidate owner,
profile/Vault identity, parent/frame relationship and metadata after consent.
Wrong-origin metadata is rejected before the resolver. Never rebind a card to
make a refused destination match. Payment manager origins use the same native
exact allowed-origin list; locked managers require native unlock.

Optional `resume_existing:true` is a plugin-specific instruction to preserve
already matching fields rather than emit their setters/events. It still needs
fresh native human approval, compares against the selected card privately and
refuses mismatches. Native default fill simply overwrites its selected fields;
resume is not a presentation security policy. No consent checkbox or Pay
button is touched.

### Verification scope

Candidate tests use synthetic temporary Vaults/profiles and real Chromium,
registered protected tools, HTTPS ingress, native approval boundaries and
actual framework builds (Vue/Vuetify full CSS, React and plain inputs). The
connected public Beget test creates its own disposable context, fills only a
synthetic account/password and never submits. Test results and artifact hashes
are recorded externally; earlier presentation/history refusal tests describe
the superseded contract, not current security guarantees. Local tests do not
establish catalog acceptance, live activation, or universal compatibility.

See the root README for TLS/operator setup.

## Admission and compatibility disclosures

The catalog payload is this runtime directory, not the repository's privileged
administrative helpers. The install scanner reports CAUTION for the bundled
setup instructions that invoke `sudo` only after operator approval. Runtime TLS
verification uses a fixed OpenSSL argument vector without a shell; payment
validation reverses the PAN digits for the Luhn check. These operations do not
constitute an updater or a permission to run administrative setup unattended.

The plugin runs in-process and imports internal Hermes Vault/classifier,
redaction, browser, gateway delivery/session and configuration APIs in addition
to the public captured-CDP dispatch seam and plugin registration APIs. Those
internal APIs can break on a Hermes update; native-parity behavior does not mean
that every dependency is a stable public API. `pre_gateway_dispatch` is a hook,
not middleware, and observes gateway messages to bind commands to their sender.
No login backend is registered and no Hermes core function is replaced.

The HTTPS listener binds all interfaces by default. Native encrypted Vault stores
saved login/TOTP/card data, including CVC; this plugin does not create a separate
credential backend. Its explicit `.env` ingress writes approved missing keys,
and setup bootstrap reads owner IDs from the selected profile's `.env`.
Administrator-allowlisted, SHA-256-pinned `secure_operation` consumers execute
with gateway privileges, are not sandboxed and must enforce their own handling
policy. No consumers are enabled by default. Links authorize their holder, not
the submitter's identity, and cancellation cannot stop an already-running
consumer. Browser input callbacks may authorize or auto-submit site actions even
though the plugin does not click submit; unknown outcomes need external
verification before retry.
