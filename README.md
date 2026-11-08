# Hermes secure-env ingress

Implicit native OTP/payment fills skip individually unavailable slots and report success for a positive native write count, not an artificial complete-control census. An entirely empty count fails. Explicitly declared layouts require their complete requested mapping; transport/cancellation uncertainty still stops the asynchronous request without retry.

Discovery and writes use the native `window.location.origin` policy, not a separate `self.origin`/sandbox-attribute veto. Selection is the native nonce/index stamp, not immutable element identity: a replacement that retains the stamp can be selected, as in Browser Vault. Same-origin scripts can already read filled values; CSS and DOM history are not a security boundary against them.

A profile-scoped, on-demand HTTPS form for adding missing `.env` keys. `/senv` accepts a **profile name and optional comma-separated field names, never secret values**. Secret values travel directly from the browser to the HTTPS listener, not through a messenger message or an LLM tool call. The gateway command works on normalized messaging platforms, subject to explicit platform-and-user authorization.

**English-first, Linux/POSIX plugin.** Each installation requires its own trusted TLS certificate, verified renewal and Internet reachability. This release uses browser links; Telegram Mini App launch is not exposed by the generic command. Automated tests do not establish compatibility with every messenger client or screen reader. Never enter secrets in chat; enter them only in the HTTPS form.

## Admission disclosures

The plugin runs in-process and uses internal Hermes Vault/classifier, redaction,
browser, delivery/session and configuration APIs as well as public captured-CDP
and plugin registration APIs. These internal dependencies can break on updates;
there is no core-function override or login-backend registration. The runtime
scanner's CAUTION setup instructions require separate approval for `sudo`.
The root administrative helpers are not the catalog install payload. The
listener binds all interfaces by default; one-use links authorize their holder.
Native encrypted Vault retains saved login/TOTP/card data, including CVC.
Explicit `.env` ingress writes approved missing keys; setup bootstrap directly
reads selected-profile `.env` owner IDs. Approved SHA-256-pinned operation
consumers run with gateway privileges, are not sandboxed, and cannot be stopped
once running merely by cancelling ingress. None are enabled by default.
Site input callbacks can authorize or submit even without a plugin submit click;
verify unknown outcomes externally before retry. See the runtime README for
native-parity boundaries and the complete compatibility disclosures.

## Installation, separately from TLS setup

YAML configuration uses bounded `ruamel.yaml>=0.18.16,<0.19`; PyYAML is not a plugin runtime dependency. Setup preserves the historical implicit scalar grammar and rejects duplicate keys, including collisions through YAML merges. Optional consumer config-read failures disable consumer discovery only; ordinary ingress config reads remain strict. A fresh-wheel registration and strict-YAML check is available in `tests/wheel_yaml_smoke.py`, run outside the checkout with an unmodified ruamel-based Hermes host on `PYTHONPATH`, an isolated `HOME`/`HERMES_HOME`, and `SENV_WHEEL_ROOT` pointing to the clean wheel environment.

**0.8.7 requires Hermes >=0.22.2**. Its public captured-CDP dispatch seam is required; this does not establish catalog acceptance or universal browser-startup compatibility. Runtime requires Python 3.11+, POSIX ownership/modes, `flock`, `O_NOFOLLOW`, OpenSSL and the bounded dependencies in `pyproject.toml` / `uv.lock`.

0.8.2 names the plugin tool `secure_env_vault` to avoid colliding with Hermes' native unified `browser_vault(action=...)`. There is no plugin `browser_vault` alias. Native Vault filling/listing remains separate; legacy Hermes >=0.21.7 exposes `browser_vault_list` / `browser_vault_fill`.

### Browser transport requirements (0.8.3)

The plugin's browser-writing paths — `secure_env_vault(mode="code")` (top-level and nested) and `secure_payment_fill`, plus `secure_login_fill` — require the host supervisor registry's public `registry.capture(task_id)` / `SUPERVISOR_REGISTRY.capture(task_id)` API. Its captured handle must support public `call(..., timeout=None, before_send=...)`: `timeout=None` waits for the actual command outcome rather than timing out locally while a secret write can still run; a **synchronous trusted `before_send` callback** runs on supervisor dispatch immediately before sending, to enforce the plugin's cancellation, expiry and binding checks. These are trusted in-process callbacks, not model-supplied code. A host with only the initial capture seam but without this dispatch follow-up is insufficient.

Commands, exact-target CDP attachments and late cleanup use the **original captured handle only**. There is no private supervisor transport fallback, raw-socket send or automatic reconnect/recapture onto a replacement connection. Reconnect, stop or registry replacement invalidates the handle; refuse or report an uncertain attempted write, inspect the site without reading secrets, and rediscover only for a fresh request. Capturing transport does not grant origin permission, human consent or task-to-target ownership.

Every browser-writing route requires an explicit existing parent selected by the authorized agent from its browser context. The human is never asked for tab IDs. Tab creator and creation history are irrelevant: no ownership module, browser_tabs.sqlite or replacement registry is used. The plugin attaches its own exact parent session through one original public capture and freezes target/session, profile, human-control lease epoch, HTTPS origin. A different supervisor default page is not a refusal. There is no origin-based sibling fallback, supervisor refocus, recapture or native stock fill/enter_code fallback. Missing parent refuses before any secret prompt. Reconnect, profile/lease change, cross-origin navigation or destroyed destination context invalidates the retained request. `allowed_owners` still authorizes the human, not tab creation. Storage remains browser-independent. Public capture unavailable is a browser capability failure, not a session authorization failure; this plugin does not repair host browser startup.

Hermes catalog submissions target the runtime-only `secure_env_ingress/` subdirectory, which has its own manifest and bounded dependencies. The root `scripts/` administrative TLS helpers are not part of the catalog install. Catalog installations use their reviewed SHA pin; repository releases can be newer than that pin. Alternatively, use either reviewed installation method below.

Two supported Hermes discovery surfaces:

- Directory plugin: install only the reviewed `secure_env_ingress/` runtime directory (containing its own `plugin.yaml` and `__init__.py`) into the selected profile through the canonical plugin installer. The administrative repository root is not the catalog payload. Let Hermes resolve the declared runtime dependencies; do not install into system Python.
- Python package: build with `uv build`, install the reviewed wheel into that same Hermes Python environment. It exposes `hermes_agent.plugins` entry point `secure-env-ingress`. The wheel does not configure or enable the plugin.

Then enable using the documented `hermes plugins enable secure-env-ingress` command **in the intended profile**. Do not run both install variants. Enabling an installed plugin, production configuration, or restarting a gateway are operator actions, not part of the local tests. The old `secure_env_ingress_probe/` is only a test fixture; never install it.

## Non-secret configuration

Use `plugins.entries.secure-env-ingress.settings` in the selected Hermes profile's `config.yaml`. Example only; replace documentation IP, numeric owner ID and absolute paths with verified deployment values:

```yaml
plugins:
  entries:
    secure-env-ingress:
      settings:
        public_ip: "203.0.113.10"
        listen_host: "0.0.0.0"
        listen_port: 18443
        cert_path: "/absolute/private/tls/current/fullchain.pem"
        key_path: "/absolute/private/tls/current/privkey.pem"
        safety_seconds: 86400
        ttl_seconds: 300
        allowed_telegram_user_ids: [123456789]
        # Alternatively/additionally: exact opaque string IDs per normalized platform.
        allowed_owners:
          discord: ["opaque-user-id"]
        mini_app_enabled: false
        delivery: this_chat  # or home; shared by .env and Browser Vault
        profiles:
          service:
            target_mode: hermes
            keys: [SERVICE_TOKEN]
          project:
            target_mode: project
            target_path: "/absolute/project/.env"
            keys: [SERVICE_TOKEN, SERVICE_SECRET]
```

- Runtime configuration uses IPv4 literals and a stable public address. Never put a bot token, private key or secret values in this configuration. Ordinary browser forms need no Telegram bot token. The historical Telegram Mini App flow is not available through generic command registration; leave `mini_app_enabled: false` for this release.
- `allowed_owners` maps lowercase normalized platform names to exact string user IDs. Legacy positive numeric `allowed_telegram_user_ids` remain supported as Telegram-only owners. Same IDs on other platforms grant nothing. Gateway chat access, roles and broad allowlists alone do not grant ownership. Configure trusted chat destinations separately in Hermes.
- `hermes` resolves `.env` inside the active `HERMES_HOME`. `skill`, `project` and `custom` require the exact absolute `.env` target; no filename supplied by the browser is accepted. Parent directories must already exist, be owned by the runtime user, and not be group/world-writable. Symlink traversal is rejected for target files.
- Existing target must be a regular, single-linked file with mode `0600`, owned by the runtime user. New files are atomically created with `0600`. Existing values are never replaced. A target change observed before commit invalidates the binding. The final check-and-replace is protected against other UIDs by the validated parent permissions and serialized among cooperative writers; an uncooperative same-UID/root writer is outside this guarantee.
- TLS certificate is mode `0644`, key `0600`, owned by the runtime user inside a private runtime directory. Certificate chain, IP SAN, validity and key match are checked before opening the listener. No untrusted/self-signed production fallback exists.
- TTL is 120–600 seconds. There is one active browser/Mini-App pair per runtime; a new request replaces the previous pair. Consuming either invalidates both. This deliberately stricter single-pair policy also serializes the target workflow.

Configuration updates create private backups under `secrets-ingress/config-backups/` in the selected Hermes home. Existing backups elsewhere are retained; no live files are moved.

## Guided setup

After enabling the plugin, send `/senv setup` from an explicitly authorized identity in a trusted conversation. Hermes handles installation and diagnosis using the bundled `secure-env-ingress:setup` skill and deterministic setup scripts. The agent requests consent for package installation, certificate issuance and other privileged changes; it cannot bypass approval policy.

If the plugin already has operator-granted `plugins.entries.secure-env-ingress.allow_gateway_injection: true` and the conversation exists, it queues a fixed **installation-only** task in that conversation. Otherwise it replies with a fixed, copyable ordinary-message installation request. The plugin never grants itself injection permission, invokes a separate model/provider, or forwards the original command/reply/media. A queued request is not proof of completed setup.

For a new non-Telegram installation, the operator can configure an exact identity with `python -m secure_env_ingress.setup_config configure --home /absolute/profile/home --platform discord --owner opaque-user-id --public-ip 203.0.113.10` (substitute verified values). This is an operator setup action, not an ownership claim accepted from chat. The platform name is a configuration value, not a separate implementation.

Before ingress settings exist, only explicit positive numeric IDs in the selected profile's private `TELEGRAM_ALLOWED_USERS` configuration can use this bootstrap. Wildcards, allow-all and another profile's environment are not setup ownership. Once ingress owners are configured, that explicit owner list applies. If no trusted owner is configured, establish it through the normal Hermes operator setup first.

The installer supports a bounded Debian/Ubuntu + systemd + snap path, checks prerequisites, installs missing packages after approval, and runs staging/production TLS and renewal checks through the hardened helpers. Unsupported distributions, busy ports, networking failures or missing privileges become an installation diagnosis task for the agent, not a reason to relax security. Existing services/firewall rules and gateway restarts are not changed without separate approval.

Fresh setup starts with a dedicated test target. The agent verifies configuration, TLS and renewal; the owner enters a **made-up value only** in the real HTTPS form to confirm the external path. Adding real target profiles is a separate explicit choice. An already-loaded plugin refreshes its own settings on the next command; loading newly installed code may still require an owner-approved gateway restart.

## Use

After `/senv setup` is complete, create a form in a trusted authorized conversation:

```text
/senv site_auth field1,field2
```

This saves the field names and opens a one-time HTTPS form. Enter the values only on that page. Names are case-sensitive and preserved exactly: `field1` and `FIELD1` are different variables. Use letters, digits and underscores; the first character must be a letter or underscore. Up to 32 fields, each at most 128 characters, are accepted. Separate names with commas without spaces; never use `name=value` in chat.

A new profile writes to `secrets-ingress/site_auth.env` inside the active Hermes home. An existing profile keeps its configured destination; explicitly supplying fields replaces its saved field list, not any `.env` values. The response identifies the fields. Afterwards, `/senv site_auth` reopens that saved form. Unknown names without fields get syntax guidance. Existing `.env` variables are never overwritten; choose missing keys rather than re-entering existing ones.


Send `/senv service` through the gateway as a configured exact platform/user owner. A one-time **bearer link is delivered according to `delivery: this_chat | home`**. The default, `this_chat`, preserves the originating chat and topic. `home` uses the active profile's configured home on the originating platform and fails closed if unavailable; there is no fallback to another destination. The same setting applies to `.env` and Browser Vault. Anyone who sees it can use it: only use `/senv` in private or operator-trusted groups/threads, never public, untrusted, or widely readable rooms. Do not forward or log the link. Open it and enter values in the HTTPS password fields, not chat. Mini App launch is unavailable on this generic command path.

- `/senv setup`: installation and diagnosis assistance using the agent and reviewed scripts; never forwards secret input.
- `/senv status`: safe readiness status, no token, URL or value dump.
- `/senv cancel`: invalidates the active owner's session and closes an idle listener.
- The CLI lacks a normalized gateway identity and cannot issue a form link. The messaging gateway command uses the host's normalized hook, authorization and generic plugin-command dispatch; no platform-specific handler is installed.

The listener starts only after authorization, target and TLS validation. A profile-local leader lock prevents a second instance. It closes on cancellation, consumption/expiry (short cleanup interval), or plugin unload. Creating a later session validates the current deployed TLS material again.

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

## ENV profile compatibility fix (0.6.4)

Version 0.6.4 restores `/senv <profile> <FIELD,...>` when trusted operation consumers are configured. ENV setup validates its own settings without rejecting or modifying the separate `consumers` section. Unknown ENV settings remain rejected; consumer validation and activation remain the responsibility of the operation loader.

## Isolated configured consumer failures (0.7.2)

A rejected administrator-configured consumer now blocks only its named `secure_operation`, not the entire plugin. Valid consumers activate independently of entry order. ENV forms, login/password/TOTP, code entry, payment-card storage and `secure_payment_fill` stay registered. All existing source hash, ownership, path, permissions and factory checks remain required; mismatching source is never executed. Malformed consumers containers disable configured operations, while sanitized startup warnings identify entry position and a fixed reason/stage without exposing configuration or exception details. Reload/unload cannot retain stale configured factories; collisions fail closed without falling back to a preexisting factory. See the operation contract below for lifecycle and trusted-code limits.

## One-shot secret operations (0.6.3)

Version 0.6.3 fixes premature `unknown` results while a submitted operation is still running. Consuming the one-use link no longer ends the wait for its callback; the original deadline and cancellation behavior remain in effect.

`secure_operation` delivers a one-use secret from the HTTPS form to an administrator-approved external consumer, without saving it to Vault or `.env` or returning it to the agent. Configure the active profile's `plugins.entries.secure-env-ingress.settings.consumers` allowlist with each operation's reviewed Python `path`, `factory`, and `sha256`. The existing programmatic registration API is also supported. There are no enabled consumers by default, no arbitrary command/URL argument, and no project-specific handler bundled with the plugin.

See [operation configuration and integration contract](secure_env_ingress/OPERATIONS.md) for a complete example, registration lifecycle, ownership/integrity checks, and trust limits. Consumers are trusted code running with gateway privileges, not sandboxed. The bearer link authorizes submission but does not prove the submitter's identity. Cancellation of an already-running action reports `unknown` and does not forcibly stop it; do not retry blindly.

This release also recognizes localized verification inputs such as `name="code"` with the label “Введите код”, retaining ambiguous-field and origin-change refusal.


## Security boundaries

Never type `/senv KEY=value` or paste a key into chat. **An absent/broken plugin cannot protect an accidental secret pasted into chat**: the messenger already received it and Hermes may treat the message as ordinary model input. **Busy-session limitation accepted:** when an agent is active, the host may queue, steer, interrupt or interpret a `/senv` message instead of reaching this command. Wait until the agent finishes or send `/stop` first, then issue a fresh command. Do not assume busy commands avoid model processing or automatically retry.

Capabilities are random 256-bit strings, held in RAM as hashes, mode/user/profile/target-bound, absent from initial HTTP requests because they use fragments. GET/prefetch does not consume them. The page strips launch parameters from history and makes strict JSON POSTs. The backend consumes a capability before validating/writing authenticated submissions; rejected authenticated input and uncertain write failure are terminal, not retryable. The page still shows success or an unconfirmed-result message and clears its fields. If the request never reaches the server, or its envelope is rejected before authentication, immediate server-side invalidation cannot be guaranteed; the TTL/cancel command still applies. Request bodies, tokens and exception detail are not logged. Key names, not values, are returned.

The first-party page has no analytics, external scripts/fonts, SDK, service worker or Web Storage. Mini App launch data is read from Telegram launch parameters and checked server-side; stripped fragments are unsupported, never a reason to weaken auth. Framing stays denied until a separately reviewed real-client exception is needed. No Telegram `sendData`/cloud storage is used.

The web flow rejects empty, multiline, NUL, oversized and `${...}`-style values (dotenv consumer interpolation would alter the latter). A new link is needed after any terminal error. The writer supports escaped multiline serialization for potential local reuse, but the web form does not. Existing dotenv files are parsed without evaluating their values; malformed/duplicate assignments fail closed. Atomic replacement uses the exact bound target identity, so simultaneous/stale sessions cannot silently update a changed file.

Limits: browser/password managers can ignore autocomplete hints; Python cannot guarantee RAM zeroization; same-UID/root or a compromised browser/OS is outside confidentiality guarantees. The originating chat receives capability links, never form values. Do not log responses at another layer or share bearer links.

## TLS operations (not performed by development tests)

Let's Encrypt IP certificates use profile `shortlived` (160 hours); use a verified current Certbot with IP support, at least 5.4 for the documented webroot path. HTTP-01 needs public port 80 during every renewal. Setup scripts are separate from runtime and require explicit operator approval for privileged changes. The lower-level `scripts/setup_tls.py` does not install Certbot: an existing trusted Certbot >=5.4, a verified packaged renewal scheduler and reachable port 80 are its prerequisites. The guided `scripts/install_host.py` orchestrator can install the classic Certbot snap and a fixed root-owned Python environment with pinned dependencies after approval. It accepts only `/snap/bin/certbot` paired with `snap.certbot.renew.timer`; it does not change firewall rules. Bootstrap the orchestrator directly with trusted `/usr/bin/python3 -I -S`, not the Hermes runtime environment. **Never sudo a script from the runtime-user-writable checkout.** An administrator must first obtain/review the whole bundle through a trusted channel and provision it (including the interpreter/dependencies) under a root-owned, non-group/world-writable tree, separate from the runtime account. Run the privileged entry point only from that trusted installation. Source ownership checks inside a Python script cannot protect an administrator who has already executed a modified script. Apply additionally refuses untrusted source/ancestor ownership and reads sources from checked no-follow descriptors; no signed release or privileged installation has been produced by these development tests. Destination writes run as the runtime account, not root. Staging uses a separate lineage, disables directory hooks and does not install a production deploy hook. The installed production hook never accepts custom test CA roots and ignores unrelated renewed lineages. The renewal dry-run is restricted to the selected certificate and also disables directory hooks. Start with staging; staging is not a trusted production certificate. Do not reuse an ACME account or TLS key as an ingress capability.

From the checkout, `python -m scripts.setup_tls --help`, `python -m scripts.deploy_certificate --help` and `python -m scripts.external_probe --help` describe the local helpers. Preflight/dry-run is not proof of remote reachability. Certbot renewal/timer, deploy-hook installation and `renew --dry-run` require a controlled host setup. The deploy helper validates source confinement and certificate/key pairing, then switches an atomic private generation; the runtime uses `current/fullchain.pem` and `current/privkey.pem`.

## Form accessibility

The form uses native labeled inputs and requests `autocomplete="off"` rather than password generation. Browsers may override this hint. Terminal outcomes receive focus; client-side authenticator errors are associated with and focus the invalid field. An operator confirmed the updated ordinary form permits Tab navigation on Windows 11 + Chrome + NVDA. This is not an all-browser or all-screen-reader guarantee.


## Test runner

Use the Hermes canonical `scripts/run_tests.sh` with an isolated test home and bounded serial browser batches. Administrative helpers are not in the runtime-only artifact.
