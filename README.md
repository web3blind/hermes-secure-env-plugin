# Hermes secure-env ingress

A profile-scoped, on-demand HTTPS form for adding missing `.env` keys. `/senv` accepts a **profile name and optional comma-separated field names, never secret values**. Secret values travel directly from the browser to the HTTPS listener, not through a messenger message or an LLM tool call. The gateway command works on normalized messaging platforms, subject to explicit platform-and-user authorization.

**English-first, Linux/POSIX plugin.** Each installation requires its own trusted TLS certificate, verified renewal and Internet reachability. This release uses browser links; Telegram Mini App launch is not exposed by the generic command. Automated tests do not establish compatibility with every messenger client or screen reader. Never enter secrets in chat; enter them only in the HTTPS form.

## Installation, separately from TLS setup

Tested against Hermes upstream `9fe737aef2dd18a351dff3c4de608d63879a6524`, Python 3.11 on Linux. No broader release-floor claim is made. Runtime requires POSIX ownership/modes, `flock`, `O_NOFOLLOW`, OpenSSL and the bounded dependencies in `pyproject.toml` / `uv.lock`.

Hermes catalog submissions target the runtime-only `secure_env_ingress/` subdirectory, which has its own manifest and bounded dependencies. The root `scripts/` administrative TLS helpers are not part of the catalog install. Catalog installations use their reviewed SHA pin; repository releases can be newer than that pin. Alternatively, use either reviewed installation method below.

Two supported Hermes discovery surfaces:

- Directory plugin: put this reviewed checkout (including root `plugin.yaml`, `__init__.py` and `secure_env_ingress/`) under the **selected profile's** `plugins/secure-env-ingress/`. Install its dependencies into the Python environment actually used by Hermes, not system Python.
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

## Browser Vault login entry (0.6.5)

The agent can call `browser_vault` with the exact HTTPS site origin and a public label. Login storage requires no browser, open tab or CDP attachment:

```json
{"origin":"https://example.com","label":"Example account"}
```

Login storage requires an interactive Telegram owner/session/profile, but is independent of browser state. The form displays the requested site; verify it before entering credentials. The immutable origin and native Vault profile are bound at issuance. Opening, closing or switching tabs does not prevent saving. Stored entries can later be used in another tab or browser session within the same Hermes profile, subject to native fill origin checks. Existing generic `.env` commands, direct field names and guided setup remain available.

1. A one-time HTTPS form link is sent using the shared delivery setting, without returning the capability URL to the model.
2. The form identifies the site and profile. The user enters a username/email, password and optional authenticator setup key directly into the form, never chat. Raw TOTP keys and supported `otpauth://totp/` URIs are validated through the native code generator before storage; invalid keys save no item and consume the submitted capability.
3. The password is stored with native encrypted `VaultStore` in the bound profile, not in `.env` or a separate password store. The tool waits for a terminal outcome; `saved` requires native metadata readback and returns the handle and origin with `filled: false`.
4. The agent rechecks the page, reads identifier metadata through `browser_vault_list`, enters the identifier, and invokes native `browser_vault_fill`. Saving, filling and successful sign-in are separate results; this plugin does not submit the site's login form.

Browser Vault requests use at most 240 seconds even when configured TTL is higher, leaving headroom below the native dispatch timeout. Ordinary `.env` retains its configured TTL. Expiry, cancellation, supersession, rejection and uncertain post-write results are distinct; an uncertain write must be checked through native metadata before retrying. New saves append native items rather than overwrite an existing login.

The owner/session, profile context and exact HTTPS origin are bound to the storage request; browser identity is not. Ownership, permissions, symlinks/hardlinks and Vault path identity are checked before write. Native path-based writes are not a defense against a hostile same-UID/root process. Identifiers are agent-visible native metadata; passwords are not. Authenticator setup keys are stored by the native encrypted Vault for subsequent native code generation; cards, addresses, third-party password-manager unlocking and restart-resume are outside this feature.

### Choosing the protected-entry workflow

The plugin ships the runtime skill `secure-env-ingress:usage` (separate from installation `setup`). Its tool descriptions explicitly cover **login/username/password** as well as **verification codes/passcodes**, so discovery need not depend on this README or another conversation's memory.

- **Save login/password and optional TOTP setup key:** `browser_vault` with `mode="login"` (or omit mode). No browser required. Saving is not filling or signing in. Afterwards list the native Vault, enter only the public username, and use native password filling on the verified origin. Reuse matching saved entries; support username-first/password-only pages without treating them as OTP forms.
- **Fill a recognized standalone code/passcode field:** `browser_vault` with `mode="code"`, using the current task's supported browser connection. No Vault storage or automatic site submission. The agent resolves multiple candidates, not the user.
- **Write an ENV secret:** `/senv <profile> <FIELD1,FIELD2>`. Do not use this to read secrets back and manually fill a browser.
- **Run a pre-registered trusted action:** `secure_operation`. Such registration is NOT required for browser login/password or code forms.

Native Vault prompts and this plugin's Telegram HTTPS forms are different paths. Native `prompt_unavailable` does not prove this plugin is unavailable: discover its `browser_vault` tool and select the appropriate mode, subject to real session authorization, delivery and HTTPS availability. Code mode is not a substitute for arbitrary account passwords.

On `expired`, reissue only when the user is ready. On `unknown`, inspect the browser without reading the secret before retrying. On `runtime_preflight`, diagnose the failed preparation step: that label is not a root cause. Never loop identical failed calls or claim all secret entry is unavailable based on another tool's error. Login/code links last at most 240 seconds, possibly less by configuration.

These instructions do not change field recognition, origin/form guards or native login filling, and require no Hermes core patch. Tool descriptions/skill registration take effect when the plugin is reloaded; an already-running conversation can still contain older guidance. This improves discovery, not a guarantee of every model's choice or every site's compatibility.

### Standalone verification code and plugin-owned selection (0.6.6)

When the already-attached browser page asks for an email, SMS or authenticator one-time code without a new username/password, use the same plugin tool with `{"origin":"https://example.com","label":"Example verification","mode":"code"}`. The owner receives a single-use HTTPS form with one masked **Verification code** field. Enter the code there (4–16 printable ASCII characters, including punctuation; no spaces or control characters), never in chat or tool arguments. No saved login or authenticator seed is required. The code is not stored in Vault, `.env`, or on disk; the form submits it to the live HTTPS runtime, which inspects the existing page and fills its unambiguous code control over the captured supervisor's CDP WebSocket. The site form is **not** explicitly submitted; some sites auto-submit on input. The tool reports `filled` only after the supervisor returns an exact fill count; uncertain outcomes require checking the page before retrying. The link expires within 240 seconds and cancellation, supersession, replay, changed page/origin/profile, or missing/ambiguous controls fail closed. Numeric and alphanumeric codes are supported, including standard adjacent one-character boxes.

Code mode discovers forms through the existing task-owned CDP supervisor transport, without using its focused page or a patched `focus_page`. One form is selected automatically. Multiple forms return `selection_required` with expiring opaque candidates; Hermes chooses using its login context and calls again with `selection` and the same origin/label. Do not ask the user to identify remote tabs. No secret is requested before selection. Candidate metadata excludes input values, query/fragment, arbitrary page text and non-allowlisted path segments. Models cannot supply a CDP endpoint or executable. Tokens are profile/owner/conversation/task scoped. Before filling, the plugin rechecks the selected document, exact HTTPS origin and stamped fields; navigation/closure never silently redirects to another candidate. Browser restart requires rediscovery. A shared CDP endpoint can expose tabs from other browser contexts; task-scoped selection tokens do not provide browser-context isolation. Use appropriately isolated endpoints when that boundary is required. This uses existing private supervisor transport APIs, so compatibility testing remains necessary, but no local core patches are required. Isolated Chromium tests cover two tabs with the same URL, two forms on one page, registered-tool HTTPS filling, automatic selection, stale selections, changed origin and replaced fields. These tests are not blanket live-account acceptance.

## ENV profile compatibility fix (0.6.4)

Version 0.6.4 restores `/senv <profile> <FIELD,...>` when trusted operation consumers are configured. ENV setup validates its own settings without rejecting or modifying the separate `consumers` section. Unknown ENV settings remain rejected; consumer validation and activation remain the responsibility of the operation loader.

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

## Verification

Run plugin Python tests through a disposable Hermes checkout, not the live profile:

```bash
cd /path/to/disposable/hermes-agent
HERMES_PYTHON=/path/to/hermes/python scripts/run_tests.sh /path/to/plugin/tests/ -q
```

Three strict xfails in the historical Phase 0 probe characterize generic-host routing limitations; they are not failed HTTPS requirements. Add `--runxfail` to expose them as actual assertions.

Local E2E tests use a disposable CA trusted only by that test, a loopback TLS listener, fake values and temporary targets. They exercise both capability modes, HMAC, replay, cancellation, permissions and shutdown. No real bot call, ACME request, firewall change or production `.env` write is required.

Optional browser smoke uses the existing loopback CDP rail at `127.0.0.1:18800`, a fresh unauthenticated context and test-only certificate acceptance:

```bash
PYTHONPATH=. python tests/browser_check.py
# Native Vault form, metadata and password-fill smoke:
PYTHONPATH=.:/path/to/hermes-agent python tests/browser_vault_check.py
# Optionally supply a local reviewed axe-core bundle:
PYTHONPATH=. SENV_AXE_PATH=/path/to/axe.min.js python tests/browser_check.py
```

These automated checks cover browser JS, labels/focus, keyboard flow, 320px reflow, DOM clearing, no Web Storage and test-file creation. An operator has additionally confirmed the ordinary URL `.env` form works with Telegram Android/TalkBack. Mini App did not open in that check; the URL button worked. This does not establish Mini App, all-device, or Browser Vault-specific TalkBack acceptance. Public TLS trust and renewal remain installation-specific checks.
