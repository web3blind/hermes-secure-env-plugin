# Hermes secure-env ingress

A profile-scoped, on-demand HTTPS form for adding missing `.env` keys. `/senv` accepts a **configured profile name, never a secret**. Secret values travel directly from the browser to the HTTPS listener, not through a Telegram message or an LLM tool call.

**English-first, Linux/POSIX plugin.** Each installation requires its own trusted TLS certificate, verified renewal and Internet reachability. Mini App launch is off by default until its real-client compatibility gate is verified. Automated browser/backend tests do not establish Telegram Mini App or TalkBack compatibility. Never enter secrets in chat; enter them only in the HTTPS form.

## Installation, separately from TLS setup

Tested against Hermes upstream `9fe737aef2dd18a351dff3c4de608d63879a6524`, Python 3.11 on Linux. No broader release-floor claim is made. Runtime requires POSIX ownership/modes, `flock`, `O_NOFOLLOW`, OpenSSL and the bounded dependencies in `pyproject.toml` / `uv.lock`.

Hermes catalog submissions target the runtime-only `secure_env_ingress/` subdirectory, which has its own manifest and bounded dependencies. The root `scripts/` administrative TLS helpers are not part of the catalog install. Until the catalog PR is merged, use either reviewed installation method below.

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
        mini_app_enabled: false
        profiles:
          service:
            target_mode: hermes
            keys: [SERVICE_TOKEN]
          project:
            target_mode: project
            target_path: "/absolute/project/.env"
            keys: [SERVICE_TOKEN, SERVICE_SECRET]
```

- v1 runtime configuration uses IPv4 literals and a stable public address. Never put the bot token, private key or secret values in this configuration; the plugin gets the current Telegram bot token from the native application in memory.
- `hermes` resolves `.env` inside the active `HERMES_HOME`. `skill`, `project` and `custom` require the exact absolute `.env` target; no filename supplied by the browser is accepted. Parent directories must already exist, be owned by the runtime user, and not be group/world-writable. Symlink traversal is rejected for target files.
- Existing target must be a regular, single-linked file with mode `0600`, owned by the runtime user. New files are atomically created with `0600`. Existing values are never replaced. A target change observed before commit invalidates the binding. The final check-and-replace is protected against other UIDs by the validated parent permissions and serialized among cooperative writers; an uncooperative same-UID/root writer is outside this guarantee.
- TLS certificate is mode `0644`, key `0600`, owned by the runtime user inside a private runtime directory. Certificate chain, IP SAN, validity and key match are checked before opening the listener. No untrusted/self-signed production fallback exists.
- TTL is 120–600 seconds. There is one active browser/Mini-App pair per runtime; a new request replaces the previous pair. Consuming either invalidates both. This deliberately stricter single-pair policy also serializes the target workflow.

## Guided setup

After enabling the plugin, send `/senv setup` in the bot's private chat. Hermes handles installation and diagnosis using the bundled `secure-env-ingress:setup` skill and deterministic setup scripts; you do not need to edit YAML or assemble shell commands yourself. The agent requests consent for package installation, certificate issuance and other privileged changes. It can use existing sudo access, but cannot manufacture missing privileges or bypass approval policy.

If the plugin already has the operator-granted `plugins.entries.secure-env-ingress.allow_gateway_injection: true` permission and the conversation exists, it queues a fixed **installation-only** task in that conversation. Otherwise it presents a one-tap setup request: tapping it sends a normal user message to the agent. The plugin never grants itself injection permission, invokes a separate model/provider, or forwards the original command/reply/media. A queued request is not proof of completed setup.

Before ingress settings exist, only explicit positive numeric IDs in the selected profile's private `TELEGRAM_ALLOWED_USERS` configuration can use this bootstrap. Wildcards, allow-all and another profile's environment are not setup ownership. Once ingress owners are configured, that explicit owner list applies. If no trusted owner is configured, establish it through the normal Hermes operator setup first.

The installer supports a bounded Debian/Ubuntu + systemd + snap path, checks prerequisites, installs missing packages after approval, and runs staging/production TLS and renewal checks through the hardened helpers. Unsupported distributions, busy ports, networking failures or missing privileges become an installation diagnosis task for the agent, not a reason to relax security. Existing services/firewall rules and gateway restarts are not changed without separate approval.

Fresh setup starts with a dedicated test target. The agent verifies configuration, TLS and renewal; the owner enters a **made-up value only** in the real HTTPS form to confirm the external path. Adding real target profiles is a separate explicit choice. An already-loaded plugin refreshes its own settings on the next command; loading newly installed code may still require an owner-approved gateway restart.

## Use

Send `/senv service` to the bot **in a private, non-Business chat**. Only configured numeric owner IDs are allowed. Open the normal link and enter values into the labeled password fields. When explicitly enabled after client checks, a separate Mini App button uses its own mode-bound capability and requires fresh, correctly signed Telegram `initData` for the requesting user.

- `/senv setup`: installation and diagnosis assistance using the agent and reviewed scripts; never forwards secret input.
- `/senv status`: safe readiness status, no token, URL or value dump.
- `/senv cancel`: invalidates the active owner's session and closes an idle listener.
- CLI/generic gateway command handler is guidance only; web-ingress launch is Telegram-native.

The listener starts only after authorization, target and TLS validation. A profile-local leader lock prevents a second instance. It closes on cancellation, consumption/expiry (short cleanup interval), or plugin unload. Creating a later session validates the current deployed TLS material again.

## Security boundaries

Never type `/senv KEY=value` or paste a key into chat. While loaded, the native handler rejects values without echoing them. **An absent/broken plugin cannot protect an accidental secret pasted into chat**: Telegram has already received it and Hermes may treat the message as ordinary model input. This accepted limitation does not justify sending values in command arguments.

Capabilities are random 256-bit strings, held in RAM as hashes, mode/user/profile/target-bound, absent from initial HTTP requests because they use fragments. GET/prefetch does not consume them. The page strips launch parameters from history and makes strict JSON POSTs. The backend consumes a capability before validating/writing authenticated submissions; rejected authenticated input and uncertain write failure are terminal, not retryable. The page still shows success or an unconfirmed-result message and clears its fields. If the request never reaches the server, or its envelope is rejected before authentication, immediate server-side invalidation cannot be guaranteed; the TTL/cancel command still applies. Request bodies, tokens and exception detail are not logged. Key names, not values, are returned.

The first-party page has no analytics, external scripts/fonts, SDK, service worker or Web Storage. Mini App launch data is read from Telegram launch parameters and checked server-side; stripped fragments are unsupported, never a reason to weaken auth. Framing stays denied until a separately reviewed real-client exception is needed. No Telegram `sendData`/cloud storage is used.

The web flow rejects empty, multiline, NUL, oversized and `${...}`-style values (dotenv consumer interpolation would alter the latter). A new link is needed after any terminal error. The writer supports escaped multiline serialization for potential local reuse, but the web form does not. Existing dotenv files are parsed without evaluating their values; malformed/duplicate assignments fail closed. Atomic replacement uses the exact bound target identity, so simultaneous/stale sessions cannot silently update a changed file.

Limits: browser/password managers can ignore autocomplete hints; Python cannot guarantee RAM zeroization; same-UID/root or a compromised browser/OS is outside confidentiality guarantees. Telegram receives capability links, never form values. Do not log bot responses at another layer or share bearer links.

## TLS operations (not performed by development tests)

Let's Encrypt IP certificates use profile `shortlived` (160 hours); use a verified current Certbot with IP support, at least 5.4 for the documented webroot path. HTTP-01 needs public port 80 during every renewal. Setup scripts are separate from runtime and require explicit operator approval for privileged changes. The lower-level `scripts/setup_tls.py` does not install Certbot: an existing trusted Certbot >=5.4, a verified packaged renewal scheduler and reachable port 80 are its prerequisites. The guided `scripts/install_host.py` orchestrator can install the classic Certbot snap and a fixed root-owned Python environment with pinned dependencies after approval. It accepts only `/snap/bin/certbot` paired with `snap.certbot.renew.timer`; it does not change firewall rules. Bootstrap the orchestrator directly with trusted `/usr/bin/python3 -I -S`, not the Hermes runtime environment. **Never sudo a script from the runtime-user-writable checkout.** An administrator must first obtain/review the whole bundle through a trusted channel and provision it (including the interpreter/dependencies) under a root-owned, non-group/world-writable tree, separate from the runtime account. Run the privileged entry point only from that trusted installation. Source ownership checks inside a Python script cannot protect an administrator who has already executed a modified script. Apply additionally refuses untrusted source/ancestor ownership and reads sources from checked no-follow descriptors; no signed release or privileged installation has been produced by these development tests. Destination writes run as the runtime account, not root. Staging uses a separate lineage, disables directory hooks and does not install a production deploy hook. The installed production hook never accepts custom test CA roots and ignores unrelated renewed lineages. The renewal dry-run is restricted to the selected certificate and also disables directory hooks. Start with staging; staging is not a trusted production certificate. Do not reuse an ACME account or TLS key as an ingress capability.

From the checkout, `python -m scripts.setup_tls --help`, `python -m scripts.deploy_certificate --help` and `python -m scripts.external_probe --help` describe the local helpers. Preflight/dry-run is not proof of remote reachability. Certbot renewal/timer, deploy-hook installation and `renew --dry-run` require a controlled host setup. The deploy helper validates source confinement and certificate/key pairing, then switches an atomic private generation; the runtime uses `current/fullchain.pem` and `current/privkey.pem`.

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
# Optionally supply a local reviewed axe-core bundle:
PYTHONPATH=. SENV_AXE_PATH=/path/to/axe.min.js python tests/browser_check.py
```

This proves browser JS, labels/focus, keyboard flow, 320px reflow, DOM clearing, no Web Storage and actual test-file creation. It does not prove trust of a public IP certificate or operation in Telegram Android/TalkBack, iOS, Desktop or Web; those rows remain unverified until actual device tests.
