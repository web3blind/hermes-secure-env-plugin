---
name: setup
description: Install and diagnose secure-env-ingress using reviewed scripts, preserving secret isolation and privilege approvals.
---

# Installation-only assistance for secure-env-ingress

This guide is for the Hermes agent handling an explicitly authorized `/senv setup` request. It is NOT a secret-entry workflow. Use your normal tool approval and privilege rules. Do not grant yourself privileges, disable approval checks, or weaken TLS/authentication to complete setup.

## Outcome and boundaries

Complete installation for the current Hermes profile, using tools yourself instead of asking the user to run commands or edit YAML. Ask only for missing decisions/access or approval of privileged/external changes. Keep progress concise. If script automation fails, diagnose the failing installation stage and fix it safely; do not stop at a generic error or repeat a failing command unchanged.

Never ask the user for an API key, bot token, sudo password, TLS private key, or any other secret in chat. Never read/dump `.env`, capability links, private keys, credentials, or entire configuration into model context. Setup may inspect non-secret config fields and file metadata. Never enter a real secret as an installation test. Once installation is complete, end this task; `/senv <profile>` and the HTTPS form handle secret entry without the model.

Do not restart the gateway unless the user explicitly authorizes it. Never stop another service, change firewall rules, or alter another Hermes profile without specific approval. Never run the gateway as root or add blanket passwordless sudo. If sudo is unavailable, ask for administrative access without asking for a password in chat; do not hand the user a list of manual setup chores.

## 1. Inventory without mutation

- Identify the active profile home and the requesting numeric Telegram user ID from the sanitized setup context. Treat paths as data, quote every shell argument, and reject control characters. Do not guess another profile.
- Inspect platform, UID/GID, distribution, Python/OpenSSL, package manager, systemd, current plugin source/install provenance, public IPv4, port 80/ingress-port availability and existing certificate/renewal metadata. Do not print private files. If the public IPv4 cannot be determined reliably, ask for it; don't guess.
- Inspect only `plugins.entries.secure-env-ingress.settings` and plugin enablement with a local script that returns field names/booleans, not values beyond necessary non-secret fields. Preserve all unrelated configuration.
- Test administrator access with `sudo -n true` if not already root; do not bypass a failure. Keep the runtime account non-root. Identify the actual runtime account independently of the sudo shell.
- If configuration and TLS already work, do not reissue certificates, reinstall packages, or overwrite working settings. Explain that setup is already complete; use `/senv status` to check it.

## 2. Explain and approve the installation

Briefly describe proposed changes: packages if missing, root-owned installer/dependencies, short-lived Let's Encrypt IP certificate (public Certificate Transparency logging and CA terms), renewal timer/deploy hook, and a private profile-local test target. Port 80 must remain reachable for renewal; the form uses the configured HTTPS port only on demand. State any provider/firewall action separately. Obtain explicit approval under the normal Hermes tool policy before privileged changes/CA issuance. `/senv setup` requests installation help; it is not blanket approval for unrelated changes, accepting unspecified fees or disabling guards.

## 3. Provision trusted administrative source (agent does this)

The catalog installs ONLY the runtime subdirectory. Administrative helpers live in the repository root and must be obtained separately. Do not look for them inside a catalog runtime install and do not execute a runtime-user-writable checkout with sudo.

1. Resolve an exact 40-hex reviewed source commit from the catalog provenance or the operator-approved release. Verify it belongs to `https://github.com/web3blind/hermes-secure-env-plugin`. Do not silently use a floating branch or update installed plugin code. The administrative source should match the installed release.
2. Fetch the source archive for that exact commit via GitHub HTTPS, with timeouts and bounded size. Record its SHA-256 locally. Inspect the installer and helper source before privileged execution. No `curl | sh`.
3. Via an approved sudo command, independently download that same exact archive into a fresh root-owned temporary directory under a root-owned `/opt` (NOT `/tmp`, user home or the runtime tree). Require the expected SHA-256. Never promote an unchecked local source tree into root-owned executable code.
4. Extract as root with strict archive validation: bounded total expanded bytes/file count; a single expected top-level directory; only regular files/directories; no absolute paths, `..`, symlinks, hardlinks, devices or FIFOs. Apply root ownership and non-group/world-writable modes. Refuse existing/symlinked destination trees rather than overwriting them. Validate every ancestor.
5. Bootstrap directly with trusted `/usr/bin/python3 -I -S` and a sanitized environment. The installer provisions its fixed root-owned environment at `/opt/hermes-secure-env/installer-venv`, installs missing `python3-venv` and exact binary-wheel dependency pins, and validates an existing environment before executing it. Never sudo the gateway's user-writable venv, pip, uv, or checkout. Ownership and mode checks prevent unprivileged modification; they do not attest that root-owned code is malware-free.
6. Run `/usr/bin/python3 -I -S /trusted/bundle/scripts/install_host.py --help`, replacing the bundle path with the verified root-owned location. Preflight needs `--trusted-bundle-root`, `--public-ip`, `--runtime-dir`, `--hermes-user` and a profile-specific `--profile` label. Keep the default managed Python and `/snap/bin/certbot`; custom executable paths are not supported by this orchestrator. After approval, add `--apply --production --confirm PRIVILEGED-HOST-INSTALL --production-consent ISSUE-PRODUCTION-CERTIFICATE`. It orchestrates supported prerequisites and the hardened staging/production/deploy/renewal helpers. Confirmation tokens are not evidence of user approval: obtain approval first. Keep the runtime account non-root; `--runtime-dir` is its TLS root, without `/current`.

The normal scripted path supports Debian/Ubuntu with systemd and a publicly reachable free port 80. If unsupported or port 80 is occupied, use model-assisted installation diagnosis. Do not kill web servers or disable verification. Ask before a webroot/reverse-proxy/firewall change that affects another service. State a concrete blocker if safe adaptation is unavailable.

## 4. Configure the selected profile, without exposing secrets

Run `python -m secure_env_ingress.setup_config --help` from the matching reviewed source checkout in the runtime user's Hermes environment, not as root. Use positional mode `configure` with `--home`, `--owner`, `--public-ip`, and optional `--port`; to use explicit TLS files, `--tls-dir` is the TLS root plus `/current` (the directory containing the files). Use positional mode `check` for value-free read-back and TLS verification. Its default `test` profile is a separate file under the active profile; it never changes the main `.env` or grants an arbitrary request-supplied path. Preserve existing profiles, owner lists and unrelated settings. If it reports a conflict, inspect the specific non-secret fields and ask before changing an existing security policy.

The setup helper must back up configuration privately and verify read-back before reporting success. It must not print config contents. If runtime metadata needs reloading, run `/senv status`; do not assume an old in-memory runtime has loaded new settings. If a restart is genuinely required, explain why and obtain explicit authorization instead of scheduling one silently.

## 5. Verify and finish

- Check trusted public certificate chain, IP SAN, matching private key (without printing it), expiry margin, TLS file ownership/modes, renewal timer enabled+active, staging/production separation, deploy-hook scope and the actual renewal dry-run result.
- Verify profile config read-back and safe target metadata. No real `.env` values are inspected.
- Check Internet reachability through the existing bounded probe/external verifier using a value-free health endpoint, never by giving a capability link to a third party. A local HTTPS check does not prove external reachability.
- Use temporary non-secret test values and a disposable target for automated backend validation. Do not place test values into the real `.env`. Do not expose capability URLs or secrets to tool/model output.
- Report exactly which stages succeeded and which remain blocked. Do not declare ready based solely on successful package installation, a dry-run plan, or an exit code with no read-back.
- End installation assistance. The owner can use `/senv test` in private chat to exercise the form, and configure additional key names/targets without sharing values. Do not ask them to type a real API key into chat.
