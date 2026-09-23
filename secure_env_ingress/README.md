# Secure Env Ingress

English-first HTTPS secret-entry forms for Hermes Telegram private chats. `/senv` accepts a configured profile name, never a secret value. Authorized users enter missing `.env` values in a short-lived, one-use HTTPS form, outside chat and LLM input. Existing keys are never overwritten.

This directory is the runtime-only catalog distribution. It contains no privileged certificate installer. Linux/POSIX, Python 3.11+, OpenSSL and the dependencies in `requirements.txt` are required. An operator must separately configure a trusted IP certificate, renewal, an owner-ID allowlist and explicit target/key profiles. No listener starts at import. Mini App mode is disabled by default pending real-client verification.

See the [full setup, security boundaries and test instructions](https://github.com/web3blind/hermes-secure-env-plugin#readme). Administrative TLS helpers in the repository root are separate, manually reviewed operator tools, not part of the catalog plugin. Never run privileged helpers from a runtime-user-writable checkout. Never paste secret values into Telegram messages, including when the plugin is unavailable.
