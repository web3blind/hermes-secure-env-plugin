# One-shot secure operations (0.6.2)

`secure_operation` is separate from `/senv` (ENV writes) and `browser_vault` (login/code). It accepts only `{ "operation": "name", "parameters": { ... } }`. No consumer is shipped or enabled by default; unknown names fail before link issuance. The administrator connects reviewed external Python code through the plugin settings allowlist below, or an integrator calls `register_consumer(home, name, factory)` from `secure_env_ingress.operations` in the trusted process before requests. Both routes share the same profile-scoped registry, reject name collisions and clear registrations on plugin unload. This is not a remote registration endpoint. The **model cannot** supply a module path, command, URL, or executable payload.

## Administrator connection (per active profile)

Install and review an external `.py` file containing a top-level `factory(canonical_json: bytes) -> BoundOperation`. The integrator owns target resolution, validation and side effects; Secure ENV owns only session binding, one-use HTTPS ingress and fixed status. Put nonsecret configuration under the **active profile's** `config.yaml` entry for `secure-env-ingress` (alongside existing HTTPS settings):

```yaml
plugins:
  entries:
    secure-env-ingress:
      settings:
        # Existing HTTPS settings and allowed owners remain here.
        consumers:
          fixed_action:
            path: /absolute/trusted/deployment/consumer.py
            factory: factory
            sha256: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
            requires_verified_principal: false
```

Replace the example digest with `sha256sum /absolute/trusted/deployment/consumer.py` (hash the actual reviewed file), and restart/reload the plugin. The file and its immediate directory must be owned by the gateway process UID and not writable by group/others; the file must be regular, not a symlink, at most 1 MiB. The config must map unique operation identifiers to exactly `path`, `factory`, `sha256`, plus optional boolean `requires_verified_principal`. No config means **disabled**. Invalid configuration, missing files/factories, hash mismatch or registration collisions abort plugin startup (no link). The source file is read and checked before execution, with no `sys.path` addition. Imports inside it still run with full gateway privileges and are **not** pinned or sandboxed by this check; protect the whole deployment and dependency chain. Updates require reviewing the new code, updating its hash, and reloading the plugin; editing config during a running plugin does not activate new operations. Never place secrets in this config.

The alternative programmatic API remains available to trusted embedding code; it must register before any request and does not need this configuration. It cannot override a configured name. The plugin does not own your external consumer's installation, credentials, target-specific approvals or action implementation.

```python
# Administrator-reviewed code, NOT generated/executed on the model's behalf.
import json
from secure_env_ingress.operations import BoundOperation, register_consumer


def factory(canonical_json: bytes) -> BoundOperation:
    public = json.loads(canonical_json)
    if set(public) != {'record'} or public['record'] not in TRUSTED_RECORDS:
        raise ValueError('unsupported record')
    record = TRUSTED_RECORDS[public['record']]
    # Resolve and freeze the exact target and action now; do not read a mutable
    # model-controlled path/URL/command or reinterpret parameters at submission.
    def execute(secret: str) -> None:
        record.use_secret_for_fixed_action(secret)  # bounded, no logging/output
    return BoundOperation(f'Authorize fixed action on record {public["record"]}', execute)

# Only for programmatic integrators (not required with the config above):
register_consumer(selected_profile_home, 'fixed_action', factory)
```

The factory receives canonical JSON bytes (at most 4096 bytes); validate all public parameters, freeze the target and action, and return a truthful, complete, human-readable summary. Do not include private values in parameters or summary. Use a trusted immutable target snapshot and verify external target identity again if it can change. The summary is rendered with `textContent` before the masked secret field. Only a single secret (at most 4096 UTF-8 bytes) reaches `execute` via the HTTPS server; the plugin neither persists it nor forwards it to an HTTP endpoint, environment variable, argument vector, model, chat, Vault, or `.env`. The consumer must itself avoid doing those things. A synthetic encrypted-fixture consumer and real registered-dispatcher/HTTPS test live in `tests/test_secure_operation.py`.

**Trust and authorization:** Consumers execute **in-process as administrator-trusted code**; this registry is not a sandbox and cannot prevent the consumer from reading other memory, logging a password, fabricating a summary, blocking indefinitely, or changing a target after binding. The factory/consumer must enforce its own operation-specific constraints, execution time budget, idempotency and target integrity. Do not install unreviewed/model-written consumers. The plugin's only output is fixed status metadata (`completed`, `unknown`, `rejected`, `expired`, `cancelled`, `superseded`); return values and exception strings are discarded. A callback exception, disconnect or timeout after submission can mean the action already happened: verify the external target; never blindly retry. Once a callback starts, cancellation, expiry or close resolves the waiting tool as `unknown` without waiting for the callback; it **does not stop the action**. The secret and bound consumer can remain in process memory until that callback returns, including after close. One in-flight callback per runtime is allowed; new secure operations are refused as busy until it finishes, even if its result is already `unknown`. High-risk consumers needing hard termination or process isolation should use a separately isolated service, not rely on an in-process timeout.

The tool requires a live bound Telegram session, exact task ID, configured owner, profile home and originating chat/thread. It freezes the operation and canonical parameters in a capability identity, sends the bearer link through configured gateway delivery, and consumes both siblings on first submission. Expiry is capped at 240 seconds; a newer request supersedes the previous one. **Bearer URL possession is authorization to submit, not proof that the submitting person is the Telegram owner**. Anyone who reads/forwards the link can execute. The ordinary link is deliberately retained for accessibility/compatibility. `requires_verified_principal=True` registrations **fail closed**: verified Telegram Mini App delivery for this new tool is not implemented, so such operations cannot issue a link rather than silently downgrading. High-risk consumers requiring verified submitter identity must wait for that transport. Cancellation/expiry cannot undo an already executing trusted callback.

No live registration/deployment is part of this source change.
