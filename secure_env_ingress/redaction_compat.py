"""Host redaction compatibility; never silently skip secret registration."""
import inspect


def register_context_secret(value, *, kind):
    from agent.redact import register_vault_redaction_value
    # Older supported hosts have only (value). Their global registration is
    # stricter (more false positives) than current context-only OTP/CVC policy.
    # Decide by signature, not by catching errors from a registration operation.
    signature = inspect.signature(register_vault_redaction_value)
    try:
        signature.bind(value, kind=kind)
    except TypeError:
        signature.bind(value)  # Unknown/incompatible API refuses before filling.
        register_vault_redaction_value(value)
    else:
        register_vault_redaction_value(value, kind=kind)
