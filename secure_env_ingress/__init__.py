"""Secure environment ingress components; importing does not start a listener."""


def register(ctx):
    """Hermes directory-plugin entrypoint for the runtime-only catalog build."""
    from .plugin import register as register_plugin
    return register_plugin(ctx)
