"""Hermes directory-plugin entrypoint; no import-time actions."""


def register(ctx):
    from .secure_env_ingress.plugin import register as register_plugin
    return register_plugin(ctx)
