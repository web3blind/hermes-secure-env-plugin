"""Public Hermes plugin registration; disabled configuration remains non-forwarding."""
import threading
from pathlib import Path
from .setup_handoff import bootstrap_owner_ids, handoff_setup
from .command import CommandController, defensive_hook, diagnostic_command

SETTING_KEYS = (
    'public_ip', 'listen_host', 'listen_port', 'ttl_seconds',
    'allowed_telegram_user_ids', 'profiles', 'cert_path', 'key_path',
    'tls_dir', 'safety_seconds', 'mini_app_enabled',
)


class LazyRuntime:
    """Delay filesystem/TLS work until a command, never while importing the plugin."""
    def __init__(self, settings, home, bot_token):
        self.settings, self.home = settings, home
        self._bot_token = bot_token
        self._runtime = None
        self._lock = threading.RLock()
        self._closed = False

    def _get(self):
        with self._lock:
            if self._closed:
                raise RuntimeError('ingress stopped')
            if self._runtime is None:
                from .runtime import IngressRuntime
                self._runtime = IngressRuntime(self.settings, self.home, self._bot_token)
            return self._runtime

    def refresh(self, settings):
        with self._lock:
            if self.settings != settings:
                if self._runtime is not None:
                    self._runtime.close()
                self._runtime = None
                self.settings = settings

    def create(self, owner, name):
        return self._get().create(owner, name)

    def cancel(self, owner):
        with self._lock:
            if self._runtime is not None:
                self._runtime.cancel(owner)

    def status(self):
        return self._get().status()

    def preflight(self):
        return self._get().preflight()

    def close(self):
        with self._lock:
            self._closed = True
            if self._runtime is not None:
                self._runtime.close()
            self._bot_token = ''


def register(ctx):
    from hermes_constants import get_hermes_home, set_hermes_home_override, reset_hermes_home_override
    home = get_hermes_home()
    def read_settings():
        token = set_hermes_home_override(home)
        try:
            settings = {}
            for key in SETTING_KEYS:
                value = ctx.get_config(key, None)
                if value is not None:
                    settings[key] = value
            return settings
        finally:
            reset_hermes_home_override(token)

    def owner_ids(settings):
        raw = settings.get('allowed_telegram_user_ids', [])
        return frozenset(x for x in raw if type(x) is int and x > 0) if isinstance(raw, list) else frozenset()

    settings = read_settings()
    allowed_ids = owner_ids(settings)
    ctx.register_skill('setup', Path(__file__).parent / 'setup' / 'SKILL.md',
                       description='Install and diagnose secure-env-ingress; never handle secret values.')
    runtimes = []
    closed = False

    def factory(application, adapter):
        if closed:
            return
        from telegram.ext import CommandHandler
        runtime = LazyRuntime(settings, home, application.bot.token)
        async def setup(update):
            token = set_hermes_home_override(home)
            try:
                await handoff_setup(ctx, adapter, update)
            finally:
                reset_hermes_home_override(token)

        def current_owner_ids():
            current = read_settings()
            runtime.refresh(current)
            return owner_ids(current)

        def setup_authorized(owner):
            current = read_settings()
            return ('allowed_telegram_user_ids' not in current
                    and owner in bootstrap_owner_ids(home))

        controller = CommandController(runtime, allowed_ids, setup_handler=setup,
                                       setup_authorized=setup_authorized,
                                       allowed_ids_supplier=current_owner_ids)
        handler = CommandHandler('senv', controller.handle)
        application.add_handler(handler)
        runtimes.append((runtime, application, handler))
        # Non-secret operational evidence for post-restart verification.
        import logging
        import os
        logging.getLogger(__name__).info(
            'secure-env-ingress: Telegram handler registered; pid=%s', os.getpid()
        )

    def close():
        nonlocal closed
        closed = True
        for runtime, application, handler in runtimes:
            runtime.close()
            application.remove_handler(handler)
        runtimes.clear()

    ctx.register_command('senv', diagnostic_command, description='Secure secret entry over HTTPS', args_hint='<profile|setup|status|cancel>')
    ctx.register_hook('pre_gateway_dispatch', defensive_hook)
    ctx.register_platform_handler('telegram', factory)
    ctx.on_unload(close)
