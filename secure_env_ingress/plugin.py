"""Public Hermes plugin registration; disabled configuration remains non-forwarding."""
import copy
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
        self._generation_lock = threading.Lock()
        self._owner_generations = {}
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

    def reserve(self, owner):
        """Capture cancellation ordering before a form worker is scheduled."""
        with self._generation_lock:
            return self._owner_generations.get(owner, 0)

    def _is_current(self, owner, reservation):
        with self._generation_lock:
            return self._owner_generations.get(owner, 0) == reservation

    def create_reserved(self, owner, name, reservation, prepare):
        """Serialize definition, config snapshot, refresh, and capability issue."""
        with self._lock:
            if not self._is_current(owner, reservation):
                raise RuntimeError('form request was cancelled')
            definition, settings = prepare()
            if not self._is_current(owner, reservation):
                raise RuntimeError('form request was cancelled')
            if settings is None:
                return definition, None
            self.refresh(settings)
            return definition, self.create(owner, name)

    def cancel(self, owner):
        with self._generation_lock:
            self._owner_generations[owner] = self._owner_generations.get(owner, 0) + 1
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
            from hermes_cli.plugins import load_config_readonly
            raw = load_config_readonly() or {}
            try:
                entry = raw['plugins']['entries'][ctx.plugin_id]
            except (KeyError, TypeError):
                return {}
            source = entry.get('settings') if isinstance(entry, dict) else None
            if not isinstance(source, dict) and isinstance(entry, dict):
                source = entry.get('config')
            if not isinstance(source, dict):
                return {}
            return {
                key: copy.deepcopy(source[key])
                for key in SETTING_KEYS
                if key in source
            }
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
            return owner_ids(current)

        def setup_authorized(owner):
            current = read_settings()
            return ('allowed_telegram_user_ids' not in current
                    and owner in bootstrap_owner_ids(home))

        def create_form(owner, name, fields, reservation):
            def prepare():
                definition = None
                if fields:
                    from .setup_config import define_named_profile
                    definition = define_named_profile(
                        home=home, owner=owner, profile=name, keys=fields,
                    )
                current = read_settings()
                if owner not in owner_ids(current):
                    from .setup_config import UnauthorizedOwnerError
                    raise UnauthorizedOwnerError('owner is not authorized')
                profiles = current.get('profiles', {})
                if not fields and (
                    not isinstance(profiles, dict) or name not in profiles
                ):
                    return None, None
                return definition, current

            return runtime.create_reserved(owner, name, reservation, prepare)

        def read_status(owner):
            with runtime._lock:
                current = read_settings()
                if owner not in owner_ids(current):
                    from .setup_config import UnauthorizedOwnerError
                    raise UnauthorizedOwnerError('owner is not authorized')
                runtime.refresh(current)
                return runtime.status()

        controller = CommandController(runtime, allowed_ids, setup_handler=setup,
                                       setup_authorized=setup_authorized,
                                       allowed_ids_supplier=current_owner_ids,
                                       form_creator=create_form, status_reader=read_status)
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

    ctx.register_command('senv', diagnostic_command, description='Secure secret entry over HTTPS', args_hint='<profile> [field1,field2]|setup|status|cancel')
    ctx.register_hook('pre_gateway_dispatch', defensive_hook)
    ctx.register_platform_handler('telegram', factory)
    ctx.on_unload(close)
