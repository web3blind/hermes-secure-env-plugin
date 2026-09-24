"""Public, platform-independent Hermes gateway registration."""
import asyncio
import copy
import threading
from contextvars import ContextVar
from dataclasses import dataclass, field
from pathlib import Path

from .command import SAFE_USAGE, SAFE_ERROR, DIRECT_USAGE, BOOTSTRAP_GUIDANCE, parse_request
from .config import ConfigError, configured_owners, owner_identity
from .setup_handoff import SETUP_REQUEST, bootstrap_owner_ids, setup_paused

SETTING_KEYS = ('public_ip', 'listen_host', 'listen_port', 'ttl_seconds',
                'allowed_telegram_user_ids', 'allowed_owners', 'profiles', 'cert_path',
                'key_path', 'tls_dir', 'safety_seconds', 'mini_app_enabled')
_CAPTURE = ContextVar('secure_env_gateway_command', default=None)

@dataclass
class Captured:
    home: Path
    args: str
    owner: tuple[str, str]
    session_key: str
    task: object = field(repr=False)
    used: bool = False
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def consume(self, args: str, home: Path) -> bool:
        with self.lock:
            if self.used or self.args != args or self.home != home or self.task is not asyncio.current_task():
                return False
            self.used = True
            return True

class LazyRuntime:
    """Delay filesystem/TLS work until an authenticated command."""
    def __init__(self, settings, home, bot_token=''):
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
        with self._generation_lock:
            return self._owner_generations.get(owner, 0)

    def _is_current(self, owner, reservation):
        with self._generation_lock:
            return self._owner_generations.get(owner, 0) == reservation

    def create_reserved(self, owner, name, reservation, prepare):
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

    def close(self):
        with self._lock:
            self._closed = True
            if self._runtime is not None:
                self._runtime.close()
            self._bot_token = ''

def register(ctx):
    from hermes_constants import get_hermes_home, set_hermes_home_override, reset_hermes_home_override
    home = Path(get_hermes_home())
    closed = False
    runtimes = {}
    runtime_lock = threading.Lock()

    def runtime_for(selected_home):
        with runtime_lock:
            if selected_home not in runtimes:
                runtimes[selected_home] = LazyRuntime({}, selected_home)
            return runtimes[selected_home]

    def read_settings(selected_home):
        token = set_hermes_home_override(selected_home)
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
            return {key: copy.deepcopy(source[key]) for key in SETTING_KEYS if key in source}
        finally:
            reset_hermes_home_override(token)

    def hook(*, event, gateway, **_kwargs):
        _CAPTURE.set(None)
        if closed or getattr(event, 'internal', False):
            return None
        if event.get_command() != 'senv':
            return None
        args = event.get_command_args().strip()
        source = getattr(event, 'source', None)
        platform = getattr(getattr(source, 'platform', None), 'value', None)
        identity = owner_identity(platform, getattr(source, 'user_id', None))
        if (identity is None or getattr(source, 'is_bot', True) or not getattr(source, 'chat_id', None)
                or getattr(source, 'profile_route_rejected', False) is True
                or getattr(source, 'chat_type', None) not in ('dm', 'group', 'thread', 'channel')):
            return None
        # The gateway has normalized source/profile but has NOT authorized it yet.
        # This is inert provenance, not a grant; the handler runs only after host auth.
        if not args or parse_request(args) is None:
            return None
        from gateway.session import build_session_key
        try:
            from gateway.session_identity import identity_of
        except ImportError:
            # Older hosts scope the entire routed handler through HERMES_HOME.
            # Validate a named source against that canonical active profile;
            # never reconstruct a profile path or borrow the default home.
            from hermes_cli.profiles import get_active_profile_name
            source_profile = getattr(source, 'profile', None)
            if source_profile and source_profile != get_active_profile_name():
                return None
            route = None
        else:
            route = identity_of(source)
            if route is None and getattr(source, 'profile', None):
                return None
        selected_home = Path(route.runtime_home) if route is not None else home
        # A plugin registered for one profile cannot serve another routed home.
        if selected_home != home or Path(get_hermes_home()) != home:
            return None
        _CAPTURE.set(Captured(selected_home, args, identity, build_session_key(source, profile=source.profile), asyncio.current_task()))
        return None

    async def command(raw_args):
        captured = _CAPTURE.get()
        _CAPTURE.set(None)  # Consume before any await; copied child tasks cannot replay it.
        if (closed or captured is None or Path(get_hermes_home()) != home
                or not captured.consume(raw_args, home)):
            return SAFE_ERROR
        owner = captured.owner
        selected_home = captured.home
        runtime = runtime_for(selected_home)
        try:
            settings = read_settings(selected_home)
            try:
                allowed = configured_owners(settings)
            except ConfigError:
                allowed = frozenset()
            bootstrap = (owner[0] == 'telegram' and owner[1].isascii() and owner[1].isdecimal()
                         and 'allowed_telegram_user_ids' not in settings
                         and 'allowed_owners' not in settings
                         and int(owner[1]) in bootstrap_owner_ids(selected_home))
            if owner not in allowed:
                if not bootstrap:
                    return SAFE_ERROR
                if raw_args != 'setup':
                    return BOOTSTRAP_GUIDANCE
            request = parse_request(raw_args)
            if request is None:
                return SAFE_USAGE
            if request.profile == 'setup':
                if setup_paused():
                    return 'Hermes is paused. Resume before installation assistance.'
                # Injection is permitted only by Hermes host policy, never by this plugin.
                try:
                    accepted = ctx.inject_message(SETUP_REQUEST, role='user', session_key=captured.session_key) is True
                except Exception:
                    accepted = False
                if accepted:
                    return 'Installation assistance was queued. No changes are confirmed. Never send values in chat.'
                return ('To request installation assistance, send this ordinary message to Hermes: '
                        + SETUP_REQUEST + ' Administrative changes still require approval.')
            if owner not in allowed:
                return SAFE_ERROR
            if request.profile == 'cancel':
                await asyncio.to_thread(runtime.cancel, owner)
                return 'The link has been cancelled.'
            if request.profile == 'status':
                def status():
                    with runtime._lock:
                        current = read_settings(selected_home)
                        if owner not in configured_owners(current):
                            return SAFE_ERROR
                        runtime.refresh(current)
                        return runtime.status()
                return await asyncio.to_thread(status)
            reservation = runtime.reserve(owner)
            def create():
                def prepare():
                    definition = None
                    if request.fields:
                        from .setup_config import define_named_profile
                        definition = define_named_profile(home=selected_home, owner=owner,
                                                          profile=request.profile, keys=request.fields)
                    current = read_settings(selected_home)
                    if owner not in configured_owners(current):
                        from .setup_config import UnauthorizedOwnerError
                        raise UnauthorizedOwnerError('owner is not authorized')
                    if not request.fields and request.profile not in current.get('profiles', {}):
                        return None, None
                    return definition, current
                return runtime.create_reserved(owner, request.profile, reservation, prepare)
            operation = asyncio.create_task(asyncio.to_thread(create))
            try:
                definition, links = await asyncio.shield(operation)
            except asyncio.CancelledError:
                try:
                    await asyncio.shield(operation)
                except Exception:
                    pass
                await asyncio.to_thread(runtime.cancel, owner)
                raise
            if links is None:
                return DIRECT_USAGE
            # The HTTPS fragment is a bearer credential; only send to the originating,
            # operator-trusted conversation. Never echo the submitted values.
            return (f"Fields: {', '.join(definition.keys)}. " if definition else '') + (
                'One-time HTTPS form (bearer link): ' + links['url'] +
                ' Do not forward; anyone in this conversation can open it. '
                'Enter values only on the page. Use /senv only in trusted chats.')
        except asyncio.CancelledError:
            raise
        except Exception:
            return SAFE_ERROR

    ctx.register_skill('setup', Path(__file__).parent / 'setup' / 'SKILL.md',
                       description='Install and diagnose secure-env-ingress; never handle secret values.')
    ctx.register_hook('pre_gateway_dispatch', hook)
    ctx.register_command('senv', command, description='Secure secret entry over HTTPS',
                         args_hint='<profile> [field1,field2]|setup|status|cancel')
    def close():
        nonlocal closed
        closed = True
        for runtime in runtimes.values():
            runtime.close()
    ctx.on_unload(close)
