"""Public, platform-independent Hermes gateway registration."""
import asyncio
import copy
import json
import time
import threading
from contextvars import ContextVar
from dataclasses import dataclass, field
from pathlib import Path

from .command import SAFE_USAGE, SAFE_ERROR, DIRECT_USAGE, BOOTSTRAP_GUIDANCE, parse_request
from .config import ConfigError, configured_owners, owner_identity
from .setup_handoff import SETUP_REQUEST, bootstrap_owner_ids, setup_paused
from .vault_ingress import capture_browser_target, assert_profile_home
from .delivery import Delivery

SETTING_KEYS = ('public_ip', 'listen_host', 'listen_port', 'ttl_seconds',
                'allowed_telegram_user_ids', 'allowed_owners', 'profiles', 'cert_path',
                'key_path', 'tls_dir', 'safety_seconds', 'mini_app_enabled', 'delivery')
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
    source_chat: str = ''
    source_thread: str = ''
    gateway: object = field(default=None, repr=False)

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

    def create_vault(self, owner, target):
        return self._get().create_vault(owner, target)

    def cancel_group(self, group_id):
        with self._lock:
            if self._runtime is not None:
                self._runtime.cancel_group(group_id)

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
    gateway_ref = None

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
        nonlocal gateway_ref
        _CAPTURE.set(None)
        if closed or getattr(event, 'internal', False):
            return None
        # Transport reference only; never an authorization grant. The tool
        # independently verifies its trusted session/owner/profile binding.
        if gateway is not None:
            import weakref
            try:
                gateway_ref = weakref.ref(gateway)
            except TypeError:
                gateway_ref = None
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
        _CAPTURE.set(Captured(selected_home, args, identity, build_session_key(source, profile=source.profile),
                              asyncio.current_task(), source_chat=str(source.chat_id),
                              source_thread=str(getattr(source, 'thread_id', '') or ''), gateway=gateway))
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
            # The HTTPS fragment is a bearer credential. Send it exactly once through
            # the selected gateway transport; the command response is an ack only.
            message = (f"Fields: {', '.join(definition.keys)}. " if definition else '') + (
                'One-time HTTPS form (bearer link): ' + links['url'] +
                ' Do not forward; anyone in this conversation can open it. '
                'Enter values only on the page. Use /senv only in trusted chats.')
            delivery = Delivery(settings.get('delivery', 'this_chat'), selected_home)
            try:
                await asyncio.wait_for(delivery.send_gateway(captured.gateway, owner[0],
                    captured.source_chat, captured.source_thread, message), timeout=18)
            except asyncio.CancelledError:
                await asyncio.shield(asyncio.to_thread(runtime.cancel_group, links['group_id']))
                raise
            except Exception:
                await asyncio.to_thread(runtime.cancel_group, links['group_id'])
                return SAFE_ERROR
            destination = ('configured platform home' if delivery.mode == 'home'
                           else 'originating chat')
            return f'One-time form sent to the {destination}. Do not forward the link.'
        except asyncio.CancelledError:
            raise
        except Exception:
            return SAFE_ERROR

    async def vault_tool(args, *, task_id=None, session_id=None, **_kwargs):
        """Only trusted gateway context + dispatcher identity may issue a form."""
        links = None
        runtime = None
        try:
            from gateway import session_context as sc
            def bound(var):
                value = var.get()
                return None if value is sc._UNSET else value
            if closed or not isinstance(args, dict) or set(args) != {'origin', 'label'}:
                raise ValueError('invalid request')
            if bound(sc._SESSION_PLATFORM) != 'telegram' or bound(sc._CRON_SESSION) != '':
                raise ValueError('not an interactive Telegram turn')
            from agent.delegation_context import is_delegated_child_context
            if is_delegated_child_context():
                raise ValueError('delegated turn')
            sid = bound(sc._SESSION_ID)
            skey = bound(sc._SESSION_KEY)
            owner_text = bound(sc._SESSION_USER_ID)
            chat = bound(sc._SESSION_CHAT_ID)
            chat_type = bound(sc._SESSION_CHAT_TYPE)
            thread = bound(sc._SESSION_THREAD_ID)
            profile = bound(sc._SESSION_PROFILE)
            from hermes_constants import profile_name_for_home
            expected_profile = profile_name_for_home(home) or 'default'
            if (not sid or not skey or not task_id or sid != task_id or
                    (session_id and session_id != sid) or not owner_text or
                    not owner_text.isdecimal() or ('telegram', owner_text) not in configured_owners(read_settings(home)) or
                    not chat or not str(chat).lstrip('-').isdecimal() or
                    chat_type not in ('dm', 'group', 'forum') or
                    profile not in ((expected_profile, '') if expected_profile == 'default' else (expected_profile,))):
                raise ValueError('session mismatch')
            assert_profile_home(home)
            target = capture_browser_target(args['origin'], args['label'], task_id, sid, skey)
            gateway = gateway_ref() if gateway_ref is not None else None
            if gateway is None:
                raise ValueError('gateway unavailable')
            runtime = runtime_for(home)
            current = read_settings(home)
            runtime.refresh(current)
            delivery = Delivery(current.get('delivery', 'this_chat'), home)
            # No model-supplied destination. The actual chat/thread come from bound gateway context.
            delivery.target('telegram', chat, thread)
            creation = asyncio.create_task(asyncio.to_thread(runtime.create_vault, ('telegram', owner_text), target))
            try:
                links = await asyncio.shield(creation)
                from .vault_ingress import assert_browser_target
                assert_profile_home(home)
                await asyncio.to_thread(assert_browser_target, target)
                text = ('One-time HTTPS login form: ' + links['url'] + ' for ' + target.origin + '. Anyone who can read this message can use the link. '
                        'Do not use a public or untrusted chat. Do not forward it. Saving does not fill or sign in.')
                delivery_task = asyncio.create_task(
                    delivery.send_gateway(gateway, 'telegram', chat, thread, text))
                try:
                    await asyncio.wait_for(asyncio.shield(delivery_task),
                                           timeout=min(18, max(0, links['expires_at'] - time.monotonic())))
                except asyncio.CancelledError:
                    delivery_task.cancel()
                    raise
                except Exception as delivery_error:
                    delivery_task.cancel()
                    await asyncio.shield(asyncio.to_thread(runtime.cancel_group, links['group_id']))
                    prior = links['completion'].result() if links['completion'].done() else {'status': 'send_failed'}
                    if prior['status'] != 'saved':
                        status = ('unknown' if prior['status'] == 'unknown' else
                                  'expired' if isinstance(delivery_error, asyncio.TimeoutError)
                                  and time.monotonic() >= links['expires_at'] else 'send_failed')
                        return json.dumps({'success': False, 'status': status,
                            'saved': None if status == 'unknown' else False,
                            'filled': False, 'error': 'Login form delivery failed, expired or write status is unknown.'})
                # The tool remains suspended until the real HTTPS submission commits (or
                # the capability expires). The Future holds metadata only, never form values.
                completion = links['completion']
                try:
                    outcome = await asyncio.wait_for(
                        asyncio.shield(asyncio.wrap_future(completion)),
                        timeout=max(0, links['expires_at'] - time.monotonic()))
                except asyncio.TimeoutError:
                    # A write holding the runtime lock may finish concurrently. Revoke
                    # this exact group first, then read its authoritative outcome.
                    await asyncio.shield(asyncio.to_thread(runtime.cancel_group, links['group_id']))
                    outcome = completion.result() if completion.done() else {'status': 'expired'}
                    if outcome['status'] == 'cancelled':
                        outcome = {'status': 'expired'}
                if outcome['status'] == 'saved':
                    return json.dumps({'success': True, 'status': 'saved', 'saved': True,
                        'filled': False, 'handle': outcome['handle'], 'origin': outcome['origin'],
                        'next': 'Recheck current browser page and origin, then use native browser_vault_list, type the identifier with browser_type and call native browser_vault_fill. Saving did not fill or sign in.'})
                return json.dumps({'success': False, 'status': outcome['status'],
                    'saved': None if outcome['status'] == 'unknown' else False, 'filled': False,
                    'error': 'Login was not confirmed saved. Recheck native browser_vault_list before retrying if status is unknown.'})
            except BaseException:
                # A cancelled to_thread worker can complete AFTER its coroutine is cancelled.
                # Wait for that exact issuance, then revoke it; never revoke a newer owner request.
                if links is None:
                    try:
                        links = await asyncio.shield(creation)
                    except Exception:
                        pass
                if links and links.get('group_id'):
                    await asyncio.shield(asyncio.to_thread(runtime.cancel_group, links['group_id']))
                raise
        except asyncio.CancelledError:
            raise
        except BaseException:
            return json.dumps({'success': False, 'error': 'Login form unavailable. Check the active Telegram session, browser page, delivery and HTTPS setup.'})

    ctx.register_tool(name='browser_vault', toolset='browser',
        schema={'name': 'browser_vault', 'description': 'Send a one-time HTTPS form for the current browser login page to the bound Telegram chat; save only, never fill or sign in. Link grants access to any chat reader.',
                'parameters': {'type': 'object', 'properties': {'origin': {'type': 'string', 'description': 'Exact current HTTPS origin, no path or trailing slash'},
                    'label': {'type': 'string', 'description': 'Short public login label'}}, 'required': ['origin', 'label'], 'additionalProperties': False}},
        handler=vault_tool, is_async=True)
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
