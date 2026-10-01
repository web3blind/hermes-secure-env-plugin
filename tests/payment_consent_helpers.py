"""Controlled Telegram notify/decision boundary, real native payment consent path."""
from contextlib import contextmanager


@contextmanager
def payment_consent(choice, *, session='synthetic-payment-consent', before_decision=None):
    from gateway import session_context as sc
    from tools import approval
    seen = []

    def notify(data):
        seen.append(data)
        assert data['pattern_key'] == 'mcp_elicitation'
        if before_decision is not None:
            before_decision()
        if choice == 'unresolved':
            assert approval.withdraw_gateway_approval(session, data['request_id'], 'synthetic withdrawal')
        else:
            assert approval.resolve_gateway_approval(session, choice, request_id=data['request_id']) == 1

    tokens = sc.set_session_vars(platform='telegram', user_id='7', chat_id='7', chat_type='dm',
                                 session_id=session, session_key=session, cron_session='')
    if choice != 'missing':
        approval.register_gateway_notify(session, notify)
    try:
        from unittest.mock import patch
        from tools import approval_gateway_wait
        with patch.object(approval_gateway_wait, '_await_gateway_decision',
                          wraps=approval_gateway_wait._await_gateway_decision) as boundary:
            yield seen
            for call in boundary.call_args_list:
                assert call.kwargs['surface'] == 'vault-payment'
    finally:
        approval.unregister_gateway_notify(session)
        sc.clear_session_vars(tokens)
