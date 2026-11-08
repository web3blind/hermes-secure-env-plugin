"""Historical full-fill/navigation outcome: acknowledgements are not sign-in proof."""
from test_nested_code import nested as nested
from test_nested_code import test_registered_nested_https as run_registered


def test_native_same_origin_spa_completion_is_filled_without_retry(nested, tmp_path, monkeypatch):
    from secure_env_ingress import vault_ingress
    from secure_env_ingress.bound_cdp import _fill_diagnostic

    original = vault_ingress.fill_verification_code
    receipts = []

    def observe(target, value, *, expires_at):
        state = _fill_diagnostic.get()
        try:
            return original(target, value, expires_at=expires_at)
        finally:
            receipts.append(dict(state))

    monkeypatch.setattr(vault_ingress, 'fill_verification_code', observe)

    def prepare(leaf):
        leaf.evaluate('''() => {
          window.originalCells = Array.from(document.querySelectorAll('input'));
          window.syntheticInputCount = 0;
          for (const e of originalCells) e.addEventListener('input', () => {
            syntheticInputCount++;
            if (originalCells.every(n => n.value.length === 1))
              history.replaceState({}, '', '/accepted-code');
          });
        }''')

    def check(leaf):
        assert leaf.evaluate('syntheticInputCount === 6')
        assert leaf.evaluate('originalCells.every(e => e.value.length === 1)')
        assert leaf.evaluate('location.pathname === "/accepted-code"')
        assert len(receipts) == 1
        assert receipts[0]['writes_attempted'] == receipts[0]['writes_confirmed'] == 6

    run_registered(nested, ('parent.test', 'parent.test'), True, tmp_path, monkeypatch,
                   setup_hook=prepare, synthetic_code='123456',
                   completion_check=check, expect_unknown=False)
