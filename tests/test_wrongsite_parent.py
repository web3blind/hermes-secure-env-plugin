"""Wrong-site supervisor regressions, disposable Chromium/ownership only."""
import time

from test_nested_code import nested as chromium_fixture, setup_chain

from secure_env_ingress import code_targets as codes, payment_fill as pf

# Re-export the genuine module-scoped disposable Chromium fixture.
nested = chromium_fixture


def authorize(tmp_path, monkeypatch, sup, parent, owner_task=None, home=None):
    from hermes_state import SessionDB
    from ownership_helpers import OwnershipFixture
    from secure_env_ingress import parent_session
    home = home or tmp_path / 'home'
    home.mkdir(exist_ok=True)
    monkeypatch.setenv('HERMES_HOME', str(home))
    task = owner_task or sup.task_id
    db = SessionDB(db_path=home / 'state.db')
    db.create_session(task, 'telegram')
    db.close()
    ledger = OwnershipFixture(home, task, sup.cdp_url, parent)
    monkeypatch.setattr(parent_session, '_proof', ledger.proof)
    return ledger, ledger.token


def wrongsite(nested):
    other = nested.context.new_page()
    other.goto('https://other.test/root')
    assert nested.sup.focus_page('https://other.test')['ok']
    nested.page.bring_to_front()  # Test-owned foreground; production never activates.
    return other, nested.sup._page_session_id


def test_nested_wrongsite_owned_parent(nested, tmp_path, monkeypatch):
    origin, leaf = setup_chain(nested)
    other, previous = wrongsite(nested)
    authorize(tmp_path, monkeypatch, nested.sup, nested.parent)
    target = None
    try:
        target = codes.discover(origin, 'Synthetic', nested.sup.task_id, parent=nested.parent)[0]
        assert nested.sup._page_session_id == previous
        assert codes.fill(target, 'Q!7&z=R9', time.monotonic() + 20)
        assert leaf.evaluate('document.querySelector("input").value === "Q!7&z=R9"')
        assert nested.sup._page_session_id == previous
    finally:
        if target:
            codes.release(target)
        other.close()


def test_payment_wrongsite_owned_parent(nested, tmp_path, monkeypatch):
    setup_chain(nested)
    nested.pages['https://parent.test/root'] = '<iframe src="https://parent.test/pay"></iframe>'
    nested.pages['https://parent.test/pay'] = '<form><input autocomplete="cc-name"><input autocomplete="cc-number"><input autocomplete="cc-exp" placeholder="MM/YY"><input autocomplete="cc-csc"></form>'
    nested.page.reload()
    nested.page.frames[-1].wait_for_selector('input')
    other, previous = wrongsite(nested)
    authorize(tmp_path, monkeypatch, nested.sup, nested.parent)
    targets = []
    try:
        targets = pf.discover(nested.sup.task_id, nested.parent, 'https://parent.test')
        assert len(targets) == 1
        pf.assert_target(targets[0])
        assert nested.sup._page_session_id == previous
    finally:
        for target in targets:
            pf.release(target)
        other.close()
