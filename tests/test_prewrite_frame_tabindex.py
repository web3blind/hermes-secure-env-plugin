"""Synthetic reproduction of unrelated iframe tabindex invalidating OTP guards."""
import time

import pytest

from test_nested_code import nested as nested, setup_chain
from test_indexed_react_browser import prepare, complete
from secure_env_ingress import code_targets as codes
from secure_env_ingress import nested_code


def prepare_unrelated(leaf):
    prepare(leaf)
    leaf.evaluate('''() => {
      const frame = document.createElement('iframe');
      frame.id = 'unrelated'; frame.src = 'https://parent.test/empty';
      document.body.append(frame);
    }''')
    leaf.wait_for_function("document.querySelector('#unrelated').contentDocument?.readyState === 'complete'")


def test_unrelated_frame_tabindex_does_not_invalidate(nested):
    # Actual failed requests had no selector/spec; complex hints retain refusal.
    selector = None
    origin, leaf = setup_chain(nested)
    prepare_unrelated(leaf)
    target = codes.discover(origin, 'Synthetic', nested.sup.task_id,
                            parent=nested.parent, field_selector=selector)[0]
    try:
        leaf.evaluate("document.querySelector('#unrelated').tabIndex = -1")
        # This is the original accepts preflight, before focus and any setter.
        assert nested_code._invoke(target.supervisor, target.leaf_sid, target.leaf_guard,
            'function(){return this.valid()}').get('value') is True
        assert codes.fill(target, '123456', time.monotonic() + 60)
        complete(leaf)
    finally:
        codes.release(target)


def test_registered_https_unrelated_prewrite_tabindex(nested, tmp_path, monkeypatch):
    from secure_env_ingress import vault_ingress
    from test_nested_code import test_registered_nested_https as run
    original = vault_ingress.fill_verification_code
    observed = []

    def fill(target, value, *, expires_at):
        assert nested_code._invoke(target.supervisor, target.leaf_sid, target.leaf_guard,
            'function(){return Array.from(this.document.querySelectorAll("input")).every(e=>!e.value)}').get('value') is True
        nested_code._invoke(target.supervisor, target.leaf_sid, target.leaf_guard,
            'function(){this.document.querySelector("#unrelated").tabIndex=-1;return true}')
        observed.append(True)
        return original(target, value, expires_at=expires_at)

    monkeypatch.setattr(vault_ingress, 'fill_verification_code', fill)
    run(nested, ('parent.test', 'parent.test'), True, tmp_path, monkeypatch,
        setup_hook=prepare_unrelated, synthetic_code='123456',
        completion_check=complete)
    assert observed == [True]


@pytest.mark.parametrize('selector', ['input[name="code-0"]', 'input[name="code-0"]:first-child'])
def test_unrelated_frame_tabindex_with_hint_stays_conservative(nested, selector):
    origin, leaf = setup_chain(nested)
    prepare_unrelated(leaf)
    target = codes.discover(origin, 'Synthetic', nested.sup.task_id,
                            parent=nested.parent, field_selector=selector)[0]
    try:
        leaf.evaluate("document.querySelector('#unrelated').tabIndex=-1")
        with pytest.raises(ValueError):
            codes.fill(target, '123456', time.monotonic() + 60)
        assert leaf.evaluate("Array.from(document.querySelectorAll('input')).every(e=>!e.value)")
    finally:
        codes.release(target)


@pytest.mark.parametrize('selector', [None, 'input[name="code-0"]'])
@pytest.mark.parametrize('where,mutation', [
    ('root', "document.querySelector('iframe').tabIndex = -1"),
    ('leaf', "document.querySelector('#unrelated').setAttribute('src', 'https://other.test/');document.querySelector('#unrelated').setAttribute('src', 'https://parent.test/empty')"),
    ('leaf', "const e=document.querySelector('#unrelated');e.replaceWith(e.cloneNode(true))"),
    ('leaf', "const e=document.querySelector('input');e.tabIndex=-1;e.removeAttribute('tabindex')"),
])
def test_frame_or_control_authority_changes_still_refuse(nested, where, mutation, selector):
    origin, leaf = setup_chain(nested)
    prepare_unrelated(leaf)
    target = codes.discover(origin, 'Synthetic', nested.sup.task_id,
                            parent=nested.parent, field_selector=selector)[0]
    try:
        subject = nested.page if where == 'root' else leaf
        subject.evaluate('() => {' + mutation + '}')
        with pytest.raises(ValueError):
            codes.fill(target, '123456', time.monotonic() + 60)
        assert leaf.evaluate("Array.from(document.querySelectorAll('input')).every(e=>e.value==='')")
    finally:
        codes.release(target)
