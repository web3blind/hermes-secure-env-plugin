"""Astra compatibility regressions: real Chromium, synthetic Vault, no submission."""
import pytest
from test_retained_login_browser import browser as chromium_fixture, env as login_env_fixture, backend, registered

browser = chromium_fixture
env = login_env_fixture


@pytest.mark.parametrize('wrong_origin', [False, True])
def test_login_through_about_blank_ancestor(env, monkeypatch, wrong_origin):
    leaf_url = 'https://leaf.test/login'
    env.browser.pages[leaf_url] = '<input id=p type=password autocomplete=current-password>'
    env.page.set_content('<iframe id=middle></iframe>')
    middle = env.page.frames[1]
    assert middle.evaluate('location.origin') == 'null'
    middle.evaluate('url=>{const f=document.createElement("iframe");f.src=url;document.body.append(f)}', leaf_url)
    leaf = next(f for f in env.page.frames if f.parent_frame == middle)
    leaf.wait_for_selector('#p')
    env.origin = 'https://wrong.test' if wrong_origin else 'https://leaf.test'
    handle, resolved = backend(env, monkeypatch)
    result = registered(env, monkeypatch, handle)
    assert result['status'] == ('target_refused' if wrong_origin else 'filled'), result
    assert len(resolved) == (0 if wrong_origin else 1)
    assert leaf.evaluate('!!document.querySelector("#p").value') is not wrong_origin
