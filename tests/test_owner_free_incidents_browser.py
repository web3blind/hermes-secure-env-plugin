"""Synthetic incident classes: wrong-site defaults and an existing popup."""
import pytest
from test_retained_login_browser import browser as _browser, env as _env, backend, registered

browser = _browser
env = _env


@pytest.mark.parametrize('default_site,destination', [('zoom.test','contabo.test'),('omni.test','hetzner.test')])
def test_twofa_selected_parent_ignores_wrong_site_default(env, monkeypatch, default_site, destination):
    default_origin='https://'+default_site
    env.origin='https://'+destination
    env.browser.pages[default_origin+'/login']='<form><input id=p type=password autocomplete=current-password></form>'
    env.browser.pages[env.origin+'/login']='<form><input id=p autocomplete=one-time-code></form>'
    env.browser.first.goto(default_origin+'/login')
    assert env.browser.sup.focus_page(default_origin)['ok']  # Fixture admission only.
    env.page.goto(env.origin+'/login')
    env.page.bring_to_front()
    handle,resolved=backend(env,monkeypatch,mode='totp')
    try:
        result=registered(env,monkeypatch,handle,mode='totp')
        assert result['status']=='filled',result
        assert len(resolved)==1
        assert env.page.evaluate('document.querySelector("#p").value.length===6')
        assert env.browser.first.evaluate('document.querySelector("#p").value===""')
    finally:
        env.browser.first.goto('https://a.test/first')
        assert env.browser.sup.focus_page('https://a.test')['ok']


def test_existing_popup_selected_without_creation_ledger(env, monkeypatch):
    env.origin='https://popup.test'
    env.browser.pages[env.origin+'/login']='<form><input id=p type=password autocomplete=current-password></form>'
    with env.browser.context.expect_page() as created:
        env.page.evaluate("window.open('https://popup.test/login','synthetic-popup')")
    popup=created.value
    popup.wait_for_selector('#p')
    popup.bring_to_front()
    session=env.browser.context.new_cdp_session(popup)
    env.parent=session.send('Target.getTargetInfo')['targetInfo']['targetId']
    session.detach()
    env.page=popup
    handle,resolved=backend(env,monkeypatch)
    try:
        result=registered(env,monkeypatch,handle)
        assert result['status']=='filled',result
        assert len(resolved)==1
        assert popup.evaluate('document.querySelector("#p").value.length>0')
        assert env.browser.first.evaluate('document.querySelector("#p").value===""')
        assert not (env.home/'browser_tabs.sqlite').exists()
    finally:
        popup.close()


def test_fresh_request_after_browser_reconnect_uses_existing_saved_login(env, monkeypatch):
    handle,resolved=backend(env,monkeypatch)
    env.browser.sup.stop()
    env.browser.sup.start()
    result=registered(env,monkeypatch,handle)
    assert result['status']=='filled',result
    assert len(resolved)==1
    assert env.page.evaluate('document.querySelector("#p").value.length>0&&!window.submitted')
    assert env.browser.first.evaluate('document.querySelector("#p").value===""')
