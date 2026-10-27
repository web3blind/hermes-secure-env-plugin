"""Ordinary login remains usable beside retained non-destination service frames."""
import pytest
from test_retained_login_browser import browser as _browser, env as _env, backend, registered
from secure_env_ingress import login_fill as lf

browser=_browser
env=_env


def service_frame(env, opaque=True):
    env.page.evaluate('opaque=>{const f=document.createElement("iframe");f.style.display="none";if(opaque)f.sandbox="allow-scripts";f.srcdoc="<p id=service>Ancillary metadata only</p>";document.body.append(f)}',opaque)
    leaf=env.page.frames[-1]
    leaf.wait_for_selector('#service',state='attached')
    return leaf


@pytest.mark.parametrize('opaque',[True,False])
def test_hidden_empty_service_frame_does_not_reject_ordinary_login(env,monkeypatch,opaque):
    leaf=service_frame(env,opaque)
    assert leaf.evaluate('self.origin') == ('null' if opaque else env.origin)
    handle,resolved=backend(env,monkeypatch)
    result=registered(env,monkeypatch,handle)
    assert result['status']=='filled',result
    assert len(resolved)==1
    assert env.page.evaluate('window.writes===1&&!window.submitted')


def test_opaque_service_navigation_is_not_an_excluded_canary(env,monkeypatch):
    leaf=service_frame(env)
    handle,resolved=backend(env,monkeypatch)
    target=lf.discover(env.browser.sup.task_id,env.parent,env.origin,lambda:None)
    env.browser.pages['https://a.test/service-new']='<p id=new-service>Changed ancillary document</p>'
    try:
        leaf.evaluate("location.href='https://a.test/service-new'")
        leaf.wait_for_selector('#new-service',state='attached')
        result=lf.fill_login(target,handle,lambda:None)
        assert result['status']=='target_refused',result
        assert not resolved
        assert env.page.evaluate('window.writes===0')
    finally:
        target.lease.close()


@pytest.mark.parametrize('hide', [
    'document.querySelector("#p").hidden=true',
    'document.querySelector("form").inert=true',
    'document.querySelector("form").setAttribute("aria-hidden","true")',
    'document.querySelector("form").style.contentVisibility="hidden"',
])
def test_actual_hidden_or_inert_destination_refuses_before_resolution(env,monkeypatch,hide):
    handle,resolved=backend(env,monkeypatch)
    env.page.evaluate(hide)
    result=registered(env,monkeypatch,handle)
    assert result['status']=='target_refused',result
    assert not resolved
    assert env.page.evaluate('window.writes===0')


def test_identifier_focus_redirection_blocks_original_password_setter(env,monkeypatch):
    handle,resolved=backend(env,monkeypatch)
    env.page.locator('#u').fill('madeup@example.test')
    env.page.evaluate("window.writes=0;document.querySelector('#p').addEventListener('focus',()=>document.querySelector('#u').value='different-user@example.test')")
    result=registered(env,monkeypatch,handle)
    assert result['status']=='target_refused',result
    assert len(resolved)==1
    assert env.page.evaluate('window.writes===0&&document.querySelector("#p").value===""')


def test_unrelated_decoration_does_not_invalidate_retained_login(env,monkeypatch):
    handle,_=backend(env,monkeypatch)
    target=lf.discover(env.browser.sup.task_id,env.parent,env.origin,lambda:None)
    try:
        env.page.evaluate("const e=document.createElement('span');e.textContent='Unrelated clock';document.body.append(e);e.textContent='Updated unrelated clock'")
        result=lf.fill_login(target,handle,lambda:None)
        assert result['status']=='filled',result
        assert env.page.evaluate('window.writes===1&&!window.submitted')
    finally:
        target.lease.close()
