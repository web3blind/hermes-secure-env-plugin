"""Actual Vue/Vuetify updates, not a framework class-name exception."""
from pathlib import Path

import pytest
from test_retained_login_browser import browser as browser, env as env, backend, registered
from secure_env_ingress import login_fill as lf

FIXTURES = Path(__file__).parent / 'fixtures'


def mount(env, framework='vuetify'):
    env.page.add_script_tag(content=(FIXTURES / 'vue-3.5.13.global.prod.js').read_text())
    if framework == 'vuetify':
        env.page.add_script_tag(content=(FIXTURES / 'vuetify-3.7.6.min.js').read_text())
        env.page.add_style_tag(content=(FIXTURES / 'vuetify-3.7.6.min.css').read_text())
    env.page.evaluate("""framework => {
      document.body.innerHTML='<div id="app"></div>';
      const template = framework==='vuetify'
        ? `<v-app><form action="/signin" @submit.prevent>
            <v-text-field id="u" autocomplete="username" v-model="user" variant="outlined" hide-details />
            <v-text-field id="p" name="password" type="password" autocomplete="current-password" v-model="password" variant="outlined" hide-details />
            <v-checkbox id="remember" v-model="remember" label="Remember" hide-details />
          </form></v-app>`
        : `<form action="/signin" @submit.prevent :class="{arbitraryActive:focus,arbitraryDirty:password}">
            <label for="p">Password</label>
            <input id="u" autocomplete="username" :value="user">
            <input id="p" name="password" type="password" autocomplete="current-password" :value="password"
              @focus="focus=true" @input="password=$event.target.value">
            <input id="remember" type="checkbox" :value="remember" :checked="remember">
          </form>`;
      const app=Vue.createApp({setup(){return {user:Vue.ref('account@example.test'),password:Vue.ref(''),remember:Vue.ref(true),focus:Vue.ref(false)}},template});
      if(framework==='vuetify')app.use(Vuetify.createVuetify());
      app.mount('#app');
      window.originalPassword=document.querySelector('#p');
      window.passwordWrites=0;document.addEventListener('input',e=>{if(e.target.id==='p')window.passwordWrites++});
    }""", framework)
    env.page.wait_for_function("() => !!document.querySelector('#p')")


@pytest.mark.parametrize('framework', ['vue', 'vuetify'])
@pytest.mark.parametrize('account_focused', [False, True])
def test_real_framework_password(env, monkeypatch, framework, account_focused):
    mount(env, framework)
    if account_focused:
        env.page.focus('#u')
        env.page.wait_for_timeout(30)
    handle, resolved = backend(env, monkeypatch)
    result = registered(env, monkeypatch, handle)
    assert result['status'] == 'filled', result
    assert len(resolved) == 1
    assert env.page.evaluate("() => originalPassword===document.querySelector('#p') && originalPassword.value.length>0 && document.querySelector('#u').value==='account@example.test' && document.querySelector('#remember').checked === true") if framework == 'vuetify' else env.page.evaluate("originalPassword===document.querySelector('#p') && originalPassword.value.length>0")












def test_native_document_scroll_is_not_layout_reconciliation(env, monkeypatch):
    env.page.evaluate("() => {const spacer=document.createElement('div');spacer.style.height='1800px';document.body.prepend(spacer)}")
    assert env.page.evaluate("document.querySelector('#p').getBoundingClientRect().top>innerHeight")
    handle, _ = backend(env, monkeypatch)
    assert registered(env, monkeypatch, handle)['status'] == 'filled'
    assert env.page.evaluate("scrollY>0&&document.querySelector('#p').value.length>0")




@pytest.mark.parametrize('reflection', ['account', 'checkbox'])
def test_sibling_same_value_reflection(env, monkeypatch, reflection):
    # A non-framework microtask handler proves this is not vendor detection.
    env.page.evaluate("""kind=>{
      const p=document.querySelector('#p'),u=document.querySelector('#u');u.value='account@example.test';
      const c=document.createElement('input');c.type='checkbox';c.checked=true;c.value='remember';p.form.append(c);
      p.addEventListener('focus',()=>queueMicrotask(()=>{const e=kind==='account'?u:c;e.setAttribute('value',e.value)}));
    }""", reflection)
    handle, _ = backend(env, monkeypatch)
    assert registered(env, monkeypatch, handle)['status'] == 'filled'
