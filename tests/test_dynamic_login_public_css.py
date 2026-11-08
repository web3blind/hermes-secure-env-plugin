"""Public Beget-derived CSS grammar, with real Vue/Vuetify dispatch.

Only synthetic accounts/passwords; no domain/framework exception in production.
The escaped utility selector and placeholder rule below were read from the public
cp.beget.com/login stylesheet. They are small grammar regressions, not a copy of
its application bundle. Full original public CSS evidence is external to source.
"""
from pathlib import Path

import pytest
from test_retained_login_browser import browser as browser, env as env, backend, registered

FIXTURES = Path(__file__).parent / 'fixtures'
UTILITY = r'.\[\&\>\:first-child\]\:tw-mt-0 > :first-child { margin-top: 0px; }'
PLACEHOLDER = '.v-text-field .v-field:not(.v-field--no-label, .v-field--active) input::-webkit-input-placeholder { opacity: 0; }'


def mount_public_shape(env):
    for asset in ('vue-3.5.13.global.prod.js', 'vuetify-3.7.6.min.js'):
        env.page.add_script_tag(content=(FIXTURES / asset).read_text())
    env.page.add_style_tag(content=(FIXTURES / 'vuetify-3.7.6.min.css').read_text())
    env.page.add_style_tag(content=UTILITY + PLACEHOLDER)
    env.page.evaluate("""() => {
      document.body.innerHTML='<div id="app"></div>';
      const app=Vue.createApp({setup(){return {user:Vue.ref('account@example.test'),password:Vue.ref(''),remember:Vue.ref(true)}},
        template:`<v-app><form action="/signin" @submit.prevent>
          <label for="u">Login</label>
          <v-text-field id="u" v-model="user" variant="outlined" density="compact" />
          <label for="p">Password</label>
          <v-text-field id="p" type="password" v-model="password" variant="outlined" density="compact" />
          <v-checkbox id="remember" v-model="remember" label="Remember me" />
          <button type="submit">Enter</button>
        </form></v-app>`});
      app.use(Vuetify.createVuetify());app.mount('#app');
      window.originalPassword=document.querySelector('#p');window.passwordWrites=0;
      document.addEventListener('input',e=>{if(e.target===originalPassword)passwordWrites++});
    }""")
    env.page.focus('#u')
    env.page.wait_for_timeout(30)


@pytest.mark.parametrize('css', [
    UTILITY,
    r'.unused\26 utility { color:red }',
    '[data-note="&"] {color:red}',
])
def test_public_css_grammar_positive(env, monkeypatch, css):
    mount_public_shape(env)
    env.page.add_style_tag(content=css)
    handle, resolved = backend(env, monkeypatch)
    result = registered(env, monkeypatch, handle, field_selector='#p', frame='top')
    assert result['status'] == 'filled', result
    assert len(resolved) == 1
    assert env.page.evaluate("originalPassword===document.querySelector('#p')&&originalPassword.value.length>0&&document.querySelector('#u').value==='account@example.test'")
