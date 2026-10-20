"""Real Chromium regression for the immutable-CSS/live-paint cache boundary."""

import pytest

from secure_env_ingress.payment_fill import _GUARD
from test_payment_reserved_slot import provider as provider

pytest_plugins = ["test_payment_dynamic_guard"]


@pytest.mark.parametrize("toggle_brand", [False, True])
def test_button_transition_revalidates_after_binding(provider, toggle_brand):
    # Preserve the captured provider's transition:all .2s. Freeze its actual
    # font transition at the initial frame, not a synthetic computed-style mock.
    provider.evaluate("""() => {
      const b=document.querySelector('button');
      getComputedStyle(b).fontSize;
      const s=document.createElement('style');
      s.textContent='button.custom-button-red {height:44px;font-size:1000px}';
      document.head.append(s);
      getComputedStyle(b).fontSize;
      window.fontTransition=b.getAnimations().find(a=>a.transitionProperty==='font-size');
      if(!fontTransition) throw Error('missing real font transition');
      fontTransition.pause();fontTransition.currentTime=0;
    }""")
    initial = provider.evaluate("""() => {
      const b=document.querySelector('button'),r=document.createRange();r.selectNodeContents(b);
      const t=r.getBoundingClientRect(),x=b.getBoundingClientRect();
      return {font:getComputedStyle(b).fontSize,bounded:t.left>=x.left-1 && t.right<=x.right+1 && t.top>=x.top-1 && t.bottom<=x.bottom+1};
    }""")
    assert initial == dict(font="16px", bounded=True)
    provider.evaluate(
        "window.guard=("
        + _GUARD
        + ")([creditCardHolder,_KKnr,expiry_date,cccvc]);window.cssBefore=Array.from(document.styleSheets,s=>Array.from(s.cssRules,r=>r.cssText))"
    )
    assert provider.evaluate("guard.valid()")
    provider.evaluate("fontTransition.play()")
    provider.wait_for_function(
        "getComputedStyle(document.querySelector('button')).fontSize==='1000px'"
    )
    assert provider.evaluate("""() => {
      const b=document.querySelector('button'),r=document.createRange();r.selectNodeContents(b);
      const t=r.getBoundingClientRect(),x=b.getBoundingClientRect();
      return t.left<x.left-1 || t.right>x.right+1 || t.top<x.top-1 || t.bottom>x.bottom+1;
    }""")
    assert provider.evaluate(
        "JSON.stringify(cssBefore)===JSON.stringify(Array.from(document.styleSheets,s=>Array.from(s.cssRules,r=>r.cssText)))"
    )
    if toggle_brand:
        provider.evaluate("brand_visa.style.display='flex'")
    assert provider.evaluate("guard.valid()") is False
    assert provider.evaluate("guard.focus(0)") is False
    assert provider.evaluate("guard.write(0,'Synthetic Holder','cc-name')") == dict(
        written=False, valid=False
    )
    assert provider.evaluate("creditCardHolder.value==='' && submissions===0")
