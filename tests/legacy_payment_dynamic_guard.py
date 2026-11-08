"""Behavioral JS guard checks in disposable unauthenticated Chromium.

The registered-tool/native-consent integration is exercised separately by
browser_payment_iframe_check.py; these fast checks cover guard edge cases.
"""
import shutil

import pytest

from secure_env_ingress.payment_fill import _GUARD
from payment_fixture_helpers import HOST


@pytest.fixture(scope='module')
def chromium():
    playwright = pytest.importorskip('playwright.sync_api')
    executable = shutil.which('chromium')
    if not executable:
        pytest.skip('Chromium required for JS behavior checks')
    with playwright.sync_playwright() as p:
        browser = p.chromium.launch(executable_path=executable, args=['--no-sandbox'])
        yield browser
        browser.close()


@pytest.fixture
def guard_page(chromium):
    context = chromium.new_context()
    page = context.new_page()
    page.set_content('''<form><label for="card">Card number</label>
        <input id="card" autocomplete="cc-number"><input id="cvc" autocomplete="cc-csc">
        <span id="brand" style="display:none;width:24px;height:16px;pointer-events:none;overflow:hidden;contain:paint"></span><input id="type" type="hidden"></form>''')
    yield page
    context.close()


def bind(page, inspection=False):
    page.evaluate('(inspection)=>{window.guard=(' + _GUARD + ')([document.querySelector("#card"),document.querySelector("#cvc")],inspection)}', inspection)
    assert page.evaluate('guard.valid()')
