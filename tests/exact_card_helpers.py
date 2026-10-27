"""Synthetic-only exact-card browser/registered-native harness."""

import json
import time
import os
from pathlib import Path

SECRET = dict(
    card_number="4242424242424242",
    cardholder_name="Synthetic Holder",
    exp_month="12",
    exp_year="2031",
    cvc="123",
)


def spec(frame="top", *, expiry="MM/YY", pan="digits", split=None):
    fields = [
        dict(role=r, selector="#" + i, frame=frame, format=f)
        for r, i, f in [
            ("pan", "pan", pan),
            ("cardholder", "holder", "text"),
            ("expiry", "exp", expiry),
            ("cvc", "cvc", "digits"),
        ]
    ]
    if split:
        fields[:1] = [
            dict(
                role="pan",
                selector="#pan" + str(i),
                frame=frame,
                format="digits",
                part=i,
                length=n,
            )
            for i, n in enumerate(split)
        ]
    return dict(
        version=1,
        purpose="payment_card",
        merchant_origin="https://parent.test",
        fields=fields,
    )


def markup(kind="input", *, split=None, monthyear=False):
    ids = ["pan", "holder", "exp", "cvc"]
    if split:
        ids[:1] = ["pan" + str(i) for i in range(len(split))]
    if monthyear:
        ids[ids.index("exp") : ids.index("exp") + 1] = ["month", "year"]
    if kind == "input":
        controls = "".join('<input id="' + i + '">' for i in ids)
    elif kind == "textarea":
        controls = "".join('<textarea id="' + i + '"></textarea>' for i in ids)
    else:
        controls = "".join(
            '<div tabindex="0" contenteditable="' + ('true' if kind == 'editable' else 'plaintext-only') + '" id="' + i + '"></div>'
            for i in ids
        )
    return (
        "<style>input,textarea,[contenteditable]{transform:translateX(9px);opacity:.2;position:relative} .unrelated:hover{transform:scale(2)}</style>"
        '<div class="unrelated">Decoration</div><form id="checkout" action="/pay" onsubmit="window.submitted=true;return false">'
        + controls
        + '<button id="pay" onclick="window.clicked=true">Pay</button></form><script>window.writes=0;document.addEventListener("input",()=>window.writes++)</script>'
    )


def page(nested, *, kind="input", topology="top", split=None, monthyear=False):
    html = markup(kind, split=split, monthyear=monthyear)
    origin = "https://parent.test"
    if topology == "top":
        nested.pages["https://parent.test/root"] = html
    elif topology in ("same", "nested", "shadow", "closed"):
        nested.pages["https://parent.test/root"] = (
            '<iframe src="https://parent.test/pay"></iframe>'
            if topology == "same"
            else '<iframe src="https://middle.test/mid"></iframe>'
        )
        nested.pages["https://middle.test/mid"] = (
            '<iframe src="https://leaf.test/pay"></iframe>'
        )
        origin = "https://parent.test" if topology == "same" else "https://leaf.test"
        nested.pages[origin + "/pay"] = html
    elif topology == "multi":
        origin = "https://leaf.test"
        nested.pages["https://parent.test/root"] = (
            '<iframe src="https://leaf.test/a"></iframe><iframe src="https://leaf.test/b"></iframe>'
        )
        nested.pages[origin + "/a"] = (
            markup().replace('<input id="exp">', "").replace('<input id="cvc">', "")
        )
        nested.pages[origin + "/b"] = (
            markup().replace('<input id="pan">', "").replace('<input id="holder">', "")
        )
    nested.page.close()
    nested.page = nested.context.new_page()
    nested.page.goto("https://parent.test/root", wait_until="domcontentloaded")
    deadline = time.monotonic() + 20
    while topology != "top" and not any(
        f.url.startswith(origin + "/") and f.url != "https://parent.test/root"
        for f in nested.page.frames
    ):
        assert time.monotonic() < deadline
        nested.page.wait_for_timeout(50)
    target = (
        nested.page
        if topology == "top"
        else next(
            f
            for f in nested.page.frames
            if f.url.startswith(origin + "/") and f.url != "https://parent.test/root"
        )
    )
    target.wait_for_selector("#pan0" if split else "#pan")
    if topology in ("shadow", "closed"):
        target.evaluate(
            'mode=>{const h=document.createElement("section");document.body.append(h);const r=h.attachShadow({mode});r.append(document.querySelector("#checkout"));r.addEventListener("input",()=>window.writes++);window.fixtureRoot=r}',
            "closed" if topology == "closed" else "open",
        )
    session = nested.context.new_cdp_session(nested.page)
    nested.parent = session.send("Target.getTargetInfo")["targetInfo"]["targetId"]
    assert nested.sup.focus_page("https://parent.test")["ok"]
    tree = session.send("Page.getFrameTree")["frameTree"]

    def flatten(t):
        return [t["frame"]] + [f for c in t.get("childFrames", []) for f in flatten(c)]

    frames = flatten(tree)
    session.detach()
    # OOPIF IDs can be obtained from the owning iframe, not guessed from URLs.
    from secure_env_ingress.code_targets import _call
    from secure_env_ingress.parent_session import ParentSession

    p = ParentSession(nested.capture(), nested.parent)
    try:
        from secure_env_ingress import nested_code as nc

        lease = nc._Lease(p.transport)

        def scan(sid, frame):
            sid, ctx = nc._context(p.transport, sid, frame, lease)
            url = nc._eval(p.transport, sid, ctx, "location.href", True).get("value")
            ids[url] = frame
            doc = nc._eval(p.transport, sid, ctx, "document")["objectId"]
            arr = nc._invoke(
                p.transport,
                sid,
                doc,
                'function(){return Array.from(this.querySelectorAll("iframe"))}',
                (),
                False,
            )["objectId"]
            count = nc._invoke(
                p.transport, sid, arr, "function(){return this.length}"
            ).get("value")
            for i in range(count):
                obj = nc._invoke(
                    p.transport, sid, arr, "function(i){return this[i]}", (i,), False
                )["objectId"]
                node = _call(p.transport, "DOM.describeNode", {"objectId": obj}, sid)[
                    "result"
                ]["node"]
                scan(sid, node["frameId"])

        ids = {}
        scan(p.sid, frames[0]["id"])
    finally:
        lease.close()
        p.drop(None)
    frame = "top" if topology == "top" else ids[target.url]
    s = spec(frame, split=split)
    if topology == "multi":
        for f in s["fields"]:
            f["frame"] = ids[
                origin + ("/a" if f["role"] in ("pan", "cardholder") else "/b")
            ]
    if monthyear:
        s["fields"][2:3] = [
            dict(role=r, selector="#" + r, frame=frame, format=f)
            for r, f in [("month", "MM"), ("year", "YYYY")]
        ]
    return origin, target, s


def registered_fill(
    nested,
    tmp_path,
    monkeypatch,
    origin,
    s,
    *,
    choice="once",
    mutation=None,
    secret=None,
    vault_origin=None,
    setup_hook=None,
):
    from agent.vault_store import VaultStore
    from generic_helpers import registered
    from test_runtime_e2e import make_runtime
    from payment_consent_helpers import payment_consent
    from gateway.run import _profile_runtime_scope
    from tools.registry import registry
    from agent.vault_backends.local import LocalLoginBackend

    runtime, settings, home, _ = make_runtime(tmp_path, mini=False)
    runtime.close()
    if setup_hook is not None:
        setup_hook(home)
    handle = (
        VaultStore(home / "vault")
        .add_item(
            "payment", "Synthetic card", secret or SECRET, origin=vault_origin or origin
        )
        .id
    )
    resolved = []
    original = LocalLoginBackend.resolve_secret

    def resolve(self, h):
        resolved.append(h)
        return original(self, h)

    monkeypatch.setattr(LocalLoginBackend, "resolve_secret", resolve)
    from secure_env_ingress import exact_card

    targets = []
    discover = exact_card.discover

    def capture(*a, **kw):
        found = discover(*a, **kw)
        targets.extend(found)
        return found

    monkeypatch.setattr(exact_card, "discover", capture)

    def before_decision():
        if mutation is not None:
            mutation(targets[0])

    with (
        registered(monkeypatch, home, settings=settings),
        _profile_runtime_scope(home, {}),
    ):
        with payment_consent(
            choice, session=nested.sup.task_id, before_decision=before_decision
        ) as seen:
            raw = registry.dispatch(
                "secure_payment_fill",
                dict(handle=handle, parent=nested.parent, origin=origin, target_spec=s),
                task_id=nested.sup.task_id,
                session_id=nested.sup.task_id,
            )
    result = json.loads(raw)
    assert SECRET["card_number"] not in raw + json.dumps(seen)
    # A three-digit CVC can occur by chance inside public random hex handles;
    # reject its standalone serialization, not coincidental identifier substrings.
    import re
    assert re.search(r"(?<![A-Za-z0-9])" + re.escape(SECRET["cvc"]) + r"(?![A-Za-z0-9])", raw + json.dumps(seen)) is None
    from secure_env_ingress import exact_card, plugin
    import hashlib

    counts = []
    no_pay = []
    for frame in nested.page.frames:
        try:
            counts.append(frame.evaluate("window.writes||0"))
            no_pay.append(frame.evaluate("!window.clicked&&!window.submitted"))
        except Exception:
            no_pay.append(False)
    receipt = dict(
        test=os.environ.get("PYTEST_CURRENT_TEST"),
        result=result,
        approvals=len(seen),
        resolutions=len(resolved),
        write_count=sum(counts),
        no_pay=all(no_pay),
        card_module=exact_card.__file__,
        plugin_module=plugin.__file__,
        module_hash=hashlib.sha256(Path(exact_card.__file__).read_bytes()).hexdigest(),
    )
    with (Path(__file__).resolve().parents[1] / "card-receipts.jsonl").open(
        "a"
    ) as ledger:
        ledger.write(json.dumps(receipt, sort_keys=True) + "\n")
    print(
        "CARD_RECEIPT "
        + json.dumps(
            dict(result=result, approvals=len(seen), resolutions=len(resolved)),
            sort_keys=True,
        )
    )
    return result, seen, resolved


def mutate_js(target, script, *, parent=False):
    """Fixed nonsensitive fixture mutation on the approval's worker thread.

    Playwright's sync objects belong to the fixture thread and cannot be called
    from native approval callbacks. Use the retained native context instead.
    """
    from secure_env_ingress.nested_code import _invoke

    sid, guard, _ = next(g for g in target.guards if g[2])
    if parent:
        sid, guard, _ = next(
            g for g in target.guards if g[0] == target.parent_sid and not g[2]
        )
    return _invoke(
        target.supervisor, sid, guard, "function(){" + script + ";return true}"
    ).get("value")


def navigate_js(target, script, *, parent=False):
    from secure_env_ingress.nested_code import _invoke

    sid, guard, _ = next(g for g in target.guards if g[2])
    if parent:
        sid, guard, _ = next(
            g for g in target.guards if g[0] == target.parent_sid and not g[2]
        )
    try:
        mutate_js(target, script, parent=parent)
    except Exception:
        pass  # Unloaded context is already a refusal.
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            if (
                _invoke(
                    target.supervisor, sid, guard, "function(){return this.valid()}"
                ).get("value")
                is not True
            ):
                return
        except Exception:
            return
        time.sleep(0.05)
    raise AssertionError("synthetic navigation did not invalidate original context")
