"""Nonempty head-title text is not OTP destination authority."""

import time
import pytest
from test_nested_code import nested as nested, setup_chain
from test_input_reconciliation import prepare
from test_cds_caret_palette import install_cds_caret_palette
from test_exact_submit_state import spec
from secure_env_ingress import code_targets as codes
from secure_env_ingress.bound_cdp import fill_diagnostic_scope


def target_with_title(nested, source=False, duplicate=False, before=None):
    origin, leaf = setup_chain(nested)
    prepare(leaf, paint=True)
    install_cds_caret_palette(leaf)
    leaf.evaluate(
        "document.title='Synthetic Wallet';window.originalTitle=document.head.querySelector('title')"
    )
    if source:
        leaf.evaluate(
            "originalTitle.id='title-label';originalCells[0].setAttribute('aria-labelledby','title-label')"
        )
    if duplicate:
        leaf.evaluate(
            "const extra=document.createElement('title');extra.textContent='Other title';document.head.append(extra)"
        )
    if before:
        leaf.evaluate(before)
    return leaf, codes.discover(
        origin,
        "Synthetic live-title projection",
        nested.sup.task_id,
        parent=nested.parent,
        target_spec=spec(),
    )[0]


@pytest.mark.parametrize("timing", ["waiting", "first_input"])
@pytest.mark.parametrize("method", ["replace", "character"])
def test_nonempty_original_title_updates_allow_exact_fill(nested, timing, method):
    leaf, target = target_with_title(nested)
    change = (
        "document.title='Synthetic Wallet (1)';document.title='Synthetic Wallet'"
        if method == "replace"
        else "originalTitle.firstChild.data='Synthetic Wallet (1)';originalTitle.firstChild.data='Synthetic Wallet'"
    )
    try:
        if timing == "waiting":
            leaf.evaluate(change)
        else:
            leaf.evaluate(
                "change=>originalCells[0].addEventListener('input',()=>{Function(change)()},{once:true})",
                change,
            )
        with fill_diagnostic_scope() as diag:
            result = codes.fill(target, "123456", time.monotonic() + 60)
        assert result is True, diag
        assert leaf.evaluate(
            "originalCells.every((e,i)=>e===document.querySelector('[name=code'+i+']')&&e.value===String(i+1))"
        )
    finally:
        codes.release(target)


@pytest.mark.parametrize(
    "attack",
    [
        "originalTitle.textContent='';originalTitle.textContent='Synthetic Wallet'",
        "originalTitle.firstChild.data='';originalTitle.firstChild.data='Synthetic Wallet'",
        "originalTitle.replaceWith(originalTitle.cloneNode(true))",
        "originalTitle.setAttribute('id','changed');originalTitle.removeAttribute('id')",
        "const n=document.createElement('span');originalTitle.append(n);n.remove()",
        "originalCells[0].setAttribute('aria-labelledby','temporary-title');originalTitle.id='temporary-title';document.title='Changed';originalTitle.removeAttribute('id');originalCells[0].removeAttribute('aria-labelledby')",
    ],
)
def test_title_structure_and_dependency_history_remain_refused(nested, attack):
    leaf, target = target_with_title(nested)
    try:
        leaf.evaluate(attack)
        try:
            result = codes.fill(target, "123456", time.monotonic() + 60)
        except (ValueError, RuntimeError):
            result = False
        assert result is False
        assert leaf.evaluate("originalCells.every(e=>e.value==='')")
    finally:
        codes.release(target)


@pytest.mark.parametrize("source,duplicate", [(True, False), (False, True)])
def test_title_source_or_ambiguous_head_remains_refused(nested, source, duplicate):
    leaf, target = target_with_title(nested, source, duplicate)
    try:
        leaf.evaluate("document.title='Changed title'")
        try:
            result = codes.fill(target, "123456", time.monotonic() + 60)
        except (ValueError, RuntimeError):
            result = False
        assert result is False
        assert leaf.evaluate("originalCells.every(e=>e.value==='')")
    finally:
        codes.release(target)


@pytest.mark.parametrize(
    "before",
    [
        "document.head.style.display='block'",
        "originalTitle.style.display='block'",
        "document.documentElement.setAttribute('dir','auto')",
        "document.head.setAttribute('dir','auto')",
    ],
)
def test_title_rendering_or_direction_dependencies_remain_refused(nested, before):
    leaf, target = target_with_title(nested, before=before)
    try:
        leaf.evaluate("document.title='Changed title'")
        try:
            result = codes.fill(target, "123456", time.monotonic() + 60)
        except (ValueError, RuntimeError):
            result = False
        assert result is False
        assert leaf.evaluate("originalCells.every(e=>e.value==='')")
    finally:
        codes.release(target)
