"""Exact no-op submit metadata is not a new destination or state transition."""

import time
import pytest
from test_nested_code import nested as nested, setup_chain
from test_input_reconciliation import prepare
from test_cds_caret_palette import install_cds_caret_palette
from test_exact_submit_state import spec
from secure_env_ingress import code_targets as codes
from secure_env_ingress.bound_cdp import fill_diagnostic_scope


def prepare_noops(leaf, attack=None, initially_disabled=True):
    prepare(leaf, paint=True)
    install_cds_caret_palette(leaf)
    leaf.evaluate(
        """([attack,initiallyDisabled])=>{
      const b=document.querySelector('#submit');
      if(initiallyDisabled){b.disabled=true;b.setAttribute('data-disabled','true')}
      if(attack==='source')originalCells[0].setAttribute('aria-labelledby','submit');
      if(attack==='ancestor')b.append(document.querySelector('form'));
      if(attack==='multiple'){const other=document.createElement('button');other.id='other';other.disabled=true;other.setAttribute('data-disabled','true');document.body.append(other)}
      originalCells[0].addEventListener('input',()=>{
        b.setAttribute('data-disabled','true');
        if(attack==='data_transition')b.setAttribute('data-disabled','false');
        if(attack==='data_roundtrip'){b.setAttribute('data-disabled','false');b.setAttribute('data-disabled','true')}
        if(attack==='data_duplicate')b.setAttribute('data-disabled','true');
        if(attack==='disabled_duplicate')b.disabled=true;
        if(attack==='multiple')document.querySelector('#other').setAttribute('data-disabled','true');
        if(attack==='class_roundtrip'){b.className='temp';b.className=''}
        if(attack==='replace')b.replaceWith(b.cloneNode(true));
        if(attack==='reparent'){const p=b.parentNode;document.body.appendChild(b);p.appendChild(b)}
        if(attack==='role'){originalCells[0].autocomplete='current-password';originalCells[0].autocomplete='one-time-code'}
      },{once:true});
    }""",
        [attack, initially_disabled],
    )


def setup_noops(nested, attack=None, initially_disabled=True):
    origin, leaf = setup_chain(nested)
    prepare_noops(leaf, attack, initially_disabled)
    target_spec = spec()
    if attack == "complex":
        for f in target_spec["fields"]:
            f["selector"] = "form " + f["selector"]
    return leaf, codes.discover(
        origin,
        "Synthetic exact no-op button metadata",
        nested.sup.task_id,
        parent=nested.parent,
        target_spec=target_spec,
    )[0]


@pytest.mark.parametrize("initially_disabled", [True, False])
def test_exact_one_noop_pair_completes_all_retained_cells(nested, initially_disabled):
    leaf, target = setup_noops(nested, initially_disabled=initially_disabled)
    try:
        with fill_diagnostic_scope() as diag:
            result = codes.fill(target, "123456", time.monotonic() + 60)
        assert result is True, diag
        assert diag["writes_attempted"] == diag["writes_confirmed"] == 6
        assert leaf.evaluate(
            "originalCells.every((e,i)=>e===document.querySelector('[name=code'+i+']')&&e.value===String(i+1)&&!e.hasAttribute('value'))"
        )
    finally:
        codes.release(target)


@pytest.mark.parametrize(
    "attack",
    [
        "data_transition",
        "data_roundtrip",
        "data_duplicate",
        "disabled_duplicate",
        "multiple",
        "class_roundtrip",
        "replace",
        "reparent",
        "source",
        "ancestor",
        "complex",
        "role",
    ],
)
@pytest.mark.parametrize("initially_disabled", [True, False])
def test_noop_acknowledgement_preserves_refusals(nested, attack, initially_disabled):
    leaf, target = setup_noops(nested, attack, initially_disabled)
    try:
        with fill_diagnostic_scope() as diag:
            try:
                result = codes.fill(target, "123456", time.monotonic() + 60)
            except (ValueError, RuntimeError):
                result = False
        assert result is False, diag
        assert leaf.evaluate("originalCells.slice(1).every(e=>e.value==='')")
    finally:
        codes.release(target)
