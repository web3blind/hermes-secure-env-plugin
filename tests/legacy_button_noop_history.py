"""Exact no-op submit metadata is not a new destination or state transition."""

import time
import pytest
from test_nested_code import nested as nested, setup_chain
from legacy_input_reconciliation import prepare
from legacy_cds_caret_palette import install_cds_caret_palette
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
