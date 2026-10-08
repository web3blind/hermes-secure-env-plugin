"""Exercise the inherited top-level selection-to-HTTPS protected-fill path."""
import os
import subprocess
import sys
from pathlib import Path
from test_nested_code import nested as nested


def test_top_level_registered_browser_flow(nested):
    from tools import browser_supervisor
    core = str(Path(browser_supervisor.__file__).resolve().parents[1])
    env = dict(os.environ, SENV_TEST_CDP_URL=nested.endpoint, SENV_CORE_ROOT=core)
    proc = subprocess.run([sys.executable, str(Path(__file__).with_name('browser_code_selection_check.py'))],
                          env=env, capture_output=True, text=True, timeout=240)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert 'REGISTERED_HTTPS_FILL' in proc.stdout


def test_discovery_does_not_change_focus_emulation(nested, monkeypatch):
    from test_nested_code import setup_chain
    from secure_env_ingress import code_targets as codes, nested_code
    origin, _ = setup_chain(nested)
    nested.page.goto(origin+'/leaf')
    methods = []
    original = nested_code._call
    def observe(sup, method, params=None, sid=None):
        methods.append(method)
        return original(sup, method, params, sid)
    monkeypatch.setattr(nested_code, '_call', observe)
    targets = codes.discover(origin, 'Synthetic', nested.sup.task_id)
    try:
        assert len(targets) == 1
        assert 'Emulation.setFocusEmulationEnabled' not in methods
    finally:
        for target in targets:
            codes.release(target)
