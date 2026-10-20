"""Known registered provider flows on disposable Chromium only."""
import json
import os
from pathlib import Path
import subprocess
import sys
from test_nested_code import nested as nested


def test_registered_provider_browser_smoke(nested):
    import secure_env_ingress
    from tools import browser_supervisor
    root = Path(secure_env_ingress.__file__).resolve().parents[1]
    core = Path(browser_supervisor.__file__).resolve().parents[1]
    env = dict(os.environ, SENV_TEST_CDP=nested.endpoint,
               PYTHONPATH=os.pathsep.join([str(root), str(core), str(Path(__file__).parent)]))
    run = subprocess.run([sys.executable, str(Path(__file__).with_name('browser_payment_iframe_check.py')), '--provider-smoke'],
                         env=env, capture_output=True, text=True, timeout=240)
    assert run.returncode == 0, run.stdout + run.stderr
    result = json.loads(run.stdout.splitlines()[-1])
    assert result['protected_iframe_browser'] == 'PASS'
    assert result['page_errors'] == 0
    assert Path(result['runtime_package']) == root / 'secure_env_ingress'
    assert result['checks'] and all(result['checks'].values())
