"""Project imports and disposable material cleanup for the upstream test wrapper."""
import shutil
import sys
from pathlib import Path
import pytest

ROOT = str(Path(__file__).resolve().parents[1])
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


@pytest.fixture(autouse=True)
def remove_disposable_material(tmp_path):
    """Do not retain fake credentials or private test-CA keys after a test."""
    yield
    shutil.rmtree(tmp_path)
