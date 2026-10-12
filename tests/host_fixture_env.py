"""Keep subprocesses on the actual candidate and clean imported host."""
import os
from pathlib import Path
import hermes_constants
import secure_env_ingress


def host_env(**values):
    return dict(os.environ, **values, PYTHONPATH=os.pathsep.join([
        str(Path(secure_env_ingress.__file__).resolve().parents[1]),
        str(Path(hermes_constants.__file__).resolve().parent),
    ]))
