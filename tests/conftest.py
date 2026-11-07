import importlib.util
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


@pytest.fixture(scope="session")
def plugin():
    """Load the project root as a package, the way Hermes loads a plugin directory."""
    name = "egress_guard_plugin"
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(
            name, os.path.join(ROOT, "__init__.py"), submodule_search_locations=[ROOT])
        mod = importlib.util.module_from_spec(spec)
        sys.modules[name] = mod
        spec.loader.exec_module(mod)
    return sys.modules[name]


@pytest.fixture(scope="session")
def adapter(plugin):
    return sys.modules["egress_guard_plugin.adapter"]


@pytest.fixture(autouse=True)
def _isolate_home(tmp_path, monkeypatch):
    """Keep tests off the real ~/.hermes: register() loads the bundled policy, whose audit path is
    ~/.hermes/egress-guard/audit.jsonl. Without this, test runs appended to the user's real audit log."""
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.delenv("EGRESS_GUARD_POLICY", raising=False)
    monkeypatch.delenv("HERMES_HOME", raising=False)
