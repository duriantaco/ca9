from __future__ import annotations

import textwrap

from ca9.analysis.entry_points import detect_entry_points


def test_detect_flask_routes(tmp_path):
    (tmp_path / "app.py").write_text(
        textwrap.dedent("""\
        from flask import Flask

        app = Flask(__name__)

        @app.route("/hello")
        def hello():
            return "Hello"

        @app.route("/world")
        def world():
            return "World"
    """)
    )

    eps = detect_entry_points(tmp_path)
    names = {ep.qualified_name for ep in eps}
    assert "app.hello" in names
    assert "app.world" in names

    flask_eps = [ep for ep in eps if ep.kind == "flask_route"]
    assert len(flask_eps) == 2
    routes = {ep.route for ep in flask_eps}
    assert "/hello" in routes
    assert "/world" in routes


def test_detect_fastapi_routes(tmp_path):
    (tmp_path / "main.py").write_text(
        textwrap.dedent("""\
        from fastapi import FastAPI

        app = FastAPI()

        @app.get("/items")
        async def list_items():
            return []

        @app.post("/items")
        async def create_item():
            return {}
    """)
    )

    eps = detect_entry_points(tmp_path)
    names = {ep.qualified_name for ep in eps}
    assert "main.list_items" in names
    assert "main.create_item" in names

    fastapi_eps = [ep for ep in eps if ep.kind == "fastapi_route"]
    assert len(fastapi_eps) == 2


def test_detect_fastapi_router(tmp_path):
    (tmp_path / "routes.py").write_text(
        textwrap.dedent("""\
        from fastapi import APIRouter

        router = APIRouter()

        @router.get("/users")
        async def get_users():
            return []
    """)
    )

    eps = detect_entry_points(tmp_path)
    names = {ep.qualified_name for ep in eps}
    assert "routes.get_users" in names


def test_detect_click_commands(tmp_path):
    (tmp_path / "cli.py").write_text(
        textwrap.dedent("""\
        import click

        @click.command()
        def main():
            pass

        @click.group()
        def grp():
            pass
    """)
    )

    eps = detect_entry_points(tmp_path)
    click_eps = [ep for ep in eps if ep.kind == "click_command"]
    names = {ep.qualified_name for ep in click_eps}
    assert "cli.main" in names
    assert "cli.grp" in names


def test_detect_django_views(tmp_path):
    (tmp_path / "urls.py").write_text(
        textwrap.dedent("""\
        from django.urls import path
        from views import home, about

        urlpatterns = [
            path("", home),
            path("about/", about),
        ]
    """)
    )

    eps = detect_entry_points(tmp_path)
    django_eps = [ep for ep in eps if ep.kind == "django_view"]
    names = {ep.qualified_name for ep in django_eps}
    assert "views.home" in names
    assert "views.about" in names


def test_detect_main_block(tmp_path):
    (tmp_path / "script.py").write_text(
        textwrap.dedent("""\
        def run():
            pass

        if __name__ == "__main__":
            run()
    """)
    )

    eps = detect_entry_points(tmp_path)
    main_eps = [ep for ep in eps if ep.kind == "main_block"]
    assert len(main_eps) == 1
    assert main_eps[0].qualified_name == "script.__main__"


def test_detect_multiple_frameworks(tmp_path):
    (tmp_path / "app.py").write_text(
        textwrap.dedent("""\
        from flask import Flask

        app = Flask(__name__)

        @app.route("/")
        def index():
            return "ok"
    """)
    )

    (tmp_path / "cli.py").write_text(
        textwrap.dedent("""\
        import click

        @click.command()
        def run():
            pass
    """)
    )

    (tmp_path / "main.py").write_text(
        textwrap.dedent("""\
        if __name__ == "__main__":
            pass
    """)
    )

    eps = detect_entry_points(tmp_path)
    kinds = {ep.kind for ep in eps}
    assert "flask_route" in kinds
    assert "click_command" in kinds
    assert "main_block" in kinds


def test_excludes_test_dirs(tmp_path):
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_app.py").write_text(
        textwrap.dedent("""\
        from flask import Flask
        app = Flask(__name__)

        @app.route("/test")
        def test_route():
            return "test"
    """)
    )

    eps = detect_entry_points(tmp_path)
    assert len(eps) == 0


def test_flask_blueprint(tmp_path):
    (tmp_path / "bp.py").write_text(
        textwrap.dedent("""\
        from flask import Blueprint

        bp = Blueprint("main", __name__)

        @bp.route("/api")
        def api_handler():
            return {}
    """)
    )

    eps = detect_entry_points(tmp_path)
    names = {ep.qualified_name for ep in eps}
    assert "bp.api_handler" in names


def test_empty_repo(tmp_path):
    eps = detect_entry_points(tmp_path)
    assert eps == []


def test_syntax_error_file(tmp_path):
    (tmp_path / "bad.py").write_text("def broken(:\n  pass")
    eps = detect_entry_points(tmp_path)
    assert eps == []
