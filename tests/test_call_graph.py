from __future__ import annotations

import textwrap

from ca9.analysis.call_graph import (
    CallGraph,
    CallGraphNode,
    _extract_functions,
    _module_name_from_path,
    build_call_graph,
)


def test_module_name_from_path(tmp_path):
    repo = tmp_path / "myproject"
    repo.mkdir()
    f = repo / "src" / "app" / "main.py"
    f.parent.mkdir(parents=True)
    f.write_text("")
    assert _module_name_from_path(f, repo) == "src.app.main"


def test_module_name_from_init(tmp_path):
    repo = tmp_path / "myproject"
    repo.mkdir()
    f = repo / "src" / "app" / "__init__.py"
    f.parent.mkdir(parents=True)
    f.write_text("")
    assert _module_name_from_path(f, repo) == "src.app"


def test_extract_functions_simple(tmp_path):
    import ast

    source = textwrap.dedent("""\
        def hello():
            pass

        def world():
            pass
    """)
    tree = ast.parse(source)
    funcs = _extract_functions(tree, "mymod", "mymod.py")
    names = [name for name, _node in funcs]
    assert "mymod.hello" in names
    assert "mymod.world" in names


def test_extract_functions_class_methods(tmp_path):
    import ast

    source = textwrap.dedent("""\
        class MyClass:
            def method_a(self):
                pass

            async def method_b(self):
                pass
    """)
    tree = ast.parse(source)
    funcs = _extract_functions(tree, "mymod", "mymod.py")
    names = [name for name, _node in funcs]
    assert "mymod.MyClass.method_a" in names
    assert "mymod.MyClass.method_b" in names


def test_build_call_graph_simple(tmp_path):
    src = tmp_path / "app.py"
    src.write_text(
        textwrap.dedent("""\
        def handler():
            process()

        def process():
            pass
    """)
    )

    graph = build_call_graph(tmp_path)
    assert "app.handler" in graph.nodes
    assert "app.process" in graph.nodes
    assert "app.process" in graph.edges.get("app.handler", set())


def test_build_call_graph_cross_file(tmp_path):
    (tmp_path / "app.py").write_text(
        textwrap.dedent("""\
        from services import fetch_data

        def handler():
            fetch_data()
    """)
    )

    svc = tmp_path / "services.py"
    svc.write_text(
        textwrap.dedent("""\
        def fetch_data():
            pass
    """)
    )

    graph = build_call_graph(tmp_path)
    assert "app.handler" in graph.nodes
    assert "services.fetch_data" in graph.nodes
    assert "services.fetch_data" in graph.edges.get("app.handler", set())


def test_build_call_graph_with_entry_points(tmp_path):
    (tmp_path / "app.py").write_text(
        textwrap.dedent("""\
        def handler():
            pass
    """)
    )

    graph = build_call_graph(tmp_path, entry_point_names={"app.handler"})
    assert graph.nodes["app.handler"].is_entry_point is True
    assert "app.handler" in graph.entry_points


def test_build_call_graph_with_main_block_entry_point(tmp_path):
    (tmp_path / "script.py").write_text(
        textwrap.dedent("""\
        def run():
            pass

        if __name__ == "__main__":
            run()
    """)
    )

    graph = build_call_graph(tmp_path, entry_point_names={"script.__main__"})

    assert "script.__main__" in graph.nodes
    assert graph.nodes["script.__main__"].is_entry_point is True
    assert "script.__main__" in graph.entry_points
    assert "script.run" in graph.edges.get("script.__main__", set())


def test_call_graph_excludes_test_files(tmp_path):
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_app.py").write_text("def test_foo(): pass")
    (tmp_path / "app.py").write_text("def handler(): pass")

    graph = build_call_graph(tmp_path)
    assert "app.handler" in graph.nodes
    assert not any("test_foo" in name for name in graph.nodes)


def test_call_graph_add_node_and_edge():
    graph = CallGraph()
    node = CallGraphNode(file_path="f.py", function_name="foo", line_start=1, line_end=3)
    graph.add_node("mod.foo", node)
    graph.add_edge("mod.foo", "mod.bar")

    assert "mod.foo" in graph.nodes
    assert "mod.bar" in graph.edges["mod.foo"]


def test_build_call_graph_syntax_error(tmp_path):
    (tmp_path / "bad.py").write_text("def broken(:\n  pass")
    (tmp_path / "good.py").write_text("def works(): pass")

    graph = build_call_graph(tmp_path)
    assert "good.works" in graph.nodes
    assert not any("broken" in name for name in graph.nodes)


def test_call_graph_async_functions(tmp_path):
    (tmp_path / "app.py").write_text(
        textwrap.dedent("""\
        async def async_handler():
            await process()

        async def process():
            pass
    """)
    )

    graph = build_call_graph(tmp_path)
    assert "app.async_handler" in graph.nodes
    assert "app.process" in graph.nodes


def test_call_graph_import_alias(tmp_path):
    (tmp_path / "app.py").write_text(
        textwrap.dedent("""\
        import services as svc

        def handler():
            svc.fetch()
    """)
    )

    (tmp_path / "services.py").write_text(
        textwrap.dedent("""\
        def fetch():
            pass
    """)
    )

    graph = build_call_graph(tmp_path)
    edges = graph.edges.get("app.handler", set())
    assert "services.fetch" in edges
