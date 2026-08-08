"""alternatives.py must execute nothing — same guarantee as proposals.py / the graph orchestrators."""
import ast
import pathlib

_BANNED = {"system", "popen", "run", "call", "check_output", "exec", "execv", "execve",
           "spawn", "spawnv", "fork", "eval"}


def test_alternatives_executes_nothing():
    src = pathlib.Path(__file__).with_name("alternatives.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            fn = node.func
            name = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", "")
            assert name.lower() not in _BANNED, f"alternatives.py must not call {name}()"
        if isinstance(node, ast.Import):
            for a in node.names:
                assert a.name != "subprocess", "alternatives.py must not import subprocess"
        if isinstance(node, ast.ImportFrom):
            assert node.module != "subprocess", "alternatives.py must not import subprocess"
