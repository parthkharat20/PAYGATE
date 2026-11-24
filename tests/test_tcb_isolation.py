"""
Architectural AST Isolation Test for the Trusted Computing Base (TCB).
Formally asserts that paygate/tcb/ has ZERO imports of LLMs, agent frameworks, or network I/O.
"""

import ast
import os
import pytest

BANNED_MODULES = {
    "openai",
    "anthropic",
    "langchain",
    "litellm",
    "requests",
    "httpx",
    "urllib",
    "urllib3",
    "http.client",
    "socket",
    "aiohttp",
}


def get_tcb_python_files():
    tcb_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "paygate", "tcb"))
    py_files = []
    for root, _, files in os.walk(tcb_dir):
        for f in files:
            if f.endswith(".py"):
                py_files.append(os.path.join(root, f))
    return py_files


@pytest.mark.parametrize("file_path", get_tcb_python_files())
def test_tcb_strict_isolation_invariants(file_path):
    """
    Assert that every module in paygate/tcb/ strictly conforms to zero-network,
    zero-LLM, zero-agent framework architectural isolation.
    """
    with open(file_path, "r", encoding="utf-8") as f:
        tree = ast.parse(f.read(), filename=file_path)

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root_module = alias.name.split(".")[0]
                assert root_module not in BANNED_MODULES, (
                    f"TCB ISOLATION VIOLATION in {os.path.basename(file_path)}: "
                    f"Banned import '{alias.name}' detected!"
                )
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                root_module = node.module.split(".")[0]
                assert root_module not in BANNED_MODULES, (
                    f"TCB ISOLATION VIOLATION in {os.path.basename(file_path)}: "
                    f"Banned from-import '{node.module}' detected!"
                )
