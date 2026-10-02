#!/usr/bin/env python3
"""
check_python.py: Find Python code that cannot run.

Only reports problems that make Python fail when the code runs, not style:
  - syntax errors (SyntaxError, IndentationError, TabError), via compile()
  - names that are used but never defined (NameError), via pyflakes, plus the
    other pyflakes messages that are errors rather than warnings
  - relative imports inside the repo that point at a module, or a name in a
    module, that does not exist (ImportError at import time)

Nothing is imported or executed: every file is only parsed. That makes it safe
to run on untrusted PR code.

Usage:
  check_python.py --root <repo dir> [--baseline <repo dir>] [--json <out>]

With --baseline, problems that already exist in the baseline tree (same file,
same message) are dropped, so a PR is only blamed for what it introduces.
"""

import argparse
import ast
import json
import os
import re
import sys
import warnings
from pathlib import Path

from pyflakes import checker as pyflakes_checker
from pyflakes import messages as m

# pyflakes messages that mean the code will fail at runtime (the rest are
# style warnings such as unused imports or variables).
ERROR_MESSAGES = tuple(getattr(m, n) for n in [
    "UndefinedName",
    "UndefinedLocal",
    "UndefinedExport",
    "DuplicateArgument",
    "ReturnOutsideFunction",
    "YieldOutsideFunction",
    "ContinueOutsideLoop",
    "BreakOutsideLoop",
    "DefaultExceptNotLast",
    "TwoStarredExpressions",
    "TooManyExpressionsInStarredAssignment",
    "StringDotFormatExtraPositionalArguments",
    "StringDotFormatExtraNamedArguments",
    "StringDotFormatMissingArgument",
    "StringDotFormatMixingAutomatic",
    "StringDotFormatInvalidFormat",
    "PercentFormatInvalidFormat",
    "PercentFormatMixedPositionalAndNamed",
    "PercentFormatUnsupportedFormatCharacter",
    "PercentFormatPositionalCountMismatch",
    "PercentFormatExtraNamedArguments",
    "PercentFormatMissingArgument",
    "PercentFormatExpectedMapping",
    "PercentFormatExpectedSequence",
    "PercentFormatStarRequiresSequence",
    "ForwardAnnotationSyntaxError",
    "RaiseNotImplemented",
    "InvalidPrintSyntax",
] if hasattr(m, n))

SKIP_DIRS = {".git", "node_modules", "__pycache__", "dist", "build", "venv", ".venv"}
PY_SHEBANG = re.compile(rb"^#!.*\bpython[0-9.]*\b")


def python_files(root: Path) -> list:
    files = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            path = Path(dirpath) / name
            if name.endswith(".py"):
                files.append(path)
            elif name.endswith(".command"):
                try:
                    with open(path, "rb") as f:
                        if PY_SHEBANG.match(f.readline()):
                            files.append(path)
                except OSError:
                    pass
    return sorted(files)


class ModuleIndex:
    """Top-level names per module file, parsed lazily (for import checks)."""

    def __init__(self, root: Path):
        self.root = root
        self.cache = {}

    def names(self, path: Path):
        if path not in self.cache:
            try:
                tree = ast.parse(path.read_bytes(), filename=str(path))
            except Exception:
                self.cache[path] = None          # broken module: reported on its own
                return None
            names, star = set(), False
            for node in tree.body:
                names |= _bound_names(node)
                if isinstance(node, ast.ImportFrom) and any(a.name == "*" for a in node.names):
                    star = True
                if isinstance(node, (ast.If, ast.Try)):
                    for sub in ast.walk(node):
                        names |= _bound_names(sub)
            self.cache[path] = (names, star)
        return self.cache[path]


def _bound_names(node) -> set:
    out = set()
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        out.add(node.name)
    elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        for t in targets:
            for n in ast.walk(t):
                if isinstance(n, ast.Name):
                    out.add(n.id)
    elif isinstance(node, (ast.Import, ast.ImportFrom)):
        for a in node.names:
            if a.name != "*":
                out.add((a.asname or a.name).split(".")[0])
    return out


def resolve(base_dir: Path, dotted: str):
    """Return (module_file, package_dir) for a dotted path under base_dir."""
    target = base_dir
    for part in [p for p in dotted.split(".") if p]:
        target = target / part
    if (target.with_suffix(".py")).is_file():
        return target.with_suffix(".py"), None
    if (target / "__init__.py").is_file():
        return target / "__init__.py", target
    if target.is_dir():
        return None, target                     # namespace package
    return None, None


def check_imports(path: Path, tree, index: ModuleIndex) -> list:
    problems = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom) or not node.level:
            continue
        base = path.parent
        for _ in range(node.level - 1):
            base = base.parent
        module = node.module or ""
        mod_file, pkg_dir = resolve(base, module)
        shown = "." * node.level + module
        if module and mod_file is None and pkg_dir is None:
            problems.append((node.lineno, f"ImportError: no module named '{shown}'"))
            continue
        for alias in node.names:
            if alias.name == "*":
                continue
            # 'from pkg import sub' may name a submodule
            if pkg_dir is not None and (
                (pkg_dir / f"{alias.name}.py").is_file() or (pkg_dir / alias.name / "__init__.py").is_file()
                or (pkg_dir / alias.name).is_dir()
            ):
                continue
            if mod_file is None:
                problems.append((node.lineno, f"ImportError: cannot import name '{alias.name}' from '{shown}'"))
                continue
            info = index.names(mod_file)
            if info is None:
                continue
            names, star = info
            if alias.name not in names and not star:
                problems.append((node.lineno, f"ImportError: cannot import name '{alias.name}' from '{shown}'"))
    return problems


def check_file(path: Path, index: ModuleIndex) -> list:
    source = path.read_bytes()
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            compile(source, str(path), "exec", dont_inherit=True)
        tree = ast.parse(source, filename=str(path))
    except SyntaxError as e:
        kind = type(e).__name__
        return [(e.lineno or 0, f"{kind}: {e.msg}")]
    except ValueError as e:                     # e.g. null bytes
        return [(0, f"SyntaxError: {e}")]

    problems = []
    w = pyflakes_checker.Checker(tree, filename=str(path))
    for msg in w.messages:
        if isinstance(msg, ERROR_MESSAGES):
            text = msg.message % msg.message_args
            prefix = "NameError" if isinstance(msg, (m.UndefinedName, m.UndefinedLocal, m.UndefinedExport)) else "Error"
            problems.append((msg.lineno, f"{prefix}: {text}"))
    problems += check_imports(path, tree, index)
    return problems


def scan(root: Path) -> list:
    index = ModuleIndex(root)
    results = []
    for path in python_files(root):
        rel = path.relative_to(root).as_posix()
        for line, text in check_file(path, index):
            results.append({"file": rel, "line": line, "message": text})
    return results


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True)
    ap.add_argument("--baseline")
    ap.add_argument("--json")
    args = ap.parse_args()

    problems = scan(Path(args.root).resolve())
    if args.baseline:
        known = {(p["file"], p["message"]) for p in scan(Path(args.baseline).resolve())}
        problems = [p for p in problems if (p["file"], p["message"]) not in known]

    if args.json:
        with open(args.json, "w") as f:
            json.dump(problems, f, indent=2)

    if not problems:
        print("OK: no syntax errors or code that would fail at runtime found")
        return 0
    for p in problems:
        print(f"::error file={p['file']},line={p['line']}::{p['message']}")
        print(f"  {p['file']}:{p['line']}: {p['message']}")
    print(f"\n{len(problems)} problem(s) found")
    return 1


if __name__ == "__main__":
    sys.exit(main())
