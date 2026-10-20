#!/usr/bin/env python3
"""
Behavior-preserving dead-code removal for .github/workflows/dead-code.yml.

Only two kinds of edits are made - both can't change what the program does:

  1. Unreachable code: statements after return/raise/break/continue in the
     same block. Skipped if that code binds a name (an assignment there still
     makes the name local), declares global/nonlocal, defines or imports
     something, or contains yield (`return; yield` makes a generator).

  2. Unused top-level imports: whole module-level import statements whose
     every name is unused according to pyflakes. Imports inside try/if/def/
     class are NEVER touched - those are often availability checks like
     `try: import ssl` or platform-specific. Also skipped: __init__.py,
     `from __future__`, and any import marked `# noqa`. An import that is
     only there for its side effect must be marked `# noqa`.

Everything else (unused functions, classes, variables, arguments) is only
reported by vulture in the PR, never edited.
"""
import argparse
import ast
import subprocess
from pathlib import Path

from pyflakes import checker, messages

TERMINATORS = (ast.Return, ast.Raise, ast.Break, ast.Continue)
UNSAFE_IN_DEAD_CODE = (
    ast.Yield, ast.YieldFrom, ast.Global, ast.Nonlocal, ast.Import, ast.ImportFrom,
    ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.NamedExpr, ast.Match,
)


def python_files():
    tracked = subprocess.run(["git", "ls-files", "-z"], capture_output=True, check=True).stdout
    for name in tracked.decode().split("\0"):
        path = Path(name)
        if not name or path.name == "__init__.py" or not path.is_file():
            continue
        if path.suffix == ".py":
            yield path
            continue
        try:
            with path.open("rb") as f:
                first = f.readline()
        except OSError:
            continue
        if first.startswith(b"#!") and b"python" in first:
            yield path   # e.g. Build-Project.command


def start_line(node):
    return min([node.lineno] + [d.lineno for d in getattr(node, "decorator_list", [])])


def binds_or_unsafe(stmts):
    for stmt in stmts:
        for node in ast.walk(stmt):
            if isinstance(node, UNSAFE_IN_DEAD_CODE):
                return True
            if isinstance(node, ast.Name) and not isinstance(node.ctx, ast.Load):
                return True
            if isinstance(node, ast.ExceptHandler) and node.name:
                return True
    return False


def unreachable_ranges(tree):
    ranges = []
    for node in ast.walk(tree):
        for field in ("body", "orelse", "finalbody"):
            block = getattr(node, field, None)
            if not isinstance(block, list) or not block or not isinstance(block[0], ast.stmt):
                continue
            for i, stmt in enumerate(block[:-1]):
                if isinstance(stmt, TERMINATORS):
                    dead = block[i + 1:]
                    first = start_line(dead[0])
                    if stmt.end_lineno >= first or binds_or_unsafe(dead):
                        break   # shares a line (`return; x`) or not provably safe
                    ranges.append((first, dead[-1].end_lineno, "unreachable code"))
                    break
    return ranges


def unused_import_ranges(tree, path, lines):
    unused = [m for m in checker.Checker(tree, filename=str(path)).messages
              if isinstance(m, messages.UnusedImport)]
    ranges = []
    for stmt in tree.body:   # module level only
        if not isinstance(stmt, (ast.Import, ast.ImportFrom)):
            continue
        if isinstance(stmt, ast.ImportFrom) and stmt.module == "__future__":
            continue
        if any("noqa" in lines[n - 1] for n in range(stmt.lineno, stmt.end_lineno + 1)):
            continue
        hits = [m for m in unused if stmt.lineno <= m.lineno <= stmt.end_lineno]
        if len(hits) >= len(stmt.names):   # every name in the statement is unused
            ranges.append((stmt.lineno, stmt.end_lineno, "unused import"))
    return ranges


def merge(ranges):
    merged = []
    for start, end, kind in sorted(ranges):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(end, merged[-1][1]), merged[-1][2])
        else:
            merged.append((start, end, kind))
    return merged


def process(path):
    source = path.read_text(encoding="utf-8")
    try:
        tree = ast.parse(source, filename=str(path))
    except (SyntaxError, ValueError):
        return []
    lines = source.splitlines(keepends=True)
    ranges = merge(unreachable_ranges(tree) + unused_import_ranges(tree, path, lines))
    if not ranges:
        return []

    removed = []
    for start, end, kind in reversed(ranges):
        removed.append((start, kind, lines[start - 1].strip()))
        del lines[start - 1:end]
    new_source = "".join(lines)
    try:
        ast.parse(new_source, filename=str(path))
    except SyntaxError:
        return []   # never leave a file broken
    path.write_text(new_source, encoding="utf-8")
    return [(path, line, kind, text) for line, kind, text in reversed(removed)]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", help="Write a Markdown list of removals here")
    args = parser.parse_args()

    removed = [item for path in python_files() for item in process(path)]
    report = [f"- `{path}:{line}` ({kind}): `{text[:120]}`" for path, line, kind, text in removed]
    print("\n".join(report) or "Nothing removed")
    if args.report:
        Path(args.report).write_text("\n".join(report) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
