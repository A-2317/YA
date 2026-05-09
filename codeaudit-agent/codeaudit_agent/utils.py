from __future__ import annotations

from pathlib import Path
from typing import Iterable
import fnmatch
import re


LANGUAGE_BY_EXTENSION = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
    ".json": "json",
    ".toml": "toml",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".xml": "xml",
    ".properties": "properties",
    ".gradle": "java",
    ".env": "env",
}


def detect_language(path: Path) -> str:
    if path.name == "Dockerfile":
        return "dockerfile"
    return LANGUAGE_BY_EXTENSION.get(path.suffix.lower(), "text")


def is_probably_binary(path: Path, sample_size: int = 4096) -> bool:
    try:
        chunk = path.read_bytes()[:sample_size]
    except OSError:
        return True
    if not chunk:
        return False
    return b"\x00" in chunk


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def line_at(text: str, line_no: int) -> str:
    lines = text.splitlines()
    if 1 <= line_no <= len(lines):
        return lines[line_no - 1].strip()
    return ""


def iter_with_line_numbers(text: str) -> Iterable[tuple[int, str]]:
    for index, line in enumerate(text.splitlines(), start=1):
        yield index, line


def path_matches_any(path: Path, patterns: list[str]) -> bool:
    text = str(path).replace("\\", "/")
    name = path.name
    return any(fnmatch.fnmatch(text, p) or fnmatch.fnmatch(name, p) for p in patterns)


def make_relative(root: Path, path: Path) -> str:
    try:
        return str(path.relative_to(root)).replace("\\", "/")
    except ValueError:
        return str(path).replace("\\", "/")


def strip_string_literals(line: str) -> str:
    # Conservative helper for style rules only. It is not a parser.
    return re.sub(r"(['\"])(?:\\.|(?!\1).)*\1", "''", line)


def looks_like_test_path(path: str) -> bool:
    lowered = path.lower().replace("\\", "/")
    return any(token in lowered for token in ["/test/", "/tests/", "test_", "_test", ".spec.", ".test."])
