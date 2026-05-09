from __future__ import annotations

from pathlib import Path
import json
import re

from .models import Dependency
from .utils import make_relative, read_text


REQ_RE = re.compile(r"^\s*([A-Za-z0-9_.-]+)\s*(?:==|>=|<=|~=|>|<)?\s*([^#;\s]+)?")
PYPROJECT_DEP_RE = re.compile(r"^[\s\"]*([A-Za-z0-9_.-]+)(?:[<>=!~ ]+([^\",]+))?")
GRADLE_DEP_RE = re.compile(r"['\"]([A-Za-z0-9_.-]+:[A-Za-z0-9_.-]+):([^'\"]+)['\"]")
MAVEN_GROUP_RE = re.compile(r"<groupId>([^<]+)</groupId>")
MAVEN_ART_RE = re.compile(r"<artifactId>([^<]+)</artifactId>")
MAVEN_VER_RE = re.compile(r"<version>([^<]+)</version>")


def discover_dependencies(root: Path) -> list[Dependency]:
    deps: list[Dependency] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        name = path.name
        try:
            if name == "requirements.txt":
                deps.extend(_parse_requirements(root, path))
            elif name == "package.json":
                deps.extend(_parse_package_json(root, path))
            elif name == "pyproject.toml":
                deps.extend(_parse_pyproject(root, path))
            elif name in {"build.gradle", "build.gradle.kts"}:
                deps.extend(_parse_gradle(root, path))
            elif name == "pom.xml":
                deps.extend(_parse_pom(root, path))
        except Exception:
            # Dependency discovery must not break the scan.
            continue
    return deps


def _parse_requirements(root: Path, path: Path) -> list[Dependency]:
    deps: list[Dependency] = []
    rel = make_relative(root, path)
    for line in read_text(path).splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        m = REQ_RE.match(line)
        if m:
            deps.append(Dependency(m.group(1), m.group(2), "pip", rel))
    return deps


def _parse_package_json(root: Path, path: Path) -> list[Dependency]:
    rel = make_relative(root, path)
    data = json.loads(read_text(path))
    deps: list[Dependency] = []
    for section in ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"]:
        for name, version in data.get(section, {}).items():
            deps.append(Dependency(name, str(version), "npm", rel))
    return deps


def _parse_pyproject(root: Path, path: Path) -> list[Dependency]:
    rel = make_relative(root, path)
    text = read_text(path)
    deps: list[Dependency] = []
    in_deps = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("dependencies") and "[" in stripped:
            in_deps = True
            continue
        if in_deps and stripped.startswith("]"):
            break
        if in_deps:
            m = PYPROJECT_DEP_RE.match(stripped.strip(","))
            if m and m.group(1):
                deps.append(Dependency(m.group(1), m.group(2), "python", rel))
    return deps


def _parse_gradle(root: Path, path: Path) -> list[Dependency]:
    rel = make_relative(root, path)
    deps: list[Dependency] = []
    for m in GRADLE_DEP_RE.finditer(read_text(path)):
        deps.append(Dependency(m.group(1), m.group(2), "gradle", rel))
    return deps


def _parse_pom(root: Path, path: Path) -> list[Dependency]:
    rel = make_relative(root, path)
    text = read_text(path)
    deps: list[Dependency] = []
    for dep_block in re.findall(r"<dependency>(.*?)</dependency>", text, re.DOTALL):
        group = MAVEN_GROUP_RE.search(dep_block)
        art = MAVEN_ART_RE.search(dep_block)
        ver = MAVEN_VER_RE.search(dep_block)
        if group and art:
            deps.append(Dependency(f"{group.group(1)}:{art.group(1)}", ver.group(1) if ver else None, "maven", rel))
    return deps
