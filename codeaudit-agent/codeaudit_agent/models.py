from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Any, Iterable
import hashlib
import json


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }[self]

    @classmethod
    def from_string(cls, value: str) -> "Severity":
        value = (value or "").strip().lower()
        for sev in cls:
            if sev.value == value:
                return sev
        raise ValueError(f"Unknown severity: {value}")


@dataclass(frozen=True)
class SourceLocation:
    path: str
    line: int = 1
    column: int = 1
    end_line: int | None = None
    snippet: str | None = None

    def display(self) -> str:
        return f"{self.path}:{self.line}:{self.column}"


@dataclass
class Finding:
    rule_id: str
    title: str
    description: str
    severity: Severity
    confidence: float
    location: SourceLocation
    cwe: str | None = None
    category: str = "security"
    evidence: dict[str, Any] = field(default_factory=dict)
    recommendation: str = ""
    fix_template: str = ""
    references: list[str] = field(default_factory=list)
    fingerprint: str = ""

    def __post_init__(self) -> None:
        if not self.fingerprint:
            payload = "|".join([
                self.rule_id,
                self.location.path,
                str(self.location.line),
                str(self.location.column),
                self.location.snippet or "",
            ])
            self.fingerprint = hashlib.sha256(payload.encode("utf-8", errors="ignore")).hexdigest()[:16]
        self.confidence = max(0.0, min(1.0, float(self.confidence)))

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        return data


@dataclass
class Dependency:
    name: str
    version: str | None
    manager: str
    source_file: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class GraphNode:
    id: str
    kind: str
    label: str
    path: str | None = None
    line: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class GraphEdge:
    source: str
    target: str
    kind: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ProjectGraph:
    nodes: dict[str, GraphNode] = field(default_factory=dict)
    edges: list[GraphEdge] = field(default_factory=list)

    def add_node(self, node: GraphNode) -> None:
        self.nodes.setdefault(node.id, node)

    def add_edge(self, source: str, target: str, kind: str, **metadata: Any) -> None:
        self.edges.append(GraphEdge(source=source, target=target, kind=kind, metadata=metadata))

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "edges": [e.to_dict() for e in self.edges],
        }

    def to_dot(self) -> str:
        lines = ["digraph CodeAuditGraph {", "  rankdir=LR;", "  node [shape=box];"]
        for node in self.nodes.values():
            label = node.label.replace('"', "'")
            lines.append(f'  "{node.id}" [label="{label}\\n({node.kind})"];')
        for edge in self.edges:
            label = edge.kind.replace('"', "'")
            lines.append(f'  "{edge.source}" -> "{edge.target}" [label="{label}"];')
        lines.append("}")
        return "\n".join(lines) + "\n"


@dataclass
class ScanSummary:
    files_scanned: int = 0
    lines_scanned: int = 0
    findings_total: int = 0
    by_severity: dict[str, int] = field(default_factory=dict)
    by_category: dict[str, int] = field(default_factory=dict)
    by_language: dict[str, int] = field(default_factory=dict)
    dependencies_total: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    root: str
    summary: ScanSummary
    findings: list[Finding]
    dependencies: list[Dependency]
    graph: ProjectGraph
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "root": self.root,
            "summary": self.summary.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
            "dependencies": [d.to_dict() for d in self.dependencies],
            "graph": self.graph.to_dict(),
            "metadata": self.metadata,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)

    def should_fail(self, min_severity: Severity | None) -> bool:
        if min_severity is None:
            return False
        return any(f.severity.rank >= min_severity.rank for f in self.findings)


def sort_findings(findings: Iterable[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda f: (-f.severity.rank, -f.confidence, f.location.path, f.location.line, f.rule_id),
    )


def node_id(*parts: str) -> str:
    raw = ":".join(str(p) for p in parts)
    digest = hashlib.sha1(raw.encode("utf-8", errors="ignore")).hexdigest()[:12]
    safe_tail = Path(parts[-1]).name if parts else "node"
    return f"{safe_tail}:{digest}"
