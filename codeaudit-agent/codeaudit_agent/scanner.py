from __future__ import annotations

from pathlib import Path
from datetime import datetime, timezone
import time

from .analyzers.base import TextAnalyzer
from .analyzers.java import JavaAnalyzer
from .analyzers.javascript import JavaScriptAnalyzer
from .analyzers.python import PythonAnalyzer
from .config import AuditConfig
from .dependencies import discover_dependencies
from .models import ProjectGraph, ScanResult, ScanSummary, sort_findings
from .utils import detect_language, is_probably_binary, make_relative, path_matches_any, read_text


class AuditAgent:
    def __init__(self, config: AuditConfig | None = None) -> None:
        self.config = config or AuditConfig.default()
        self.analyzers = {
            "python": PythonAnalyzer(self.config),
            "javascript": JavaScriptAnalyzer(self.config),
            "typescript": JavaScriptAnalyzer(self.config),
            "java": JavaAnalyzer(self.config),
            "text": TextAnalyzer(self.config),
            "json": TextAnalyzer(self.config),
            "toml": TextAnalyzer(self.config),
            "yaml": TextAnalyzer(self.config),
            "xml": TextAnalyzer(self.config),
            "properties": TextAnalyzer(self.config),
            "env": TextAnalyzer(self.config),
        }

    def scan(self, root_path: str | Path) -> ScanResult:
        start = time.time()
        root = Path(root_path).resolve()
        if not root.exists():
            raise FileNotFoundError(f"Scan root does not exist: {root}")
        if not root.is_dir():
            raise NotADirectoryError(f"Scan root must be a directory: {root}")

        graph = ProjectGraph()
        findings = []
        summary = ScanSummary()

        files = list(self._iter_source_files(root))
        for path in files:
            rel = make_relative(root, path)
            language = detect_language(path)
            analyzer = self.analyzers.get(language, self.analyzers["text"])
            try:
                text = read_text(path)
            except OSError:
                continue
            summary.files_scanned += 1
            summary.lines_scanned += len(text.splitlines())
            summary.by_language[language] = summary.by_language.get(language, 0) + 1
            file_findings = analyzer.analyze(root, path, text, graph)
            findings.extend(file_findings)

        findings = sort_findings(findings)
        for finding in findings:
            summary.by_severity[finding.severity.value] = summary.by_severity.get(finding.severity.value, 0) + 1
            summary.by_category[finding.category] = summary.by_category.get(finding.category, 0) + 1
        summary.findings_total = len(findings)

        dependencies = discover_dependencies(root)
        summary.dependencies_total = len(dependencies)

        metadata = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "duration_seconds": round(time.time() - start, 3),
            "engine": "codeaudit-agent",
            "version": "0.1.0",
            "policy": "defensive-static-audit-only",
        }
        return ScanResult(str(root), summary, findings, dependencies, graph, metadata)

    def _iter_source_files(self, root: Path):
        excluded_dirs = set(self.config.exclude_dirs)
        include_ext = set(self.config.include_extensions)
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if any(part in excluded_dirs for part in path.parts):
                continue
            if path.name in self.config.exclude_files:
                continue
            if path_matches_any(path, self.config.exclude_files):
                continue
            if path.stat().st_size > self.config.max_file_size_bytes:
                continue
            if path.suffix.lower() not in include_ext and path.name not in {"Dockerfile", ".env"}:
                continue
            if is_probably_binary(path):
                continue
            yield path
