from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Iterable

from ..config import AuditConfig
from ..models import Finding, GraphNode, ProjectGraph, Severity, SourceLocation, node_id
from ..rules import ALL_REGEX_RULES, RegexRule
from ..utils import iter_with_line_numbers, line_at, looks_like_test_path, make_relative


class Analyzer(ABC):
    language: str = "text"

    def __init__(self, config: AuditConfig) -> None:
        self.config = config

    @abstractmethod
    def analyze(self, root: Path, path: Path, text: str, graph: ProjectGraph) -> list[Finding]:
        raise NotImplementedError

    def add_file_node(self, root: Path, path: Path, graph: ProjectGraph, language: str | None = None) -> str:
        rel = make_relative(root, path)
        fid = node_id("file", rel)
        graph.add_node(GraphNode(id=fid, kind="file", label=rel, path=rel, metadata={"language": language or self.language}))
        return fid

    def regex_findings(self, root: Path, path: Path, text: str, language: str) -> list[Finding]:
        findings: list[Finding] = []
        rel = make_relative(root, path)
        for rule in ALL_REGEX_RULES:
            if rule.languages and language not in rule.languages:
                continue
            for line_no, line in iter_with_line_numbers(text):
                match = rule.pattern.search(line)
                if not match:
                    continue
                if self._is_ignored_in_context(rule, rel, line):
                    continue
                findings.append(self.finding_from_rule(rule, rel, line_no, match.start() + 1, line.strip()))
        return findings

    def finding_from_rule(self, rule: RegexRule, rel: str, line_no: int, col: int, snippet: str) -> Finding:
        severity = self.config.override_severity(rule.rule_id, rule.severity)
        return Finding(
            rule_id=rule.rule_id,
            title=rule.title,
            description=rule.description,
            severity=severity,
            confidence=rule.confidence,
            location=SourceLocation(path=rel, line=line_no, column=col, snippet=snippet[:240]),
            cwe=rule.cwe,
            category=rule.category,
            recommendation=rule.recommendation,
            fix_template=rule.fix_template,
        )

    def style_findings(self, root: Path, path: Path, text: str, language: str) -> list[Finding]:
        rel = make_relative(root, path)
        findings: list[Finding] = []
        max_len = self.config.team_rules.max_line_length
        for line_no, line in iter_with_line_numbers(text):
            if len(line) > max_len:
                findings.append(Finding(
                    rule_id="STYLE-LINE-LENGTH",
                    title="代码行过长",
                    description=f"该行长度为 {len(line)}，超过团队建议的 {max_len}。",
                    severity=self.config.override_severity("STYLE-LINE-LENGTH", Severity.INFO),
                    confidence=0.95,
                    location=SourceLocation(rel, line_no, max_len + 1, snippet=line.strip()[:240]),
                    category="style",
                    recommendation="拆分表达式、提取变量或格式化长字符串，提升可读性。",
                    fix_template="将长表达式拆成多行，并使用格式化工具统一风格。",
                ))
        return findings

    def apply_global_filters(self, findings: Iterable[Finding]) -> list[Finding]:
        filtered: list[Finding] = []
        ignore_rules = set(self.config.ignore_rules)
        ignore_fingerprints = set(self.config.ignore_fingerprints)
        for finding in findings:
            if finding.rule_id in ignore_rules:
                continue
            if finding.fingerprint in ignore_fingerprints:
                continue
            filtered.append(finding)
        return filtered

    def _is_ignored_in_context(self, rule: RegexRule, rel_path: str, line: str) -> bool:
        if "nosec" in line or "codeaudit: ignore" in line:
            return True
        if self.config.team_rules.allow_test_secrets and rule.rule_id.startswith("CWE-798") and looks_like_test_path(rel_path):
            return True
        return False


class TextAnalyzer(Analyzer):
    language = "text"

    def analyze(self, root: Path, path: Path, text: str, graph: ProjectGraph) -> list[Finding]:
        self.add_file_node(root, path, graph, self.language)
        findings = []
        findings.extend(self.regex_findings(root, path, text, self.language))
        findings.extend(self.style_findings(root, path, text, self.language))
        return self.apply_global_filters(findings)
