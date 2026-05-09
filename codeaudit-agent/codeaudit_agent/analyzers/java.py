from __future__ import annotations

from pathlib import Path
import re

from .base import Analyzer
from ..models import Finding, GraphNode, ProjectGraph, Severity, SourceLocation, node_id
from ..utils import iter_with_line_numbers, make_relative


CLASS_RE = re.compile(r"\b(class|interface|enum)\s+([A-Za-z_$][\w$]*)")
METHOD_RE = re.compile(r"\b(public|protected|private|static|final|synchronized|native|abstract|\s)+\s*[\w<>\[\], ?]+\s+([A-Za-z_$][\w$]*)\s*\([^;]*\)\s*\{")
IMPORT_RE = re.compile(r"^\s*import\s+([\w.*]+);")
CALL_RE = re.compile(r"\b([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*\(")
SQL_KEYWORD_RE = re.compile(r"(?i)\b(select|insert|update|delete)\b.*\b(from|into|set|where)\b")


class JavaAnalyzer(Analyzer):
    language = "java"

    def analyze(self, root: Path, path: Path, text: str, graph: ProjectGraph) -> list[Finding]:
        rel = make_relative(root, path)
        file_id = self.add_file_node(root, path, graph, self.language)
        findings: list[Finding] = []
        findings.extend(self.regex_findings(root, path, text, self.language))
        findings.extend(self.style_findings(root, path, text, self.language))
        findings.extend(self._semantic_scan(rel, file_id, text, graph))
        return self.apply_global_filters(findings)

    def _semantic_scan(self, rel: str, file_id: str, text: str, graph: ProjectGraph) -> list[Finding]:
        findings: list[Finding] = []
        current = file_id
        for line_no, line in iter_with_line_numbers(text):
            stripped = line.strip()
            import_match = IMPORT_RE.search(line)
            if import_match:
                name = import_match.group(1)
                import_id = node_id("import", name)
                graph.add_node(GraphNode(import_id, "import", name, rel, line_no))
                graph.add_edge(file_id, import_id, "imports")

            cls = CLASS_RE.search(line)
            if cls:
                name = cls.group(2)
                class_id = node_id("class", rel, name)
                current = class_id
                graph.add_node(GraphNode(class_id, "class", name, rel, line_no))
                graph.add_edge(file_id, class_id, "defines")

            method = METHOD_RE.search(line)
            if method and method.group(2) not in {"if", "for", "while", "switch", "catch"}:
                name = method.group(2)
                method_id = node_id("method", rel, name, str(line_no))
                current = method_id
                graph.add_node(GraphNode(method_id, "method", name, rel, line_no))
                graph.add_edge(file_id, method_id, "defines")

            for call in CALL_RE.finditer(line):
                name = call.group(1)
                if name in {"if", "for", "while", "switch", "catch", "return", "new"}:
                    continue
                callee = node_id("symbol", name)
                graph.add_node(GraphNode(callee, "symbol", name))
                graph.add_edge(current, callee, "calls", line=line_no)

            if "System.out.print" in line:
                findings.append(Finding(
                    rule_id="STYLE-JAVA-SYSTEM-OUT",
                    title="生产代码中使用 System.out 输出",
                    description="System.out 不便于日志级别、结构化字段和敏感信息治理。",
                    severity=self.config.override_severity("STYLE-JAVA-SYSTEM-OUT", Severity.INFO),
                    confidence=0.93,
                    location=SourceLocation(rel, line_no, line.find("System.out") + 1, snippet=stripped[:240]),
                    category="style",
                    recommendation="改用团队统一日志框架，并避免输出敏感数据。",
                    fix_template="private static final Logger log = LoggerFactory.getLogger(CurrentClass.class);",
                ))

            if SQL_KEYWORD_RE.search(line) and "+" in line:
                findings.append(Finding(
                    rule_id="CWE-89-JAVA-SQL-INJECTION",
                    title="SQL 字符串拼接注入风险",
                    description="SQL 使用字符串拼接，若变量可控可能导致 SQL 注入。",
                    severity=Severity.HIGH,
                    confidence=0.82,
                    location=SourceLocation(rel, line_no, 1, snippet=stripped[:240]),
                    cwe="CWE-89",
                    category="security",
                    recommendation="改用 PreparedStatement 或 ORM 绑定参数。",
                    fix_template="PreparedStatement ps = conn.prepareStatement('SELECT * FROM users WHERE id = ?'); ps.setString(1, id);",
                ))

            if re.search(r"catch\s*\(\s*(Exception|Throwable)\s+\w+\s*\)\s*\{\s*\}", line):
                findings.append(Finding(
                    rule_id="JAVA-BROAD-EMPTY-CATCH",
                    title="宽泛且空的异常捕获",
                    description="空 catch 会隐藏错误并降低安全审计可观测性。",
                    severity=Severity.MEDIUM,
                    confidence=0.9,
                    location=SourceLocation(rel, line_no, 1, snippet=stripped[:240]),
                    category="maintainability",
                    recommendation="捕获具体异常，记录上下文，并在必要时重新抛出。",
                    fix_template="catch (SpecificException e) { log.warn('context', e); throw e; }",
                ))

            if re.search(r"\.get\s*\(\s*\)\s*;?", line) and "Optional" not in line:
                findings.append(Finding(
                    rule_id="CWE-476-JAVA-OPTIONAL-GET",
                    title="Optional.get 空值风险",
                    description="Optional.get 在值不存在时会抛出异常，应显式处理空分支。",
                    severity=Severity.LOW,
                    confidence=0.58,
                    location=SourceLocation(rel, line_no, line.find(".get") + 1, snippet=stripped[:240]),
                    cwe="CWE-476",
                    category="reliability",
                    recommendation="使用 orElse、orElseThrow 或 ifPresent 显式处理。",
                    fix_template="value.orElseThrow(() -> new IllegalArgumentException('missing value'))",
                ))
        return findings
