from __future__ import annotations

from pathlib import Path
import re

from .base import Analyzer
from ..models import Finding, GraphNode, ProjectGraph, Severity, SourceLocation, node_id
from ..utils import iter_with_line_numbers, line_at, make_relative


SQL_KEYWORD_RE = re.compile(r"(?i)\b(select|insert|update|delete)\b.*\b(from|into|set|where)\b")
FUNC_RE = re.compile(r"\b(function\s+([A-Za-z_$][\w$]*)|(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\(?[^=]*?\)?\s*=>)")
IMPORT_RE = re.compile(r"\b(?:import\s+.*?\s+from\s+['\"]([^'\"]+)['\"]|require\(['\"]([^'\"]+)['\"]\))")
CALL_RE = re.compile(r"\b([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)?)\s*\(")


class JavaScriptAnalyzer(Analyzer):
    language = "javascript"

    def analyze(self, root: Path, path: Path, text: str, graph: ProjectGraph) -> list[Finding]:
        language = "typescript" if path.suffix.lower() in {".ts", ".tsx"} else "javascript"
        rel = make_relative(root, path)
        file_id = self.add_file_node(root, path, graph, language)
        findings: list[Finding] = []
        findings.extend(self.regex_findings(root, path, text, language))
        findings.extend(self.style_findings(root, path, text, language))
        findings.extend(self._semantic_scan(rel, file_id, text, graph, language))
        return self.apply_global_filters(findings)

    def _semantic_scan(self, rel: str, file_id: str, text: str, graph: ProjectGraph, language: str) -> list[Finding]:
        findings: list[Finding] = []
        current_function = file_id
        for line_no, line in iter_with_line_numbers(text):
            import_match = IMPORT_RE.search(line)
            if import_match:
                name = import_match.group(1) or import_match.group(2) or "unknown"
                import_id = node_id("import", name)
                graph.add_node(GraphNode(import_id, "import", name, rel, line_no))
                graph.add_edge(file_id, import_id, "imports")

            func_match = FUNC_RE.search(line)
            if func_match:
                name = func_match.group(2) or func_match.group(3) or "anonymous"
                current_function = node_id("function", rel, name, str(line_no))
                graph.add_node(GraphNode(current_function, "function", name, rel, line_no, {"language": language}))
                graph.add_edge(file_id, current_function, "defines")

            for call_match in CALL_RE.finditer(line):
                name = call_match.group(1)
                if name in {"if", "for", "while", "switch", "catch", "function"}:
                    continue
                callee = node_id("symbol", name)
                graph.add_node(GraphNode(callee, "symbol", name))
                graph.add_edge(current_function, callee, "calls", line=line_no)

            stripped = line.strip()
            if self.config.team_rules.forbid_console_log and re.search(r"\bconsole\.(log|debug|info)\s*\(", line):
                findings.append(Finding(
                    rule_id="STYLE-JS-CONSOLE",
                    title="生产代码中使用 console 输出",
                    description="团队规范禁止 console.log/debug/info 进入生产代码。",
                    severity=self.config.override_severity("STYLE-JS-CONSOLE", Severity.INFO),
                    confidence=0.95,
                    location=SourceLocation(rel, line_no, line.find("console") + 1, snippet=stripped[:240]),
                    category="style",
                    recommendation="改用统一 logger，并对敏感字段做脱敏。",
                    fix_template="logger.info({ event: 'name', ...safeMetadata })",
                ))

            if re.search(r"\b(var)\s+", line):
                findings.append(Finding(
                    rule_id="STYLE-JS-VAR",
                    title="使用 var 声明变量",
                    description="var 具有函数作用域和提升行为，易引入维护风险。",
                    severity=self.config.override_severity("STYLE-JS-VAR", Severity.INFO),
                    confidence=0.9,
                    location=SourceLocation(rel, line_no, line.find("var") + 1, snippet=stripped[:240]),
                    category="style",
                    recommendation="优先使用 const；需要重新赋值时使用 let。",
                    fix_template="const value = ...; 或 let value = ...;",
                ))

            if "==" in line and "===" not in line and "!=" not in line:
                findings.append(Finding(
                    rule_id="STYLE-JS-LOOSE-EQUALITY",
                    title="使用宽松相等比较",
                    description="== 会触发隐式类型转换，可能导致边界条件错误。",
                    severity=self.config.override_severity("STYLE-JS-LOOSE-EQUALITY", Severity.LOW),
                    confidence=0.8,
                    location=SourceLocation(rel, line_no, line.find("==") + 1, snippet=stripped[:240]),
                    category="style",
                    recommendation="使用 === 或显式类型转换后再比较。",
                    fix_template="if (String(a) === String(b)) { ... }",
                ))

            if SQL_KEYWORD_RE.search(line) and any(token in line for token in ["+", "${", "`"]):
                findings.append(Finding(
                    rule_id="CWE-89-JS-SQL-INJECTION",
                    title="SQL 字符串拼接注入风险",
                    description="SQL 使用字符串拼接或模板字符串，若变量可控可能导致 SQL 注入。",
                    severity=Severity.HIGH,
                    confidence=0.82,
                    location=SourceLocation(rel, line_no, 1, snippet=stripped[:240]),
                    cwe="CWE-89",
                    category="security",
                    recommendation="改用参数化查询或 ORM 的绑定参数 API。",
                    fix_template="db.query('SELECT * FROM users WHERE id = ?', [userId])",
                ))

            if re.search(r"\b(req|request)\.(query|body|params)\b", line) and re.search(r"\b(fs\.readFile|fs\.createReadStream|path\.join)\b", line):
                findings.append(Finding(
                    rule_id="CWE-22-JS-PATH-TRAVERSAL",
                    title="文件路径遍历风险",
                    description="用户可控参数直接参与文件路径计算，可能访问预期目录外的文件。",
                    severity=Severity.MEDIUM,
                    confidence=0.68,
                    location=SourceLocation(rel, line_no, 1, snippet=stripped[:240]),
                    cwe="CWE-22",
                    category="security",
                    recommendation="使用固定根目录、path.resolve 后做前缀校验，并限制文件名白名单。",
                    fix_template="const target = path.resolve(base, name); if (!target.startsWith(base)) throw new Error('bad path');",
                ))
        return findings
