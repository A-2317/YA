from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from .base import Analyzer
from ..models import Finding, GraphNode, ProjectGraph, Severity, SourceLocation, node_id
from ..utils import line_at, make_relative


USER_INPUT_NAMES = {"request", "args", "form", "query", "params", "input", "payload", "body", "data"}
SQL_METHODS = {"execute", "executemany", "raw", "filter", "where"}
DANGEROUS_OS_FUNCS = {"system", "popen", "spawn", "spawnlp", "spawnl", "spawnv", "spawnvp"}


class PythonAnalyzer(Analyzer):
    language = "python"

    def analyze(self, root: Path, path: Path, text: str, graph: ProjectGraph) -> list[Finding]:
        rel = make_relative(root, path)
        file_id = self.add_file_node(root, path, graph, self.language)
        findings: list[Finding] = []
        findings.extend(self.regex_findings(root, path, text, self.language))
        findings.extend(self.style_findings(root, path, text, self.language))

        try:
            tree = ast.parse(text, filename=rel)
        except SyntaxError as exc:
            findings.append(Finding(
                rule_id="PY-SYNTAX-ERROR",
                title="Python 语法解析失败",
                description="该文件无法被 Python AST 解析，审计覆盖可能不完整。",
                severity=Severity.LOW,
                confidence=0.98,
                location=SourceLocation(rel, exc.lineno or 1, exc.offset or 1, snippet=exc.text.strip() if exc.text else None),
                category="maintainability",
                recommendation="先修复语法错误，再重新运行审计。",
                fix_template="运行 python -m py_compile <file> 定位并修复语法问题。",
            ))
            return self.apply_global_filters(findings)

        visitor = _PythonVisitor(root=root, rel=rel, text=text, graph=graph, file_id=file_id, config=self.config)
        visitor.visit(tree)
        findings.extend(visitor.findings)
        return self.apply_global_filters(findings)


class _PythonVisitor(ast.NodeVisitor):
    def __init__(self, root: Path, rel: str, text: str, graph: ProjectGraph, file_id: str, config: Any) -> None:
        self.root = root
        self.rel = rel
        self.text = text
        self.graph = graph
        self.file_id = file_id
        self.config = config
        self.findings: list[Finding] = []
        self.scope: list[str] = []
        self.import_aliases: dict[str, str] = {}
        self.sql_like_variables: set[str] = set()

    def visit_Import(self, node: ast.Import) -> Any:
        for alias in node.names:
            name = alias.asname or alias.name.split(".")[0]
            self.import_aliases[name] = alias.name
            import_id = node_id("import", alias.name)
            self.graph.add_node(GraphNode(id=import_id, kind="import", label=alias.name, path=self.rel, line=node.lineno))
            self.graph.add_edge(self.file_id, import_id, "imports")
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> Any:
        module = node.module or ""
        for alias in node.names:
            full = f"{module}.{alias.name}" if module else alias.name
            name = alias.asname or alias.name
            self.import_aliases[name] = full
            import_id = node_id("import", full)
            self.graph.add_node(GraphNode(id=import_id, kind="import", label=full, path=self.rel, line=node.lineno))
            self.graph.add_edge(self.file_id, import_id, "imports")
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> Any:
        cls_name = ".".join(self.scope + [node.name])
        cls_id = node_id("class", self.rel, cls_name)
        self.graph.add_node(GraphNode(id=cls_id, kind="class", label=cls_name, path=self.rel, line=node.lineno))
        self.graph.add_edge(self.file_id, cls_id, "defines")
        for base in node.bases:
            base_name = self._name_of(base)
            if base_name:
                base_id = node_id("symbol", base_name)
                self.graph.add_node(GraphNode(id=base_id, kind="symbol", label=base_name))
                self.graph.add_edge(cls_id, base_id, "inherits")
        self.scope.append(node.name)
        self.generic_visit(node)
        self.scope.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        self._visit_function(node)

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        function_name = ".".join(self.scope + [node.name])
        function_id = node_id("function", self.rel, function_name)
        self.graph.add_node(GraphNode(
            id=function_id,
            kind="function",
            label=function_name,
            path=self.rel,
            line=node.lineno,
            metadata={"async": isinstance(node, ast.AsyncFunctionDef)},
        ))
        self.graph.add_edge(self.file_id, function_id, "defines")
        if self.config.team_rules.require_python_type_hints:
            self._check_type_hints(node)
        self.scope.append(node.name)
        self.generic_visit(node)
        self.scope.pop()

    def visit_Assign(self, node: ast.Assign) -> Any:
        if self._is_interpolated_string(node.value) or self._contains_binop_string_concat(node.value):
            try:
                rendered = ast.unparse(node.value).lower()
            except Exception:
                rendered = ""
            if any(keyword in rendered for keyword in ["select", "insert", "update", "delete", " where "]):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.sql_like_variables.add(target.id)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> Any:
        call_name = self._name_of(node.func)
        if call_name:
            caller = node_id("function", self.rel, ".".join(self.scope)) if self.scope else self.file_id
            callee = node_id("symbol", call_name)
            self.graph.add_node(GraphNode(id=callee, kind="symbol", label=call_name))
            self.graph.add_edge(caller, callee, "calls", line=node.lineno)

        self._check_eval_exec(node, call_name)
        self._check_command_injection(node, call_name)
        self._check_sql_injection(node, call_name)
        self._check_path_traversal(node, call_name)
        self._check_null_misuse(node, call_name)
        self._check_debug_print(node, call_name)
        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> Any:
        if node.type is None or self._name_of(node.type) in {"Exception", "BaseException"}:
            if len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
                self.add_finding(
                    "PY-BROAD-EMPTY-EXCEPT",
                    "宽泛且空的异常处理",
                    "except Exception/pass 会吞掉真实错误，使安全与稳定性问题难以发现。",
                    Severity.MEDIUM,
                    0.88,
                    node,
                    category="maintainability",
                    recommendation="捕获具体异常，记录上下文，并在无法恢复时重新抛出。",
                    fix_template="except SpecificError as exc: logger.exception('context'); raise",
                )
        self.generic_visit(node)

    def _check_type_hints(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        missing = []
        args = list(node.args.args) + list(node.args.kwonlyargs)
        for arg in args:
            if arg.arg in {"self", "cls"}:
                continue
            if arg.annotation is None:
                missing.append(arg.arg)
        if node.returns is None:
            missing.append("return")
        if missing:
            self.add_finding(
                "STYLE-PY-TYPE-HINTS",
                "缺少 Python 类型标注",
                f"函数 {node.name} 缺少类型标注：{', '.join(missing)}。",
                Severity.INFO,
                0.9,
                node,
                category="style",
                recommendation="为公共函数参数和返回值补充类型标注，降低新人理解成本。",
                fix_template="def func(arg: Type) -> ReturnType: ...",
            )

    def _check_eval_exec(self, node: ast.Call, call_name: str | None) -> None:
        if call_name in {"eval", "exec"}:
            severity = Severity.HIGH if self._args_contain_user_input(node.args) else Severity.MEDIUM
            self.add_finding(
                "CWE-94-PY-DYNAMIC-EXECUTION",
                "Python 动态代码执行风险",
                "eval/exec 会执行字符串内容；若字符串来自用户输入，会形成代码注入风险。",
                severity,
                0.9,
                node,
                cwe="CWE-94",
                recommendation="使用白名单映射、ast.literal_eval 或专用解析器替代动态执行。",
                fix_template="handlers = {'safe_name': safe_func}; handlers.get(name, default)()",
            )

    def _check_command_injection(self, node: ast.Call, call_name: str | None) -> None:
        if not call_name:
            return
        dangerous = call_name in {"os.system", "os.popen"} or call_name.split(".")[-1] in DANGEROUS_OS_FUNCS
        subprocess_shell = call_name.startswith("subprocess.") and any(
            kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True for kw in node.keywords
        )
        if dangerous or subprocess_shell:
            high_risk = self._args_contain_user_input(node.args) or subprocess_shell
            self.add_finding(
                "CWE-78-PY-COMMAND-INJECTION",
                "系统命令执行注入风险",
                "系统命令通过字符串或 shell 执行，参数拼接时可能被注入。",
                Severity.HIGH if high_risk else Severity.MEDIUM,
                0.84,
                node,
                cwe="CWE-78",
                recommendation="使用 subprocess.run([...], shell=False)，参数以数组传入并做白名单校验。",
                fix_template="subprocess.run([binary, arg1, arg2], check=True, shell=False)",
            )

    def _check_sql_injection(self, node: ast.Call, call_name: str | None) -> None:
        if not call_name or call_name.split(".")[-1] not in SQL_METHODS:
            return
        if not node.args:
            return
        query = node.args[0]
        risky_query = (
            self._is_interpolated_string(query)
            or self._contains_binop_string_concat(query)
            or (isinstance(query, ast.Name) and query.id in self.sql_like_variables)
        )
        if risky_query:
            self.add_finding(
                "CWE-89-PY-SQL-INJECTION",
                "SQL 字符串拼接注入风险",
                "SQL 查询使用 f-string、format 或字符串拼接，若参数可控可能导致 SQL 注入。",
                Severity.HIGH,
                0.86,
                node,
                cwe="CWE-89",
                recommendation="改用参数化查询，不要把用户输入拼入 SQL 字符串。",
                fix_template="cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
            )

    def _check_path_traversal(self, node: ast.Call, call_name: str | None) -> None:
        if call_name not in {"open", "pathlib.Path.open", "Path.open"}:
            return
        if node.args and (self._args_contain_user_input(node.args) or self._contains_join_with_user_input(node.args[0])):
            self.add_finding(
                "CWE-22-PY-PATH-TRAVERSAL",
                "文件路径遍历风险",
                "文件路径可能包含用户可控输入，未看到规范化和根目录边界校验。",
                Severity.MEDIUM,
                0.72,
                node,
                cwe="CWE-22",
                recommendation="使用固定根目录、resolve 后校验路径仍位于根目录内，并限制文件名白名单。",
                fix_template="target = (base / name).resolve(); assert target.is_relative_to(base.resolve())",
            )

    def _check_null_misuse(self, node: ast.Call, call_name: str | None) -> None:
        if call_name and call_name.endswith(".get") and len(node.args) == 1 and not node.keywords:
            self.add_finding(
                "CWE-476-PY-DICT-GET-NONE",
                "dict.get 返回 None 后可能被误用",
                "dict.get 未提供默认值，调用方若直接链式使用可能出现 NoneType 异常。",
                Severity.LOW,
                0.55,
                node,
                cwe="CWE-476",
                category="reliability",
                recommendation="为 get 提供默认值，或显式处理 None 分支。",
                fix_template="value = data.get('key', default_value)",
            )

    def _check_debug_print(self, node: ast.Call, call_name: str | None) -> None:
        if call_name == "print" and self.config.team_rules.forbid_print:
            self.add_finding(
                "STYLE-PY-PRINT",
                "生产代码中使用 print",
                "团队规范禁止直接 print，建议使用结构化日志。",
                Severity.INFO,
                0.95,
                node,
                category="style",
                recommendation="改用 logger.debug/info/warning，并避免输出敏感信息。",
                fix_template="logger.info('message', extra={'key': value})",
            )

    def _args_contain_user_input(self, args: list[ast.AST]) -> bool:
        return any(self._contains_user_input(arg) for arg in args)

    def _contains_user_input(self, node: ast.AST) -> bool:
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and child.id.lower() in USER_INPUT_NAMES:
                return True
            if isinstance(child, ast.Attribute) and child.attr.lower() in USER_INPUT_NAMES:
                return True
            if isinstance(child, ast.Call) and self._name_of(child.func) in {"input", "request.get_json", "request.form.get", "request.args.get"}:
                return True
        return False

    def _contains_join_with_user_input(self, node: ast.AST) -> bool:
        text = ast.unparse(node) if hasattr(ast, "unparse") else ""
        return "join" in text and self._contains_user_input(node)

    def _is_interpolated_string(self, node: ast.AST) -> bool:
        if isinstance(node, ast.JoinedStr):
            return True
        if isinstance(node, ast.Call) and self._name_of(node.func) and self._name_of(node.func).endswith(".format"):
            return True
        return False

    def _contains_binop_string_concat(self, node: ast.AST) -> bool:
        for child in ast.walk(node):
            if isinstance(child, ast.BinOp) and isinstance(child.op, (ast.Add, ast.Mod)):
                return True
        return False

    def _name_of(self, node: ast.AST | None) -> str | None:
        if node is None:
            return None
        if isinstance(node, ast.Name):
            return self.import_aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            left = self._name_of(node.value)
            return f"{left}.{node.attr}" if left else node.attr
        if isinstance(node, ast.Call):
            return self._name_of(node.func)
        if isinstance(node, ast.Subscript):
            return self._name_of(node.value)
        return None

    def add_finding(
        self,
        rule_id: str,
        title: str,
        description: str,
        severity: Severity,
        confidence: float,
        node: ast.AST,
        cwe: str | None = None,
        category: str = "security",
        recommendation: str = "",
        fix_template: str = "",
    ) -> None:
        sev = self.config.override_severity(rule_id, severity)
        line_no = getattr(node, "lineno", 1)
        col = getattr(node, "col_offset", 0) + 1
        self.findings.append(Finding(
            rule_id=rule_id,
            title=title,
            description=description,
            severity=sev,
            confidence=confidence,
            location=SourceLocation(self.rel, line_no, col, snippet=line_at(self.text, line_no)[:240]),
            cwe=cwe,
            category=category,
            recommendation=recommendation,
            fix_template=fix_template,
        ))
