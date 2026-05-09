from __future__ import annotations

from dataclasses import dataclass
from typing import Pattern
import re

from .models import Severity


@dataclass(frozen=True)
class RegexRule:
    rule_id: str
    title: str
    description: str
    severity: Severity
    confidence: float
    category: str
    pattern: Pattern[str]
    cwe: str | None = None
    recommendation: str = ""
    fix_template: str = ""
    languages: tuple[str, ...] = ()


SECRET_PATTERNS: list[RegexRule] = [
    RegexRule(
        rule_id="CWE-798-HARDCODED-SECRET",
        cwe="CWE-798",
        title="疑似硬编码密钥或令牌",
        description="代码中出现类似 secret、token、api_key、password 的硬编码赋值。",
        severity=Severity.HIGH,
        confidence=0.72,
        category="security",
        pattern=re.compile(
            r"(?i)\b(api[_-]?key|secret|token|passwd|password|private[_-]?key)\b\s*[:=]\s*['\"][^'\"]{8,}['\"]"
        ),
        recommendation="将密钥移到安全的密钥管理系统或环境变量中，提交前轮换已泄露凭据。",
        fix_template="使用 os.environ / process.env / secret manager 读取密钥，并从仓库历史中移除明文凭据。",
    ),
    RegexRule(
        rule_id="CWE-798-AWS-ACCESS-KEY",
        cwe="CWE-798",
        title="疑似 AWS Access Key",
        description="发现形似 AWS Access Key ID 的字符串。",
        severity=Severity.HIGH,
        confidence=0.8,
        category="security",
        pattern=re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
        recommendation="立即确认密钥是否真实；如真实，吊销并轮换凭据。",
        fix_template="删除硬编码 access key，改为 IAM role、OIDC 或 secret manager 注入。",
    ),
]


GENERIC_TEXT_RULES: list[RegexRule] = [
    RegexRule(
        rule_id="STYLE-TODO-FIXME",
        title="遗留 TODO/FIXME 标记",
        description="发现 TODO、FIXME 或 HACK 标记，可能代表未收敛风险。",
        severity=Severity.INFO,
        confidence=0.85,
        category="maintainability",
        pattern=re.compile(r"\b(TODO|FIXME|HACK)\b", re.IGNORECASE),
        recommendation="将 TODO 转换为 issue，补充 owner、截止时间和验收标准。",
        fix_template="如果该标记已无意义，删除；否则创建跟踪任务并写明上下文。",
    )
]


PYTHON_REGEX_RULES: list[RegexRule] = [
    RegexRule(
        rule_id="CWE-94-PY-EVAL",
        cwe="CWE-94",
        title="动态代码执行 eval/exec",
        description="eval 或 exec 可执行动态代码，若输入可控会导致代码注入。",
        severity=Severity.HIGH,
        confidence=0.82,
        category="security",
        pattern=re.compile(r"\b(eval|exec)\s*\("),
        recommendation="改用显式解析、白名单映射或 ast.literal_eval 处理可信字面量。",
        fix_template="将 eval(user_input) 替换为白名单分发表或安全解析器。",
        languages=("python",),
    ),
    RegexRule(
        rule_id="CWE-502-PY-PICKLE",
        cwe="CWE-502",
        title="不安全 pickle 反序列化",
        description="pickle.load/loads 对不可信数据反序列化可能触发任意代码执行。",
        severity=Severity.HIGH,
        confidence=0.86,
        category="security",
        pattern=re.compile(r"\bpickle\.(load|loads)\s*\("),
        recommendation="不要反序列化不可信 pickle；改用 JSON、msgpack 或签名校验后的安全格式。",
        fix_template="将 pickle.loads(data) 改为 json.loads(data)，并为输入增加 schema 校验。",
        languages=("python",),
    ),
]


JS_REGEX_RULES: list[RegexRule] = [
    RegexRule(
        rule_id="CWE-94-JS-EVAL",
        cwe="CWE-94",
        title="JavaScript 动态代码执行",
        description="eval、Function 构造器或 setTimeout 字符串参数可能导致代码注入。",
        severity=Severity.HIGH,
        confidence=0.78,
        category="security",
        pattern=re.compile(r"\b(eval|Function)\s*\(|set(Time|Interval)out\s*\(\s*['\"]"),
        recommendation="改用静态函数调用、白名单解析或安全表达式解释器。",
        fix_template="删除 eval/Function，使用显式映射：const handlers = {name: fn}; handlers[name]?.()。",
        languages=("javascript", "typescript"),
    ),
    RegexRule(
        rule_id="CWE-79-JS-INNERHTML",
        cwe="CWE-79",
        title="可能的 DOM XSS：innerHTML / dangerouslySetInnerHTML",
        description="直接写入 HTML sink，若数据来自用户输入可能导致 XSS。",
        severity=Severity.MEDIUM,
        confidence=0.7,
        category="security",
        pattern=re.compile(r"\b(innerHTML|outerHTML|insertAdjacentHTML|dangerouslySetInnerHTML)\b"),
        recommendation="优先使用 textContent / JSX 自动转义；必须插入 HTML 时先做可信 sanitizer。",
        fix_template="将 element.innerHTML = value 改为 element.textContent = value；或集中使用 DOMPurify.sanitize。",
        languages=("javascript", "typescript"),
    ),
    RegexRule(
        rule_id="CWE-78-JS-CHILD-PROCESS-EXEC",
        cwe="CWE-78",
        title="child_process.exec 命令注入风险",
        description="exec 通过 shell 执行字符串命令，参数拼接会产生命令注入风险。",
        severity=Severity.HIGH,
        confidence=0.78,
        category="security",
        pattern=re.compile(r"\b(exec|execSync)\s*\("),
        recommendation="改用 execFile / spawn 并以参数数组传参，同时白名单命令。",
        fix_template="child_process.execFile(binary, [arg1, arg2], {shell:false})。",
        languages=("javascript", "typescript"),
    ),
]


JAVA_REGEX_RULES: list[RegexRule] = [
    RegexRule(
        rule_id="CWE-78-JAVA-RUNTIME-EXEC",
        cwe="CWE-78",
        title="Runtime.exec / ProcessBuilder 命令注入风险",
        description="动态拼接系统命令可能导致命令注入或权限边界绕过。",
        severity=Severity.HIGH,
        confidence=0.76,
        category="security",
        pattern=re.compile(r"\b(Runtime\.getRuntime\(\)\.exec|new\s+ProcessBuilder)\b"),
        recommendation="避免 shell 字符串拼接；使用参数数组、命令白名单和最小权限运行。",
        fix_template="new ProcessBuilder(List.of(binary, arg1, arg2)).start()，并校验 binary 白名单。",
        languages=("java",),
    ),
    RegexRule(
        rule_id="CWE-502-JAVA-OBJECTINPUTSTREAM",
        cwe="CWE-502",
        title="Java 不安全反序列化",
        description="ObjectInputStream.readObject 处理不可信数据会产生反序列化风险。",
        severity=Severity.HIGH,
        confidence=0.84,
        category="security",
        pattern=re.compile(r"\breadObject\s*\("),
        recommendation="避免 Java 原生反序列化不可信输入；启用 ObjectInputFilter 或改用安全数据格式。",
        fix_template="使用 JSON + schema 校验；如必须 readObject，配置 ObjectInputFilter 白名单。",
        languages=("java",),
    ),
]


ALL_REGEX_RULES = SECRET_PATTERNS + GENERIC_TEXT_RULES + PYTHON_REGEX_RULES + JS_REGEX_RULES + JAVA_REGEX_RULES
