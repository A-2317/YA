from __future__ import annotations

from collections import defaultdict
from pathlib import Path

from .models import Finding, ScanResult, Severity


SEVERITY_ICON = {
    "critical": "🛑",
    "high": "🔴",
    "medium": "🟠",
    "low": "🟡",
    "info": "ℹ️",
}


def render_markdown(result: ScanResult, max_findings: int | None = None) -> str:
    lines: list[str] = []
    summary = result.summary
    lines.append("# CodeAudit Agent 审计报告")
    lines.append("")
    lines.append("## 执行摘要")
    lines.append("")
    lines.append(f"- 扫描根目录：`{result.root}`")
    lines.append(f"- 扫描文件数：{summary.files_scanned}")
    lines.append(f"- 扫描代码行数：{summary.lines_scanned}")
    lines.append(f"- 发现问题总数：{summary.findings_total}")
    lines.append(f"- 依赖项数量：{summary.dependencies_total}")
    lines.append(f"- 生成时间：{result.metadata.get('generated_at', '')}")
    lines.append("")

    lines.append("## 严重级别分布")
    lines.append("")
    lines.append("| 严重级别 | 数量 |")
    lines.append("|---|---:|")
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        count = summary.by_severity.get(sev.value, 0)
        lines.append(f"| {SEVERITY_ICON[sev.value]} {sev.value} | {count} |")
    lines.append("")

    lines.append("## 语言分布")
    lines.append("")
    lines.append("| 语言 | 文件数 |")
    lines.append("|---|---:|")
    for lang, count in sorted(summary.by_language.items()):
        lines.append(f"| {lang} | {count} |")
    lines.append("")

    lines.append("## Top 风险文件")
    lines.append("")
    file_scores = _score_files(result.findings)
    if file_scores:
        lines.append("| 文件 | 风险分 | 问题数 |")
        lines.append("|---|---:|---:|")
        counts = defaultdict(int)
        for f in result.findings:
            counts[f.location.path] += 1
        for path, score in file_scores[:10]:
            lines.append(f"| `{path}` | {score} | {counts[path]} |")
    else:
        lines.append("未发现明显风险文件。")
    lines.append("")

    lines.append("## 问题详情")
    lines.append("")
    displayed = result.findings if max_findings is None else result.findings[:max_findings]
    if not displayed:
        lines.append("未发现问题。")
    for index, finding in enumerate(displayed, start=1):
        lines.extend(_render_finding(index, finding))
    if max_findings is not None and len(result.findings) > max_findings:
        lines.append(f"\n还有 {len(result.findings) - max_findings} 个问题未在 Markdown 中展开，请查看 report.json。")

    lines.append("")
    lines.append("## 修复顺序建议")
    lines.append("")
    lines.append("1. 优先处理 `critical` / `high` 且 confidence >= 0.75 的问题。")
    lines.append("2. 对涉及凭据泄露的问题，先轮换凭据，再清理代码和仓库历史。")
    lines.append("3. 对注入类问题，统一引入参数化 API、白名单校验和集中输入验证。")
    lines.append("4. 对风格类问题，尽量通过 formatter、linter 和 CI gate 自动化。")
    lines.append("5. 每个修复 PR 附带最小回归测试，避免只改表象。")
    lines.append("")
    return "\n".join(lines)


def render_pr_template(result: ScanResult) -> str:
    high_findings = [f for f in result.findings if f.severity.rank >= Severity.HIGH.rank]
    medium_findings = [f for f in result.findings if f.severity == Severity.MEDIUM]
    lines = [
        "# 修复 PR 模板",
        "",
        "## 背景",
        "",
        f"本 PR 基于 CodeAudit Agent 审计结果生成。扫描共发现 {result.summary.findings_total} 个问题，其中高危及以上 {len(high_findings)} 个，中危 {len(medium_findings)} 个。",
        "",
        "## 修复范围",
        "",
    ]
    for finding in result.findings[:12]:
        lines.append(f"- [{finding.severity.value}] `{finding.rule_id}` `{finding.location.display()}`：{finding.title}")
    if len(result.findings) > 12:
        lines.append(f"- 其余 {len(result.findings) - 12} 项见 `audit-out/report.json`。")
    lines.extend([
        "",
        "## 主要改动",
        "",
        "- [ ] 移除硬编码敏感信息，改为环境变量或密钥管理系统注入。",
        "- [ ] 将动态 SQL / 命令拼接改为参数化 API。",
        "- [ ] 增加输入校验、路径规范化和边界检查。",
        "- [ ] 替换不安全反序列化 / 动态执行逻辑。",
        "- [ ] 补充单元测试或回归测试。",
        "",
        "## 验证方式",
        "",
        "```bash",
        "python -m codeaudit_agent scan . --out audit-out",
        "pytest",
        "```",
        "",
        "## 风险与回滚",
        "",
        "- 风险：修复注入类问题可能改变边界输入的处理方式，需要关注兼容性。",
        "- 回滚：单独 revert 本 PR；如涉及凭据轮换，不应恢复旧凭据。",
        "",
        "## 审计清单",
        "",
        "- [ ] 无新增 high/critical 问题。",
        "- [ ] 关键修复有测试覆盖。",
        "- [ ] 日志不包含敏感数据。",
        "- [ ] 配置变更已同步部署文档。",
    ])
    return "\n".join(lines) + "\n"


def _render_finding(index: int, finding: Finding) -> list[str]:
    lines = [
        f"### {index}. {SEVERITY_ICON[finding.severity.value]} {finding.title}",
        "",
        f"- 规则：`{finding.rule_id}`",
        f"- 严重级别：`{finding.severity.value}`",
        f"- 置信度：`{finding.confidence:.2f}`",
        f"- 位置：`{finding.location.display()}`",
        f"- 分类：`{finding.category}`",
    ]
    if finding.cwe:
        lines.append(f"- CWE：`{finding.cwe}`")
    lines.extend([
        f"- 指纹：`{finding.fingerprint}`",
        "",
        finding.description,
        "",
    ])
    if finding.location.snippet:
        lines.extend(["```text", finding.location.snippet, "```", ""])
    if finding.recommendation:
        lines.extend(["**修复建议**：" + finding.recommendation, ""])
    if finding.fix_template:
        lines.extend(["**可执行改法参考**：", "", "```text", finding.fix_template, "```", ""])
    return lines


def _score_files(findings: list[Finding]) -> list[tuple[str, int]]:
    scores: dict[str, int] = defaultdict(int)
    weights = {"critical": 20, "high": 10, "medium": 5, "low": 2, "info": 1}
    for f in findings:
        scores[f.location.path] += weights[f.severity.value]
    return sorted(scores.items(), key=lambda item: (-item[1], item[0]))


def write_outputs(result: ScanResult, out_dir: str | Path) -> None:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.json").write_text(result.to_json(), encoding="utf-8")
    (out / "report.md").write_text(render_markdown(result), encoding="utf-8")
    import json
    (out / "graph.json").write_text(
        json.dumps(result.graph.to_dict(), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    (out / "graph.dot").write_text(result.graph.to_dot(), encoding="utf-8")
    (out / "pr_template.md").write_text(render_pr_template(result), encoding="utf-8")
