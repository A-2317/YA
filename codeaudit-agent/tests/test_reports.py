from pathlib import Path

from codeaudit_agent import AuditAgent, AuditConfig
from codeaudit_agent.reports import render_markdown, render_pr_template


def test_reports_render():
    root = Path(__file__).resolve().parents[1] / "examples" / "vulnerable_project"
    result = AuditAgent(AuditConfig.default()).scan(root)
    markdown = render_markdown(result, max_findings=5)
    pr = render_pr_template(result)
    assert "CodeAudit Agent 审计报告" in markdown
    assert "修复 PR 模板" in pr
    assert "CWE" in markdown
