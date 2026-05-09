from pathlib import Path

from codeaudit_agent import AuditAgent, AuditConfig, Severity


def test_demo_project_detects_security_findings():
    root = Path(__file__).resolve().parents[1] / "examples" / "vulnerable_project"
    result = AuditAgent(AuditConfig.default()).scan(root)
    rule_ids = {finding.rule_id for finding in result.findings}
    assert "CWE-89-PY-SQL-INJECTION" in rule_ids
    assert "CWE-78-PY-COMMAND-INJECTION" in rule_ids
    assert "CWE-798-HARDCODED-SECRET" in rule_ids
    assert "CWE-94-PY-DYNAMIC-EXECUTION" in rule_ids
    assert "CWE-89-JS-SQL-INJECTION" in rule_ids
    assert "CWE-89-JAVA-SQL-INJECTION" in rule_ids
    assert result.summary.files_scanned >= 3
    assert result.graph.nodes
    assert result.graph.edges


def test_fail_threshold():
    root = Path(__file__).resolve().parents[1] / "examples" / "vulnerable_project"
    config = AuditConfig.default()
    config.fail_on_severity = "high"
    result = AuditAgent(config).scan(root)
    assert result.should_fail(Severity.HIGH)


def test_ignore_rule():
    root = Path(__file__).resolve().parents[1] / "examples" / "vulnerable_project"
    config = AuditConfig.default()
    config.ignore_rules = ["CWE-798-HARDCODED-SECRET"]
    result = AuditAgent(config).scan(root)
    rule_ids = {finding.rule_id for finding in result.findings}
    assert "CWE-798-HARDCODED-SECRET" not in rule_ids
