from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .config import AuditConfig
from .models import Severity
from .reports import render_markdown, write_outputs
from .scanner import AuditAgent


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="codeaudit-agent",
        description="Offline defensive static code audit agent for security and style review.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan a project directory.")
    scan.add_argument("path", help="Project directory to scan.")
    scan.add_argument("--config", help="Path to .codeaudit-agent.json.")
    scan.add_argument("--out", help="Output directory for report files.")
    scan.add_argument("--format", choices=["text", "json", "markdown"], default="text", help="Console output format.")
    scan.add_argument("--fail-on", choices=[s.value for s in Severity], help="Exit non-zero if at least this severity exists.")
    scan.add_argument("--max-findings", type=int, default=30, help="Maximum findings printed in console markdown/text.")

    sub.add_parser("init-config", help="Print a default JSON configuration.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "init-config":
        print(AuditConfig.default().to_json())
        return 0

    if args.command == "scan":
        config = AuditConfig.from_file(args.config) if args.config else AuditConfig.default()
        if args.fail_on:
            config.fail_on_severity = args.fail_on
        agent = AuditAgent(config)
        result = agent.scan(args.path)

        if args.out:
            write_outputs(result, args.out)

        if args.format == "json":
            print(result.to_json())
        elif args.format == "markdown":
            print(render_markdown(result, max_findings=args.max_findings))
        else:
            print(_render_text_summary(result, args.out))

        return 1 if result.should_fail(config.fail_severity()) else 0
    return 2


def _render_text_summary(result, out_dir: str | None) -> str:
    summary = result.summary
    lines = [
        "CodeAudit Agent scan complete",
        f"Root: {result.root}",
        f"Files scanned: {summary.files_scanned}",
        f"Lines scanned: {summary.lines_scanned}",
        f"Findings: {summary.findings_total}",
        "Severity: " + ", ".join(f"{k}={v}" for k, v in sorted(summary.by_severity.items())),
    ]
    if result.findings:
        lines.append("")
        lines.append("Top findings:")
        for finding in result.findings[:10]:
            lines.append(f"- [{finding.severity.value}] {finding.rule_id} {finding.location.display()} {finding.title}")
    if out_dir:
        lines.append("")
        lines.append(f"Reports written to: {Path(out_dir).resolve()}")
    return "\n".join(lines)


if __name__ == "__main__":
    sys.exit(main())
