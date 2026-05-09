from __future__ import annotations

from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any
import json

from .models import Severity


@dataclass
class TeamRules:
    max_line_length: int = 120
    forbid_console_log: bool = True
    forbid_print: bool = False
    require_python_type_hints: bool = False
    forbid_todo_in_production: bool = False
    allow_test_secrets: bool = False

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "TeamRules":
        if not data:
            return cls()
        valid = {k: v for k, v in data.items() if k in cls.__dataclass_fields__}
        return cls(**valid)


@dataclass
class AuditConfig:
    exclude_dirs: list[str] = field(default_factory=lambda: [
        ".git", ".hg", ".svn", "node_modules", "dist", "build", "target", "out",
        "venv", ".venv", "__pycache__", ".mypy_cache", ".pytest_cache", ".idea", ".vscode",
    ])
    exclude_files: list[str] = field(default_factory=lambda: [
        "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "Pipfile.lock",
    ])
    include_extensions: list[str] = field(default_factory=lambda: [
        ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".json", ".toml", ".yaml", ".yml",
        ".env", ".ini", ".cfg", ".properties", ".gradle", ".xml",
    ])
    max_file_size_bytes: int = 1_048_576
    fail_on_severity: str | None = None
    team_rules: TeamRules = field(default_factory=TeamRules)
    severity_overrides: dict[str, str] = field(default_factory=dict)
    ignore_rules: list[str] = field(default_factory=list)
    ignore_fingerprints: list[str] = field(default_factory=list)

    @classmethod
    def default(cls) -> "AuditConfig":
        return cls()

    @classmethod
    def from_file(cls, path: str | Path | None) -> "AuditConfig":
        if path is None:
            return cls.default()
        config_path = Path(path)
        if not config_path.exists():
            raise FileNotFoundError(f"Config file not found: {config_path}")
        data = json.loads(config_path.read_text(encoding="utf-8"))
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AuditConfig":
        kwargs: dict[str, Any] = {}
        for field_name in cls.__dataclass_fields__:
            if field_name in data and field_name != "team_rules":
                kwargs[field_name] = data[field_name]
        kwargs["team_rules"] = TeamRules.from_dict(data.get("team_rules"))
        return cls(**kwargs)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        return data

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)

    def fail_severity(self) -> Severity | None:
        if not self.fail_on_severity:
            return None
        return Severity.from_string(self.fail_on_severity)

    def override_severity(self, rule_id: str, default: Severity) -> Severity:
        value = self.severity_overrides.get(rule_id)
        if not value:
            return default
        return Severity.from_string(value)
