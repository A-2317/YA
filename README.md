# CodeAudit Agent

CodeAudit Agent 是一个离线运行的防御型软件工程 / 代码审计 Agent。它面向团队存量代码库的安全漏洞、异常风险和编码规范问题，完成以下流程：

1. 解析项目目录、源码文件和依赖清单。
2. 构建轻量语义图谱，包括文件、模块、类、函数、导入、调用和继承关系。
3. 基于 CWE 映射规则和团队代码规范进行静态扫描。
4. 对发现的问题做上下文聚合、置信度评分和优先级排序。
5. 输出 JSON、Markdown 审计报告、语义图和可复制的 PR 修复模板。

> 本项目用于授权代码审计、质量治理和安全加固，不包含攻击利用逻辑。

## 支持语言

- Python：AST + 规则扫描
- JavaScript / TypeScript：启发式规则扫描
- Java：启发式规则扫描
- 其他文本文件：通用 secret / TODO / 大文件等规则

## 快速开始

```bash
cd codeaudit-agent
python -m codeaudit_agent scan ./examples/vulnerable_project --out ./audit-out
```

安装成命令行工具：

```bash
pip install -e .
codeaudit-agent scan ./examples/vulnerable_project --out ./audit-out
```

查看输出：

```text
audit-out/
  report.md          # 人类可读报告
  report.json        # 机器可读报告
  graph.json         # 语义图
  graph.dot          # Graphviz DOT 图
  pr_template.md     # 修复 PR 模板
```

## 常用命令

生成默认配置：

```bash
python -m codeaudit_agent init-config > .codeaudit-agent.json
```

使用配置扫描：

```bash
python -m codeaudit_agent scan . --config .codeaudit-agent.json --out audit-out
```

只输出 JSON 到终端：

```bash
python -m codeaudit_agent scan . --format json
```

## 配置示例

```json
{
  "exclude_dirs": [".git", "node_modules", "dist", "build", "venv", ".venv"],
  "max_file_size_bytes": 1048576,
  "fail_on_severity": "high",
  "team_rules": {
    "max_line_length": 120,
    "forbid_console_log": true,
    "forbid_print": false,
    "require_python_type_hints": false
  },
  "severity_overrides": {
    "STYLE-LINE-LENGTH": "info"
  },
  "ignore_rules": []
}
```

## 规则覆盖

内置规则包含但不限于：

- CWE-78：OS Command Injection 风险，如 shell=True、child_process.exec、Runtime.exec。
- CWE-89：SQL Injection 风险，如字符串拼接 SQL、模板字符串 SQL。
- CWE-79：XSS 风险，如 innerHTML / dangerouslySetInnerHTML。
- CWE-94：Code Injection 风险，如 eval / exec / Function 构造器。
- CWE-22：Path Traversal 风险，如请求参数直接进入文件路径。
- CWE-502：不安全反序列化，如 pickle.loads、ObjectInputStream.readObject。
- CWE-798：硬编码密钥、令牌、密码。
- CWE-476：空值 / None 相关可疑用法。
- 团队规范：行长、print / console、宽泛异常、TODO/FIXME、类型提示等。

## 作为库使用

```python
from codeaudit_agent import AuditAgent, AuditConfig

agent = AuditAgent(AuditConfig.default())
result = agent.scan("/path/to/repo")
print(result.summary)
```

## CI 示例

```yaml
name: CodeAudit Agent
on: [pull_request]
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: pip install -e .
      - run: codeaudit-agent scan . --out audit-out --fail-on high
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: codeaudit-report
          path: audit-out
```

## 设计边界

静态审计不能替代人工复核、SAST 商业工具或运行时安全测试。本工具默认保守：宁可将复杂问题标为 `medium` / `low` 并给出复核建议，也不会声称自动证明漏洞可利用。
