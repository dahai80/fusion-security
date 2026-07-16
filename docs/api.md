# Fusion-Security API Reference

## Core Modules

### `fusion_security.scanner`

```python
from fusion_security.scanner import Scanner, ScanTarget, ScanResult

# Scan a directory
scanner = Scanner(use_ai=True, model="qwen3.5-9b")
target = ScanTarget("/path/to/project", max_file_size=1_000_000, max_files=10000)
result = await scanner.scan(target, severity_threshold="low")

# Quick scan
result = await scanner.scan_directory("/path", severity_threshold="high")
print(result.summary, len(result.vulnerabilities))
```

### `fusion_security.rules`

```python
from fusion_security.rules import RuleEngine, ScanRule

engine = RuleEngine()
print(f"{engine.get_rule_count()} rules loaded")

# Add custom rule
engine.add_rule(ScanRule(
    id="CUSTOM001", name="Custom Rule", description="Check dangerous patterns",
    severity="high", cwe_id="CWE-000", pattern=r"dangerous_func"
))
```

### `fusion_security.models`

```python
from fusion_security.models import Vulnerability

vuln = Vulnerability(
    id="V1", title="SQL Injection", description="User input concatenated in SQL",
    severity="critical", confidence=0.95,
    file_path="/app/db.py", line_number=42,
    code_snippet="cursor.execute('SELECT * FROM users WHERE id = ' + user_input)",
    rule_id="SQL001", cwe_id="CWE-89",
    fix_suggestion="Use parameterized queries",
)
print(vuln.to_dict())
```

### `fusion_security.ai`

```python
from fusion_security.ai import AIAnalyzer

analyzer = AIAnalyzer(model="qwen3.5-9b")

# Verify findings (reduce false positives)
verified = await analyzer.verify_findings(findings, files)

# Semantic scan (find logic flaws)
semantic = await analyzer.semantic_scan(files)

# Generate fix
fix_code = await analyzer.generate_fix(vuln)
```

### `fusion_security.fix`

```python
from fusion_security.fix import FixGenerator, FixPatch

gen = FixGenerator()
patch = gen.generate_fix(vuln)
print(patch.to_diff())  # unified diff format

# AI-enhanced fix
patch = await gen.ai_enhance_fix(patch)
```

### `fusion_security.report`

```python
from fusion_security.report import ReportGenerator

gen = ReportGenerator()
md = gen.generate_markdown(result)
html = gen.generate_html(result)
json_str = gen.generate_json(result)
saved = gen.save_report(result, "~/reports", formats=["md", "json", "html"])
```

## CLI Reference

```bash
fusion-security scan [OPTIONS] PATH
fusion-security check [PATH]
fusion-security rules
```

### `scan` — Full vulnerability scan

| Option | Description |
|--------|-------------|
| `--severity`, `-s` | Minimum severity: `critical`, `high`, `medium`, `low` |
| `--output`, `-o` | Report output directory |
| `--format`, `-f` | Report format: `md`, `json`, `html`, `all` |
| `--no-ai` | Disable AI analysis |
| `--model`, `-m` | fusion-mlx model name |
| `--verbose`, `-v` | Verbose output |

### `check` — Quick CI check

```bash
fusion-security check /path/to/project
# Output: {"vulnerabilities": 3, "critical": 1, "high": 1, "medium": 1, "low": 0, "summary": "..."}
```

### `rules` — List detection rules

```bash
fusion-security rules
```

## Vulnerability Rules (15+ rules)

| ID | Name | Severity | CWE |
|----|------|----------|-----|
| SQL001 | SQL Injection | critical | CWE-89 |
| SQL002 | SQL Injection (concat) | critical | CWE-89 |
| XSS001 | Cross-Site Scripting | high | CWE-79 |
| XSS002 | XSS (template) | high | CWE-79 |
| CMD001 | Command Injection | critical | CWE-78 |
| CMD002 | Command Injection (shell=True) | high | CWE-78 |
| PATH001 | Path Traversal | high | CWE-22 |
| SEC001 | Hardcoded Secret | high | CWE-798 |
| SEC002 | Hardcoded Token | critical | CWE-798 |
| CRYPTO001 | Weak Cryptography | medium | CWE-327 |
| AUTH001 | Missing Authentication | high | CWE-862 |
| XXE001 | XML External Entity | high | CWE-611 |
| REDIR001 | Open Redirect | medium | CWE-601 |
| LOG001 | Log Injection | medium | CWE-117 |

## Data Models

### `Vulnerability`

| Field | Type | Description |
|-------|------|-------------|
| `id` | `str` | Unique identifier |
| `title` | `str` | Vulnerability title |
| `description` | `str` | Detailed description |
| `severity` | `str` | `critical`, `high`, `medium`, `low` |
| `confidence` | `float` | 0.0 - 1.0 |
| `file_path` | `str` | Affected file path |
| `line_number` | `int` | Line number |
| `code_snippet` | `str` | Surrounding code context |
| `rule_id` | `str` | Matching rule ID |
| `cwe_id` | `str` | CWE identifier |
| `fix_suggestion` | `str` | Fix recommendation |
| `verified` | `bool` | AI-verified status |

### `ScanRule`

| Field | Type | Description |
|-------|------|-------------|
| `id` | `str` | Rule identifier |
| `name` | `str` | Human-readable name |
| `description` | `str` | Rule description |
| `severity` | `str` | Default severity |
| `cwe_id` | `str` | CWE mapping |
| `pattern` | `str` | Regex pattern |
| `language` | `str` | Target language |
| `fix_template` | `str` | Fix suggestion template |
| `category` | `str` | `injection`, `xss`, `crypto`, `config`, `auth` |