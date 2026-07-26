"""报告生成器 — 生成漏洞审计报告。"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from jinja2 import Environment, BaseLoader

from ..engine.scanner import ScanResult
from ..models.vulnerability import Vulnerability

logger = logging.getLogger(__name__)

HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>安全审计报告</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;max-width:960px;margin:40px auto;padding:0 24px;color:#1a1a2e;background:#fafafa}
h1{color:#1a1a2e;border-bottom:2px solid #e0e0e0;padding-bottom:12px;margin-bottom:20px}
.meta{display:flex;flex-wrap:wrap;gap:16px;margin-bottom:20px;font-size:14px;color:#555}
.meta span{background:#fff;padding:6px 12px;border-radius:6px;border:1px solid #e0e0e0}
.summary{background:#fff;padding:16px;border-radius:8px;border:1px solid #e0e0e0;margin-bottom:24px;line-height:1.6}
.vuln{background:#fff;padding:16px 20px;border-radius:8px;border:1px solid #e0e0e0;margin-bottom:16px}
.vuln h3{margin-bottom:8px;font-size:16px}
.critical{color:#d32f2f}
.high{color:#f57c00}
.medium{color:#fbc02d}
.low{color:#388e3c}
.vuln-meta{font-size:13px;color:#555;margin-bottom:8px}
.vuln-meta span{margin-right:16px}
pre{background:#f5f5f5;padding:12px;border-radius:6px;overflow-x:auto;font-size:13px;line-height:1.5;border:1px solid #e8e8e8}
.fix{background:#e8f5e9;padding:8px 12px;border-radius:6px;font-size:13px;margin-top:8px}
footer{text-align:center;color:#999;font-size:12px;margin-top:40px;padding:20px 0;border-top:1px solid #e0e0e0}
</style>
</head>
<body>
<h1>🔒 代码安全审计报告</h1>
<div class="meta">
    <span><strong>扫描目标:</strong> {{ target_path }}</span>
    <span><strong>扫描时间:</strong> {{ scan_time }}</span>
    <span><strong>文件数:</strong> {{ files_scanned }}</span>
    <span><strong>漏洞:</strong> {{ vuln_count }}</span>
    <span><strong>耗时:</strong> {{ duration_ms }}ms</span>
</div>
<div class="summary">{{ summary }}</div>

{% for vuln in vulnerabilities %}
<div class="vuln">
    <h3 class="{{ vuln.severity }}">[{{ vuln.severity.upper() }}] {{ vuln.title }}</h3>
    <div class="vuln-meta">
        <span><strong>文件:</strong> {{ vuln.file_path }}:{{ vuln.line_number }}</span>
        <span><strong>CWE:</strong> {{ vuln.cwe_id }}</span>
        <span><strong>置信度:</strong> {{ vuln.confidence }}</span>
    </div>
    <p>{{ vuln.description }}</p>
    {% if vuln.code_snippet %}
    <pre>{{ vuln.code_snippet[:500] }}</pre>
    {% endif %}
    {% if vuln.fix_suggestion %}
    <div class="fix">💡 {{ vuln.fix_suggestion }}</div>
    {% endif %}
</div>
{% endfor %}

<footer>
    <p>由 Fusion-Security v0.1.0 于 {{ scan_time }} 自动生成 | 100% 本地离线，代码不出境</p>
    <p>⚠️ 修复建议由 AI 生成，请人工审核后再应用</p>
</footer>
</body>
</html>
"""

_jinja_env = Environment(loader=BaseLoader(), autoescape=True)
_html_template = _jinja_env.from_string(HTML_TEMPLATE)


class ReportGenerator:

    def generate_markdown(self, result: ScanResult) -> str:
        lines = []
        lines.append(f"# 代码安全审计报告")
        lines.append("")
        lines.append(f"**扫描目标**: {result.target.path}")
        lines.append(f"**扫描时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"**扫描文件**: {result.files_scanned} 个")
        lines.append(f"**扫描耗时**: {result.duration_ms:.0f}ms")
        lines.append("")
        lines.append(f"## 扫描摘要")
        lines.append("")
        lines.append(f"{result.summary}")
        lines.append("")

        if result.vulnerabilities:
            lines.append(f"## 漏洞详情")
            lines.append("")
            for i, vuln in enumerate(result.vulnerabilities, 1):
                sev_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}
                icon = sev_icon.get(vuln.severity, "⚪")
                lines.append(f"### {i}. {icon} [{vuln.severity.upper()}] {vuln.title}")
                lines.append("")
                lines.append(f"- **文件**: {vuln.file_path}:{vuln.line_number}")
                lines.append(f"- **CWE**: {vuln.cwe_id}")
                lines.append(f"- **置信度**: {vuln.confidence}")
                lines.append(f"- **描述**: {vuln.description}")
                if vuln.fix_suggestion:
                    lines.append(f"- **修复建议**: {vuln.fix_suggestion}")
                lines.append("")
                lines.append("```")
                lines.append(vuln.code_snippet[:500])
                lines.append("```")
                lines.append("")

        lines.append("---")
        lines.append(f"*由 Fusion-Security v0.1.0 于 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} 自动生成*")
        lines.append("*100% 本地离线，代码不出境*")
        lines.append("*⚠️ 修复建议由 AI 生成，请人工审核后再应用*")
        return "\n".join(lines)

    def generate_json(self, result: ScanResult) -> str:
        return json.dumps(result.to_dict(), ensure_ascii=False, indent=2)

    def generate_html(self, result: ScanResult) -> str:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        vuln_data = []
        for v in result.vulnerabilities:
            vuln_data.append({
                "title": v.title,
                "severity": v.severity,
                "file_path": v.file_path,
                "line_number": v.line_number,
                "cwe_id": v.cwe_id,
                "confidence": v.confidence,
                "description": v.description,
                "code_snippet": v.code_snippet or "",
                "fix_suggestion": v.fix_suggestion or "",
            })
        return _html_template.render(
            target_path=result.target.path,
            scan_time=now,
            files_scanned=result.files_scanned,
            vuln_count=len(result.vulnerabilities),
            duration_ms=f"{result.duration_ms:.0f}",
            summary=result.summary,
            vulnerabilities=vuln_data,
        )

    def save_report(self, result: ScanResult, output_dir: str, formats: List[str] = None) -> Dict[str, str]:
        if formats is None:
            formats = ["md", "json"]

        out_dir = Path(output_dir).expanduser()
        out_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        saved = {}

        if "md" in formats:
            path = out_dir / f"security_report_{timestamp}.md"
            path.write_text(self.generate_markdown(result), encoding="utf-8")
            saved["markdown"] = str(path)

        if "json" in formats:
            path = out_dir / f"security_report_{timestamp}.json"
            path.write_text(self.generate_json(result), encoding="utf-8")
            saved["json"] = str(path)

        if "html" in formats:
            path = out_dir / f"security_report_{timestamp}.html"
            path.write_text(self.generate_html(result), encoding="utf-8")
            saved["html"] = str(path)

        return saved
