"""报告生成器 — 生成漏洞审计报告。"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..scanner.scanner import ScanResult
from ..rules.engine import Vulnerability

logger = logging.getLogger(__name__)


class ReportGenerator:
    """审计报告生成器 — 生成 Markdown/JSON/HTML 格式报告。

    对标 Claude Security 的审计日志能力。
    """

    def generate_markdown(self, result: ScanResult) -> str:
        """生成 Markdown 报告。"""
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
                lines.append(f"- **置信度**: {vuln.confidence:.0%}")
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
        return "\n".join(lines)

    def generate_json(self, result: ScanResult) -> str:
        """生成 JSON 格式报告。"""
        return json.dumps(result.to_dict(), ensure_ascii=False, indent=2)

    def generate_html(self, result: ScanResult) -> str:
        """生成 HTML 格式报告。"""
        md = self.generate_markdown(result)
        html = "<!DOCTYPE html><html><head><meta charset='utf-8'><title>安全审计报告</title>"
        html += "<style>body{font-family:-apple-system,sans-serif;max-width:900px;margin:40px auto;padding:0 20px}"
        html += "h1{color:#1a1a2e;border-bottom:2px solid #e0e0e0}"
        html += ".critical{color:#d32f2f}.high{color:#f57c00}.medium{color:#fbc02d}.low{color:#388e3c}"
        html += "pre{background:#f5f5f5;padding:10px;border-radius:4px;overflow-x:auto}"
        html += "</style></head><body>"
        html += f"<h1>🔒 代码安全审计报告</h1>"
        html += f"<p><strong>扫描目标:</strong> {result.target.path}</p>"
        html += f"<p><strong>扫描时间:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>"
        html += f"<p><strong>文件数:</strong> {result.files_scanned} | "
        html += f"<strong>漏洞:</strong> {len(result.vulnerabilities)} | "
        html += f"<strong>耗时:</strong> {result.duration_ms:.0f}ms</p>"
        html += f"<p>{result.summary}</p>"

        for vuln in result.vulnerabilities:
            sev_class = vuln.severity
            html += f"<div class='vuln'><h3 class='{sev_class}'>[{vuln.severity.upper()}] {vuln.title}</h3>"
            html += f"<p><strong>文件:</strong> {vuln.file_path}:{vuln.line_number}</p>"
            html += f"<p><strong>CWE:</strong> {vuln.cwe_id} | <strong>置信度:</strong> {vuln.confidence:.0%}</p>"
            html += f"<p>{vuln.description}</p>"
            html += f"<pre>{vuln.code_snippet[:500]}</pre></div>"

        html += f"<p><em>由 Fusion-Security 自动生成 | 100% 本地离线</em></p></body></html>"
        return html

    def save_report(self, result: ScanResult, output_dir: str, formats: List[str] = None) -> Dict[str, str]:
        """保存报告到文件。"""
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