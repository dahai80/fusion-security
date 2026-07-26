"""SCA (Software Composition Analysis) — dependency vulnerability scanner."""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx

from ...models.vulnerability import Vulnerability

logger = logging.getLogger(__name__)


@dataclass
class Dependency:
    name: str
    version: str
    ecosystem: str
    source_file: str = ""
    is_dev: bool = False


@dataclass
class KnownVuln:
    cve_id: str
    package: str
    affected_versions: str
    severity: str
    description: str
    fixed_version: str = ""


KNOWN_VULNS: List[KnownVuln] = [
    KnownVuln("CVE-2023-36664", "pypdf", "<3.16.0", "critical", "pypdf 注入漏洞", "3.16.0"),
    KnownVuln("CVE-2023-40217", "cryptography", "<41.0.6", "high", "cryptography 中间人攻击", "41.0.6"),
    KnownVuln("CVE-2023-43804", "urllib3", "<2.0.7", "high", "urllib3 Cookie 泄露", "2.0.7"),
    KnownVuln("CVE-2023-44287", "pillow", "<10.0.1", "high", "Pillow 图像解析 DoS", "10.0.1"),
    KnownVuln("CVE-2023-23934", "werkzeug", "<2.2.3", "medium", "Werkzeug Cookie 解析问题", "2.2.3"),
    KnownVuln("CVE-2023-25577", "flask", "<2.2.3", "medium", "Flask cookie 解析 DoS", "2.2.3"),
    KnownVuln("CVE-2022-25883", "semver", "<7.5.2", "high", "semver ReDoS", "7.5.2"),
    KnownVuln("CVE-2023-32002", "node:vm", "<20.5.0", "high", "Node.js vm 模块沙箱逃逸", "20.5.0"),
    KnownVuln("CVE-2023-34453", "snappy", "<0.2.0", "medium", "snappy 缓冲区溢出", "0.2.0"),
    KnownVuln("CVE-2022-32149", "golang.org/x/text", "<0.3.8", "high", "Go x/text DoS", "0.3.8"),
]

DEPRECATED_PACKAGES: List[Dict[str, str]] = [
    {"name": "pycrypto", "reason": "已停止维护，存在已知漏洞，使用pycryptodome替代", "alternative": "pycryptodome"},
    {"name": "paramiko", "reason": "旧版本存在安全漏洞", "alternative": "paramiko>=3.0"},
    {"name": "request", "reason": "已废弃，使用requests替代", "alternative": "requests"},
    {"name": "pickle", "reason": "不应用于不可信数据反序列化", "alternative": "json/msgpack"},
    {"name": "md5", "reason": "MD5已不安全，使用hashlib.sha256替代", "alternative": "hashlib"},
]

LICENSE_RISKS: Dict[str, str] = {
    "GPL-2.0": "copyleft — 商用需开源衍生作品",
    "GPL-3.0": "copyleft — 商用需开源衍生作品",
    "AGPL-3.0": "强copyleft — 网络服务也需开源",
    "SSPL-1.0": "非OSI认证 — 可能限制云服务使用",
    "BSL-1.1": "商业源码许可 — 有使用限制",
    " Commons-Clause": "非开源 — 禁止商业销售",
}

STALE_VERSION_YEARS = 3

OSV_API_URL = "https://osv.dev/v1/query"
OSV_BATCH_URL = "https://osv.dev/v1/querybatch"

ECOSYSTEM_MAP = {
    "pypi": "PyPI",
    "npm": "npm",
    "gomod": "Go",
    "cargo": "crates.io",
    "rubygems": "RubyGems",
}

SEVERITY_ORDER = {"LOW": "low", "MODERATE": "medium", "MEDIUM": "medium", "HIGH": "high", "CRITICAL": "critical"}


class OSVClient:
    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout
        self._client: Optional[httpx.Client] = None

    def _get_client(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(timeout=self.timeout)
        return self._client

    def query_batch(self, deps: List[Dependency]) -> Dict[str, List[Dict]]:
        results: Dict[str, List[Dict]] = {}
        if not deps:
            return results
        queries = []
        for dep in deps:
            osv_eco = ECOSYSTEM_MAP.get(dep.ecosystem)
            if not osv_eco:
                continue
            queries.append({
                "version": dep.version,
                "package": {"name": dep.name, "ecosystem": osv_eco},
            })
        if not queries:
            return results
        batch_payload = {"queries": queries}
        try:
            client = self._get_client()
            resp = client.post(OSV_BATCH_URL, json=batch_payload)
            if resp.status_code != 200:
                logger.warning(f"[OSV] batch query failed: HTTP {resp.status_code}")
                return results
            data = resp.json()
            for i, dep in enumerate(deps):
                if i >= len(data.get("results", [])):
                    break
                vulns = data["results"][i].get("vulns", [])
                if vulns:
                    key = f"{dep.name}@{dep.version}"
                    results[key] = vulns
        except (httpx.HTTPError, json.JSONDecodeError, KeyError) as e:
            logger.warning(f"[OSV] batch query error: {e}")
        return results

    def close(self):
        if self._client is not None:
            self._client.close()
            self._client = None


class SCAScanner:
    def __init__(self, use_osv: bool = True):
        self.use_osv = use_osv
        self.osv_client = OSVClient() if use_osv else None
        self.parsers = {
            "requirements*.txt": self._parse_requirements,
            "Pipfile": self._parse_pipfile,
            "pyproject.toml": self._parse_pyproject,
            "package.json": self._parse_package_json,
            "go.mod": self._parse_gomod,
            "Cargo.toml": self._parse_cargo,
            "Gemfile": self._parse_gemfile,
        }

    def scan(self, project_path: str) -> List[Vulnerability]:
        deps = self.collect_dependencies(project_path)
        logger.info(f"[SCA] 收集到 {len(deps)} 个依赖")
        vulns = self.check_vulnerabilities(deps)
        vulns.extend(self.check_deprecated(deps))
        vulns.extend(self.check_license(project_path))
        vulns.extend(self.check_stale_versions(deps))
        if self.osv_client:
            self.osv_client.close()
        return vulns

    def collect_dependencies(self, project_path: str) -> List[Dependency]:
        deps: List[Dependency] = []
        root = Path(project_path)
        for pattern, parser in self.parsers.items():
            for dep_file in root.rglob(pattern):
                if any(p in dep_file.parts for p in {'.git', 'node_modules', '.venv', '__pycache__'}):
                    continue
                try:
                    content = dep_file.read_text(encoding="utf-8", errors="ignore")
                    file_deps = parser(str(dep_file), content)
                    deps.extend(file_deps)
                except Exception as e:
                    logger.debug(f"[SCA] 解析 {dep_file} 失败: {e}")
        return deps

    def check_vulnerabilities(self, deps: List[Dependency]) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []
        osv_results: Dict[str, List[Dict]] = {}
        if self.use_osv and self.osv_client:
            osv_results = self.osv_client.query_batch(deps)
            if osv_results:
                logger.info(f"[OSV] 查询到 {sum(len(v) for v in osv_results.values())} 条漏洞")
        for dep in deps:
            key = f"{dep.name}@{dep.version}"
            if key in osv_results:
                for osv_vuln in osv_results[key]:
                    v = self._osv_to_vulnerability(dep, osv_vuln)
                    if v:
                        vulns.append(v)
            else:
                for kv in KNOWN_VULNS:
                    if self._is_affected(dep, kv):
                        v = Vulnerability(
                            id=f"SCA-{kv.cve_id}-{dep.name}",
                            title=f"依赖漏洞: {dep.name} {dep.version} ({kv.cve_id})",
                            description=f"{dep.name} {dep.version} 存在 {kv.cve_id}: {kv.description}",
                            severity=kv.severity,
                            confidence=85,
                            file_path=dep.source_file,
                            line_number=0,
                            code_snippet=f"{dep.name}=={dep.version}",
                            rule_id="FUS-SCA-001",
                            cwe_id="CWE-1035",
                            fix_suggestion=f"升级 {dep.name} 到 {kv.fixed_version} 或更高版本",
                        )
                        vulns.append(v)
        logger.info(f"[SCA] 发现 {len(vulns)} 个依赖漏洞")
        return vulns

    def _osv_to_vulnerability(self, dep: Dependency, osv_vuln: Dict) -> Optional[Vulnerability]:
        vuln_id = osv_vuln.get("id", "OSV-UNKNOWN")
        summary = osv_vuln.get("summary", "")
        details = osv_vuln.get("details", "")
        severity_raw = ""
        severities = osv_vuln.get("database_specific", {}).get("severity", "")
        if not severities:
            sv = osv_vuln.get("severity", [])
            if sv:
                severity_raw = sv[0].get("score", "")
        severity = self._map_severity(severity_raw or severities)
        cwe_id = "CWE-1035"
        aliases = osv_vuln.get("aliases", [])
        cve_id = next((a for a in aliases if a.startswith("CVE-")), vuln_id)
        fixed_version = ""
        affected = osv_vuln.get("affected", [])
        for aff in affected:
            pkg = aff.get("package", {})
            if pkg.get("name", "").lower() == dep.name.lower():
                for r in aff.get("ranges", []):
                    for event in r.get("events", []):
                        if "fixed" in event:
                            fixed_version = event["fixed"]
                            break
                break
        description = summary or details or f"{dep.name} {dep.version} 存在漏洞 {cve_id}"
        return Vulnerability(
            id=f"SCA-{cve_id}-{dep.name}",
            title=f"依赖漏洞: {dep.name} {dep.version} ({cve_id})",
            description=description,
            severity=severity,
            confidence=90,
            file_path=dep.source_file,
            line_number=0,
            code_snippet=f"{dep.name}=={dep.version}",
            rule_id="FUS-SCA-001",
            cwe_id=cwe_id,
            fix_suggestion=f"升级 {dep.name} 到 {fixed_version} 或更高版本" if fixed_version else "查看 OSV 漏洞详情获取修复建议",
        )

    def _map_severity(self, raw: str) -> str:
        raw_upper = raw.upper().strip()
        if raw_upper in SEVERITY_ORDER:
            return SEVERITY_ORDER[raw_upper]
        if raw_upper in ("CRITICAL", "CRIT"):
            return "critical"
        if raw_upper in ("HIGH", "IMPORTANT"):
            return "high"
        if raw_upper in ("MODERATE", "MEDIUM"):
            return "medium"
        return "low"

    def _is_affected(self, dep: Dependency, kv: KnownVuln) -> bool:
        if dep.name.lower() != kv.package.lower():
            return False
        try:
            dep_ver = self._parse_version(dep.version)
            affected = kv.affected_versions
            if affected.startswith("<="):
                fixed = self._parse_version(affected[2:])
                return dep_ver <= fixed
            elif affected.startswith("<"):
                fixed = self._parse_version(affected[1:])
                return dep_ver < fixed
            elif affected.startswith(">="):
                fixed = self._parse_version(affected[2:])
                return dep_ver >= fixed
        except (ValueError, IndexError):
            return False
        return False

    def _parse_version(self, version: str) -> tuple:
        cleaned = re.sub(r'[^0-9.]', '', version)
        parts = cleaned.split(".")
        parsed = tuple(int(p) for p in parts if p.isdigit())
        if not parsed:
            raise ValueError(f"无法解析版本号: {version}")
        return parsed

    def check_deprecated(self, deps: List[Dependency]) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []
        for dep in deps:
            for pkg in DEPRECATED_PACKAGES:
                if dep.name.lower() == pkg["name"].lower():
                    vulns.append(Vulnerability(
                        id=f"SCA-DEPRECATED-{dep.name}",
                        title=f"已废弃组件: {dep.name}",
                        description=f"{dep.name} {dep.version} 已废弃: {pkg['reason']}",
                        severity="medium",
                        confidence=90,
                        file_path=dep.source_file,
                        line_number=0,
                        code_snippet=f"{dep.name}=={dep.version}",
                        rule_id="FUS-SCA-002",
                        cwe_id="CWE-1104",
                        fix_suggestion=f"替换为 {pkg['alternative']}",
                    ))
                    break
        logger.info(f"[SCA-002] 发现 {len(vulns)} 个已废弃组件")
        return vulns

    def check_license(self, project_path: str) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []
        root = Path(project_path)
        license_files = list(root.glob("LICENSE*")) + list(root.glob("COPYING*"))
        for lf in license_files:
            try:
                content = lf.read_text(encoding="utf-8", errors="ignore")
                for license_name, risk in LICENSE_RISKS.items():
                    if license_name.lower() in content.lower():
                        vulns.append(Vulnerability(
                            id=f"SCA-LICENSE-{license_name}",
                            title=f"许可证合规风险: {license_name}",
                            description=f"项目使用 {license_name} 许可证: {risk}",
                            severity="medium",
                            confidence=80,
                            file_path=str(lf),
                            line_number=1,
                            code_snippet=license_name,
                            rule_id="FUS-SCA-003",
                            cwe_id="CWE-1104",
                            fix_suggestion=f"评估 {license_name} 许可证对业务的影响，必要时替换为MIT/Apache-2.0等宽松许可证的组件",
                        ))
                        break
            except Exception as e:
                logger.debug(f"[SCA-003] 读取 {lf} 失败: {e}")

        for dep_file in root.rglob("package.json"):
            if any(p in dep_file.parts for p in {'.git', 'node_modules', '.venv', '__pycache__'}):
                continue
            try:
                data = json.loads(dep_file.read_text(encoding="utf-8", errors="ignore"))
                for dep_name, dep_info in data.get("dependencies", {}).items():
                    if isinstance(dep_info, dict):
                        lic = dep_info.get("license", "")
                    else:
                        lic = ""
                    for license_name, risk in LICENSE_RISKS.items():
                        if license_name.lower() == lic.lower():
                            vulns.append(Vulnerability(
                                id=f"SCA-LICENSE-{dep_name}-{license_name}",
                                title=f"许可证合规风险: {dep_name} ({license_name})",
                                description=f"依赖 {dep_name} 使用 {license_name}: {risk}",
                                severity="medium",
                                confidence=85,
                                file_path=str(dep_file),
                                line_number=0,
                                code_snippet=f"{dep_name}: {license_name}",
                                rule_id="FUS-SCA-003",
                                cwe_id="CWE-1104",
                                fix_suggestion=f"评估 {dep_name} ({license_name}) 对业务的影响，考虑替换为宽松许可证的替代方案",
                            ))
            except Exception as e:
                logger.debug(f"[SCA-003] 解析 {dep_file} 失败: {e}")

        logger.info(f"[SCA-003] 发现 {len(vulns)} 个许可证合规风险")
        return vulns

    def check_stale_versions(self, deps: List[Dependency]) -> List[Vulnerability]:
        import time
        vulns: List[Vulnerability] = []
        current_year = time.gmtime().tm_year
        for dep in deps:
            try:
                ver_parts = self._parse_version(dep.version)
                major = ver_parts[0] if ver_parts else 0
                if major == 0:
                    continue
                year_hint = 2000 + major if major < 100 else major
                if current_year - year_hint > STALE_VERSION_YEARS:
                    vulns.append(Vulnerability(
                        id=f"SCA-STALE-{dep.name}",
                        title=f"组件版本过旧: {dep.name} {dep.version}",
                        description=f"{dep.name} {dep.version} 可能已过旧({STALE_VERSION_YEARS}年以上)，建议升级到最新版本",
                        severity="low",
                        confidence=50,
                        file_path=dep.source_file,
                        line_number=0,
                        code_snippet=f"{dep.name}=={dep.version}",
                        rule_id="FUS-SCA-004",
                        cwe_id="CWE-1104",
                        fix_suggestion=f"升级 {dep.name} 到最新版本以获取安全补丁和功能改进",
                    ))
            except (ValueError, IndexError):
                continue
        logger.info(f"[SCA-004] 发现 {len(vulns)} 个过旧组件")
        return vulns

    def _parse_requirements(self, file_path: str, content: str) -> List[Dependency]:
        deps: List[Dependency] = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            match = re.match(r'^([a-zA-Z0-9_.-]+)\s*[=~><!]+\s*([0-9][0-9.a-zA-Z*-]*)', line)
            if match:
                deps.append(Dependency(
                    name=match.group(1), version=match.group(2),
                    ecosystem="pypi", source_file=file_path,
                ))
        return deps

    def _parse_pipfile(self, file_path: str, content: str) -> List[Dependency]:
        deps: List[Dependency] = []
        in_packages = False
        in_dev = False
        for line in content.splitlines():
            stripped = line.strip()
            if stripped == "[packages]":
                in_packages = True
                in_dev = False
                continue
            elif stripped == "[dev-packages]":
                in_packages = True
                in_dev = True
                continue
            elif stripped.startswith("["):
                in_packages = False
                continue
            if in_packages and "=" in stripped:
                name, _, rest = stripped.partition("=")
                name = name.strip()
                ver_match = re.search(r'"([0-9][0-9.a-zA-Z*-]*)"', rest)
                if ver_match:
                    deps.append(Dependency(
                        name=name, version=ver_match.group(1),
                        ecosystem="pypi", source_file=file_path, is_dev=in_dev,
                    ))
        return deps

    def _parse_pyproject(self, file_path: str, content: str) -> List[Dependency]:
        deps: List[Dependency] = []
        in_deps = False
        for line in content.splitlines():
            stripped = line.strip()
            if "dependencies" in stripped and "=" in stripped:
                in_deps = True
                continue
            elif in_deps and stripped.startswith("["):
                in_deps = False
                continue
            if in_deps:
                match = re.match(r'^"([a-zA-Z0-9_.-]+)([><=!~]+[0-9][0-9.a-zA-Z*-]*)', stripped)
                if match:
                    ver = re.search(r'[0-9][0-9.a-zA-Z*-]*', match.group(2))
                    deps.append(Dependency(
                        name=match.group(1),
                        version=ver.group(0) if ver else "0",
                        ecosystem="pypi", source_file=file_path,
                    ))
        return deps

    def _parse_package_json(self, file_path: str, content: str) -> List[Dependency]:
        deps: List[Dependency] = []
        try:
            data = json.loads(content)
            for section, is_dev in [("dependencies", False), ("devDependencies", True)]:
                for name, ver in data.get(section, {}).items():
                    clean_ver = re.sub(r'[^0-9.]', '', ver)
                    if clean_ver:
                        deps.append(Dependency(
                            name=name, version=clean_ver,
                            ecosystem="npm", source_file=file_path, is_dev=is_dev,
                        ))
        except json.JSONDecodeError:
            pass
        return deps

    def _parse_gomod(self, file_path: str, content: str) -> List[Dependency]:
        deps: List[Dependency] = []
        in_require = False
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("require ("):
                in_require = True
                continue
            elif stripped == ")" and in_require:
                in_require = False
                continue
            if in_require or stripped.startswith("require "):
                match = re.match(r'^\s*(\S+)\s+(v[0-9][0-9.]+)', stripped)
                if match:
                    deps.append(Dependency(
                        name=match.group(1), version=match.group(2).lstrip("v"),
                        ecosystem="gomod", source_file=file_path,
                    ))
        return deps

    def _parse_cargo(self, file_path: str, content: str) -> List[Dependency]:
        deps: List[Dependency] = []
        in_deps = False
        for line in content.splitlines():
            stripped = line.strip()
            if stripped == "[dependencies]":
                in_deps = True
                continue
            elif stripped.startswith("["):
                in_deps = False
                continue
            if in_deps and "=" in stripped:
                name, _, rest = stripped.partition("=")
                name = name.strip()
                ver = re.search(r'"([0-9][0-9.a-zA-Z*-]*)"', rest)
                if ver:
                    deps.append(Dependency(
                        name=name, version=ver.group(1),
                        ecosystem="cargo", source_file=file_path,
                    ))
        return deps

    def _parse_gemfile(self, file_path: str, content: str) -> List[Dependency]:
        deps: List[Dependency] = []
        for line in content.splitlines():
            match = re.match(r"gem\s+'([^']+)'(?:\s*,\s*'([^']+)')?", line.strip())
            if match:
                deps.append(Dependency(
                    name=match.group(1),
                    version=match.group(2) or "0",
                    ecosystem="rubygems", source_file=file_path,
                ))
        return deps
