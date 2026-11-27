"""SCA (Software Composition Analysis) — dependency vulnerability scanner."""

from __future__ import annotations

import contextlib
import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path

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


KNOWN_VULNS: list[KnownVuln] = [
    KnownVuln("CVE-2023-36664", "pypdf", "<3.16.0", "critical", "pypdf injection vulnerability", "3.16.0"),
    KnownVuln("CVE-2023-40217", "cryptography", "<41.0.6", "high", "cryptography man-in-the-middle attack", "41.0.6"),
    KnownVuln("CVE-2023-43804", "urllib3", "<2.0.7", "high", "urllib3 cookie leak", "2.0.7"),
    KnownVuln("CVE-2023-44287", "pillow", "<10.0.1", "high", "Pillow image parsing DoS", "10.0.1"),
    KnownVuln("CVE-2023-23934", "werkzeug", "<2.2.3", "medium", "Werkzeug cookie parsing issue", "2.2.3"),
    KnownVuln("CVE-2023-25577", "flask", "<2.2.3", "medium", "Flask cookie parsing DoS", "2.2.3"),
    KnownVuln("CVE-2022-25883", "semver", "<7.5.2", "high", "semver ReDoS", "7.5.2"),
    KnownVuln("CVE-2023-32002", "node:vm", "<20.5.0", "high", "Node.js vm module sandbox escape", "20.5.0"),
    KnownVuln("CVE-2023-34453", "snappy", "<0.2.0", "medium", "snappy buffer overflow", "0.2.0"),
    KnownVuln("CVE-2022-32149", "golang.org/x/text", "<0.3.8", "high", "Go x/text DoS", "0.3.8"),
]

DEPRECATED_PACKAGES: list[dict[str, str]] = [
    {
        "name": "pycrypto",
        "reason": "unmaintained with known vulnerabilities; use pycryptodome instead",
        "alternative": "pycryptodome",
    },
    {
        "name": "paramiko",
        "reason": "older versions have known security vulnerabilities",
        "alternative": "paramiko>=3.0",
    },
    {"name": "request", "reason": "deprecated; use requests instead", "alternative": "requests"},
    {"name": "pickle", "reason": "should not be used to deserialize untrusted data", "alternative": "json/msgpack"},
    {"name": "md5", "reason": "MD5 is no longer secure; use hashlib.sha256 instead", "alternative": "hashlib"},
]

LICENSE_RISKS: dict[str, str] = {
    "GPL-2.0": "copyleft — commercial use requires open-sourcing derivative works",
    "GPL-3.0": "copyleft — commercial use requires open-sourcing derivative works",
    "AGPL-3.0": "strong copyleft — network services must also be open-sourced",
    "SSPL-1.0": "not OSI-approved — may restrict cloud service usage",
    "BSL-1.1": "business source license — usage restrictions apply",
    " Commons-Clause": "not open source — commercial sale prohibited",
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
        self._client: httpx.Client | None = None

    def _get_client(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(timeout=self.timeout)
        return self._client

    def query_batch(self, deps: list[Dependency]) -> dict[str, list[dict]]:
        results: dict[str, list[dict]] = {}
        if not deps:
            return results
        queries = []
        for dep in deps:
            osv_eco = ECOSYSTEM_MAP.get(dep.ecosystem)
            if not osv_eco:
                continue
            queries.append(
                {
                    "version": dep.version,
                    "package": {"name": dep.name, "ecosystem": osv_eco},
                }
            )
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
    def __init__(self, use_osv: bool = False):
        # use_osv defaults to False: keeps the 100% offline promise. Enabling it
        # sends the dependency manifest out to osv.dev.
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

    def scan(self, project_path: str) -> list[Vulnerability]:
        # osv_client.close() previously ran before return; error paths (any check
        # raising) leaked the httpx.Client. Moved into finally to guarantee release.
        try:
            deps = self.collect_dependencies(project_path)
            logger.info(f"[SCA] collected {len(deps)} dependencies")
            vulns = self.check_vulnerabilities(deps)
            vulns.extend(self.check_deprecated(deps))
            vulns.extend(self.check_license(project_path))
            vulns.extend(self.check_stale_versions(deps))
            return vulns
        finally:
            if self.osv_client:
                with contextlib.suppress(Exception):
                    self.osv_client.close()

    def collect_dependencies(self, project_path: str) -> list[Dependency]:
        deps: list[Dependency] = []
        root = Path(project_path)
        for pattern, parser in self.parsers.items():
            for dep_file in root.rglob(pattern):
                if any(p in dep_file.parts for p in {".git", "node_modules", ".venv", "__pycache__"}):
                    continue
                try:
                    content = dep_file.read_text(encoding="utf-8", errors="ignore")
                    file_deps = parser(str(dep_file), content)
                    deps.extend(file_deps)
                except Exception as e:
                    logger.debug(f"[SCA] failed to parse {dep_file}: {e}")
        return deps

    def check_vulnerabilities(self, deps: list[Dependency]) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []
        osv_results: dict[str, list[dict]] = {}
        if self.use_osv and self.osv_client:
            osv_results = self.osv_client.query_batch(deps)
            if osv_results:
                logger.info(f"[OSV] found {sum(len(v) for v in osv_results.values())} vulnerabilities")
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
                            title=f"Dependency vulnerability: {dep.name} {dep.version} ({kv.cve_id})",
                            description=f"{dep.name} {dep.version} is affected by {kv.cve_id}: {kv.description}",
                            severity=kv.severity,
                            confidence=85,
                            file_path=dep.source_file,
                            line_number=0,
                            code_snippet=f"{dep.name}=={dep.version}",
                            rule_id="FUS-SCA-001",
                            cwe_id="CWE-1035",
                            fix_suggestion=f"Upgrade {dep.name} to {kv.fixed_version} or later",
                        )
                        vulns.append(v)
        logger.info(f"[SCA] found {len(vulns)} dependency vulnerabilities")
        return vulns

    def _osv_to_vulnerability(self, dep: Dependency, osv_vuln: dict) -> Vulnerability | None:
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
        description = summary or details or f"{dep.name} {dep.version} is affected by {cve_id}"
        return Vulnerability(
            id=f"SCA-{cve_id}-{dep.name}",
            title=f"Dependency vulnerability: {dep.name} {dep.version} ({cve_id})",
            description=description,
            severity=severity,
            confidence=90,
            file_path=dep.source_file,
            line_number=0,
            code_snippet=f"{dep.name}=={dep.version}",
            rule_id="FUS-SCA-001",
            cwe_id=cwe_id,
            fix_suggestion=f"Upgrade {dep.name} to {fixed_version} or later"
            if fixed_version
            else "See the OSV advisory for remediation guidance",
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
        cleaned = re.sub(r"[^0-9.]", "", version)
        parts = cleaned.split(".")
        parsed = tuple(int(p) for p in parts if p.isdigit())
        if not parsed:
            raise ValueError(f"cannot parse version: {version}")
        return parsed

    def check_deprecated(self, deps: list[Dependency]) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []
        for dep in deps:
            for pkg in DEPRECATED_PACKAGES:
                if dep.name.lower() == pkg["name"].lower():
                    vulns.append(
                        Vulnerability(
                            id=f"SCA-DEPRECATED-{dep.name}",
                            title=f"Deprecated component: {dep.name}",
                            description=f"{dep.name} {dep.version} is deprecated: {pkg['reason']}",
                            severity="medium",
                            confidence=90,
                            file_path=dep.source_file,
                            line_number=0,
                            code_snippet=f"{dep.name}=={dep.version}",
                            rule_id="FUS-SCA-002",
                            cwe_id="CWE-1104",
                            fix_suggestion=f"Replace with {pkg['alternative']}",
                        )
                    )
                    break
        logger.info(f"[SCA-002] found {len(vulns)} deprecated components")
        return vulns

    def check_license(self, project_path: str) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []
        root = Path(project_path)
        license_files = list(root.glob("LICENSE*")) + list(root.glob("COPYING*"))
        for lf in license_files:
            try:
                content = lf.read_text(encoding="utf-8", errors="ignore")
                for license_name, risk in LICENSE_RISKS.items():
                    if license_name.lower() in content.lower():
                        vulns.append(
                            Vulnerability(
                                id=f"SCA-LICENSE-{license_name}",
                                title=f"License compliance risk: {license_name}",
                                description=f"Project uses the {license_name} license: {risk}",
                                severity="medium",
                                confidence=80,
                                file_path=str(lf),
                                line_number=1,
                                code_snippet=license_name,
                                rule_id="FUS-SCA-003",
                                cwe_id="CWE-1104",
                                fix_suggestion=f"Evaluate the business impact of the {license_name} license; replace components with permissive licenses such as MIT/Apache-2.0 when necessary",
                            )
                        )
                        break
            except Exception as e:
                logger.debug(f"[SCA-003] failed to read {lf}: {e}")

        for dep_file in root.rglob("package.json"):
            if any(p in dep_file.parts for p in {".git", "node_modules", ".venv", "__pycache__"}):
                continue
            try:
                data = json.loads(dep_file.read_text(encoding="utf-8", errors="ignore"))
                for dep_name, dep_info in data.get("dependencies", {}).items():
                    lic = dep_info.get("license", "") if isinstance(dep_info, dict) else ""
                    for license_name, risk in LICENSE_RISKS.items():
                        if license_name.lower() == lic.lower():
                            vulns.append(
                                Vulnerability(
                                    id=f"SCA-LICENSE-{dep_name}-{license_name}",
                                    title=f"License compliance risk: {dep_name} ({license_name})",
                                    description=f"Dependency {dep_name} uses {license_name}: {risk}",
                                    severity="medium",
                                    confidence=85,
                                    file_path=str(dep_file),
                                    line_number=0,
                                    code_snippet=f"{dep_name}: {license_name}",
                                    rule_id="FUS-SCA-003",
                                    cwe_id="CWE-1104",
                                    fix_suggestion=f"Evaluate the business impact of {dep_name} ({license_name}); consider replacing it with a permissively licensed alternative",
                                )
                            )
            except Exception as e:
                logger.debug(f"[SCA-003] failed to parse {dep_file}: {e}")

        logger.info(f"[SCA-003] found {len(vulns)} license compliance risks")
        return vulns

    def check_stale_versions(self, deps: list[Dependency]) -> list[Vulnerability]:
        import time

        vulns: list[Vulnerability] = []
        current_year = time.gmtime().tm_year
        for dep in deps:
            try:
                ver_parts = self._parse_version(dep.version)
                major = ver_parts[0] if ver_parts else 0
                if major == 0:
                    continue
                year_hint = 2000 + major if major < 100 else major
                if current_year - year_hint > STALE_VERSION_YEARS:
                    vulns.append(
                        Vulnerability(
                            id=f"SCA-STALE-{dep.name}",
                            title=f"Outdated component version: {dep.name} {dep.version}",
                            description=f"{dep.name} {dep.version} may be outdated ({STALE_VERSION_YEARS}+ years old); consider upgrading to the latest version",
                            severity="low",
                            confidence=50,
                            file_path=dep.source_file,
                            line_number=0,
                            code_snippet=f"{dep.name}=={dep.version}",
                            rule_id="FUS-SCA-004",
                            cwe_id="CWE-1104",
                            fix_suggestion=f"Upgrade {dep.name} to the latest version to get security patches and feature improvements",
                        )
                    )
            except (ValueError, IndexError):
                continue
        logger.info(f"[SCA-004] found {len(vulns)} outdated components")
        return vulns

    def _parse_requirements(self, file_path: str, content: str) -> list[Dependency]:
        deps: list[Dependency] = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            match = re.match(r"^([a-zA-Z0-9_.-]+)\s*[=~><!]+\s*([0-9][0-9.a-zA-Z*-]*)", line)
            if match:
                deps.append(
                    Dependency(
                        name=match.group(1),
                        version=match.group(2),
                        ecosystem="pypi",
                        source_file=file_path,
                    )
                )
        return deps

    def _parse_pipfile(self, file_path: str, content: str) -> list[Dependency]:
        deps: list[Dependency] = []
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
                    deps.append(
                        Dependency(
                            name=name,
                            version=ver_match.group(1),
                            ecosystem="pypi",
                            source_file=file_path,
                            is_dev=in_dev,
                        )
                    )
        return deps

    def _parse_pyproject(self, file_path: str, content: str) -> list[Dependency]:
        deps: list[Dependency] = []
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
                    ver = re.search(r"[0-9][0-9.a-zA-Z*-]*", match.group(2))
                    deps.append(
                        Dependency(
                            name=match.group(1),
                            version=ver.group(0) if ver else "0",
                            ecosystem="pypi",
                            source_file=file_path,
                        )
                    )
        return deps

    def _parse_package_json(self, file_path: str, content: str) -> list[Dependency]:
        deps: list[Dependency] = []
        try:
            data = json.loads(content)
            for section, is_dev in [("dependencies", False), ("devDependencies", True)]:
                for name, ver in data.get(section, {}).items():
                    # ver may be a dist-tag ("latest"), an alias ("npm:foo@1.0"), or a
                    # non-string (file:/...). re.sub raises TypeError on non-strings
                    # (previously only JSONDecodeError was caught). Skip non-strings and
                    # versions without digits to avoid false positives.
                    if not isinstance(ver, str):
                        continue
                    clean_ver = re.sub(r"[^0-9.]", "", ver)
                    if clean_ver:
                        deps.append(
                            Dependency(
                                name=name,
                                version=clean_ver,
                                ecosystem="npm",
                                source_file=file_path,
                                is_dev=is_dev,
                            )
                        )
        except json.JSONDecodeError:
            pass
        return deps

    def _parse_gomod(self, file_path: str, content: str) -> list[Dependency]:
        deps: list[Dependency] = []
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
                match = re.match(r"^\s*(\S+)\s+(v[0-9][0-9.]+)", stripped)
                if match:
                    deps.append(
                        Dependency(
                            name=match.group(1),
                            version=match.group(2).lstrip("v"),
                            ecosystem="gomod",
                            source_file=file_path,
                        )
                    )
        return deps

    def _parse_cargo(self, file_path: str, content: str) -> list[Dependency]:
        deps: list[Dependency] = []
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
                    deps.append(
                        Dependency(
                            name=name,
                            version=ver.group(1),
                            ecosystem="cargo",
                            source_file=file_path,
                        )
                    )
        return deps

    def _parse_gemfile(self, file_path: str, content: str) -> list[Dependency]:
        deps: list[Dependency] = []
        for line in content.splitlines():
            match = re.match(r"gem\s+'([^']+)'(?:\s*,\s*'([^']+)')?", line.strip())
            if match:
                deps.append(
                    Dependency(
                        name=match.group(1),
                        version=match.group(2) or "0",
                        ecosystem="rubygems",
                        source_file=file_path,
                    )
                )
        return deps
