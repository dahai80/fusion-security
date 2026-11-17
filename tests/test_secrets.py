import json
import os
import subprocess
import tempfile
from pathlib import Path

import pytest

from fusion_security.engine.secrets import SecretScanner, scan_history
from fusion_security.engine.secrets.integration import secrets_vulnerabilities
from fusion_security.engine.secrets.scanner import Allowlist, shannon_entropy

FIXTURES = Path(__file__).parent / "fixtures"

# Synthetic tokens, string-concat split so GitHub push protection does not
# fire on this file. Joined only at runtime.
AWS_KEY = "AKIA4QP3M9ZKX7WVT" + "2RD"
STRIPE_KEY = "sk_live_51H8xYzabcdefghijklmnop" + "qrstuv"


def load_corpus(filename: str) -> list[dict]:
    """Load a corpus fixture; join split token halves (@@name@@ placeholders).

    Tokens are stored split so GitHub push protection does not fire on the
    committed fixture; joining happens only at test time.
    """
    data = json.loads((FIXTURES / filename).read_text(encoding="utf-8"))
    tokens = {k: v["a"] + v["b"] for k, v in data.get("tokens", {}).items()}

    def render(text: str) -> str:
        for name, value in tokens.items():
            text = text.replace(f"@@{name}@@", value)
        return text

    return [{"text": render(c["text"]), "expect_rule": c.get("expect_rule")} for c in data["cases"]]


class TestEntropy:
    def test_shannon_entropy_bounds(self):
        assert shannon_entropy("") == 0.0
        assert shannon_entropy("aaaa") == 0.0
        assert shannon_entropy("A1b2C3d4!") > 2.5

    def test_confidence_severity_mapping(self):
        s = SecretScanner(allowlist=Allowlist())
        verified = s.scan_text(f"key = {AWS_KEY}")[0]
        assert verified.confidence == "verified" and verified.severity == "critical"
        likely = s.scan_text("api_key = 'Xk9$mQ2vLp8tR3wZk5Nj7Hf4D'")[0]
        assert likely.confidence == "likely" and likely.severity == "high"


class TestCorpus:
    """Plan gate: validators must reject a committed negative-sample corpus —
    every positive found with the expected rule, zero false positives."""

    @pytest.fixture(scope="class")
    def corpus(self):
        return load_corpus("secrets_corpus.json")

    def test_zero_false_positives(self, corpus):
        s = SecretScanner(allowlist=Allowlist())
        fps = []
        for c in corpus:
            if c["expect_rule"] is None and s.scan_text(c["text"]):
                fps.append(c["text"][:70])
        assert not fps, f"false positives: {fps}"

    def test_positive_recall(self, corpus):
        s = SecretScanner(allowlist=Allowlist())
        positives = [c for c in corpus if c["expect_rule"]]
        misses = [
            c["expect_rule"]
            for c in positives
            if not any(f.rule_id == f"SEC-{c['expect_rule'].upper()}" for f in s.scan_text(c["text"]))
        ]
        assert not misses, f"positive misses: {misses}"


class TestAllowlist:
    def test_content_hash_allowlist_suppresses(self):
        s = SecretScanner(allowlist=Allowlist())
        findings = s.scan_text(f"aws_access_key_id = {AWS_KEY}", rel_path="a.py")
        assert findings
        import hashlib

        al = Allowlist(entries={hashlib.sha256(findings[0].match.encode()).hexdigest()})
        s2 = SecretScanner(allowlist=al)
        assert s2.scan_text(f"aws_access_key_id = {AWS_KEY}", rel_path="a.py") == []

    def test_path_allowlist_suppresses(self):
        s = SecretScanner(allowlist=Allowlist(paths={"tests/fixtures/sample.pem"}))
        assert s.scan_text("-----BEGIN RSA PRIVATE KEY-----", rel_path="tests/fixtures/sample.pem") == []
        assert s.scan_text("-----BEGIN RSA PRIVATE KEY-----", rel_path="app/real.pem")


class TestVulnerabilityMapping:
    def test_findings_map_to_cwe798_vulnerabilities(self, tmp_path):
        f = tmp_path / "cfg.py"
        f.write_text(f"aws_access_key_id = {AWS_KEY}\n", encoding="utf-8")
        vulns = secrets_vulnerabilities(f, f.read_text(encoding="utf-8"), tmp_path)
        assert len(vulns) == 1
        v = vulns[0]
        assert v.rule_id == "SEC-AWS_ACCESS_KEY_ID"
        assert v.severity == "critical"
        assert v.cwe_id == "CWE-798"
        assert v.line_number == 1

    def test_allowlisted_file_maps_to_no_findings(self, tmp_path, monkeypatch):
        monkeypatch.setenv("FUSION_SECRETS_ALLOWLIST", str(tmp_path / "none.json"))
        f = tmp_path / "docs.md"
        f.write_text("token = abc123 short\n", encoding="utf-8")
        assert secrets_vulnerabilities(f, f.read_text(encoding="utf-8"), tmp_path) == []


def _git(repo: Path):
    def run(*args):
        subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)

    return run


class TestHistoryScan:
    def test_history_scan_finds_and_dedupes_by_commit(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        run = _git(repo)
        run("init", "-q")
        run("config", "user.email", "t@t.local")
        run("config", "user.name", "t")
        secret_file = repo / "cfg.py"
        secret_file.write_text(f"aws_access_key_id = {AWS_KEY}\n", encoding="utf-8")
        run("add", ".")
        run("commit", "-qm", "add cfg")
        # Remove the secret in a second commit; history scan must still flag it.
        secret_file.write_text("aws_access_key_id = os.environ['AWS_KEY']\n", encoding="utf-8")
        run("add", ".")
        run("commit", "-qm", "fix leak")

        result = scan_history(str(repo))
        assert result.commits_scanned >= 2
        assert any(f.rule_id == "SEC-AWS_ACCESS_KEY_ID" for f in result.findings)
        assert all(f.commit for f in result.findings if f.rule_id == "SEC-AWS_ACCESS_KEY_ID")

    def test_history_scan_rejects_non_repo(self, tmp_path):
        with pytest.raises(ValueError):
            scan_history(str(tmp_path))


class TestPipelineWiring:
    @pytest.mark.asyncio
    async def test_discover_stage_emits_secrets_findings(self):
        from fusion_security.engine.pipeline import PipelineConfig, PipelineContext, ScanPipeline

        with tempfile.TemporaryDirectory() as tmp:
            py = Path(tmp) / "cfg.py"
            py.write_text(f"aws_access_key_id = {AWS_KEY}\n", encoding="utf-8")
            pipeline = ScanPipeline(
                PipelineConfig(use_ai=False, enable_adversarial=False, enable_sca=False, enable_taint=False)
            )
            ctx = PipelineContext(project_path=tmp)
            ctx.files = [py]
            await pipeline._stage_discover(ctx)
            rule_ids = {v.rule_id for v in ctx.vulnerabilities}
            assert "SEC-AWS_ACCESS_KEY_ID" in rule_ids

    @pytest.mark.asyncio
    async def test_discover_stage_secrets_disabled(self):
        from fusion_security.engine.pipeline import PipelineConfig, PipelineContext, ScanPipeline

        with tempfile.TemporaryDirectory() as tmp:
            py = Path(tmp) / "cfg.py"
            py.write_text(f"aws_access_key_id = {AWS_KEY}\n", encoding="utf-8")
            pipeline = ScanPipeline(
                PipelineConfig(
                    use_ai=False, enable_adversarial=False, enable_sca=False, enable_taint=False, enable_secrets=False
                )
            )
            ctx = PipelineContext(project_path=tmp)
            ctx.files = [py]
            await pipeline._stage_discover(ctx)
            assert not any(v.rule_id.startswith("SEC-") for v in ctx.vulnerabilities)

    @pytest.mark.asyncio
    async def test_legacy_scanner_counts_secrets_for_gate(self):
        from fusion_security.engine.scanner import Scanner, ScanTarget

        with tempfile.TemporaryDirectory() as tmp:
            py = Path(tmp) / "cfg.py"
            py.write_text(f'stripe_key = "{STRIPE_KEY}"\n', encoding="utf-8")
            scanner = Scanner(use_ai=False)
            result = await scanner.scan(ScanTarget(tmp))
            secret_hits = [v for v in result.vulnerabilities if v.rule_id == "SEC-STRIPE_SECRET_KEY"]
            assert secret_hits
            assert secret_hits[0].severity == "critical"


class TestSastDeprecation:
    def test_legacy_secret_rules_still_present_but_flagged(self):
        import inspect

        from fusion_security.engine.rules.engine import RuleEngine

        ids = {r.id for r in RuleEngine().get_rules()}
        assert {"SEC001", "SEC002"} <= ids
        import fusion_security.engine.rules.engine as rules_mod

        mod_src = inspect.getsource(rules_mod)
        assert "DEPRECATED (P1.2)" in mod_src


class TestSecretsCli:
    def _make_tree(self, tmp_path: Path) -> Path:
        (tmp_path / "node_modules" / "pkg").mkdir(parents=True)
        (tmp_path / ".next" / "static").mkdir(parents=True)
        (tmp_path / "dist").mkdir(parents=True)
        (tmp_path / "sub" / "vendor").mkdir(parents=True)
        (tmp_path / "src").mkdir(parents=True)
        (tmp_path / "src" / "app.py").write_text(f'stripe_key = "{STRIPE_KEY}"\n', encoding="utf-8")
        (tmp_path / "node_modules" / "pkg" / "index.js").write_text(f'const k = "{STRIPE_KEY}";\n', encoding="utf-8")
        (tmp_path / ".next" / "static" / "chunk.js").write_text(f'e="{STRIPE_KEY}";\n', encoding="utf-8")
        (tmp_path / "dist" / "bundle.min.js").write_text(f'x="{STRIPE_KEY}";\n', encoding="utf-8")
        (tmp_path / "sub" / "vendor" / "lib.py").write_text(f'k = "{STRIPE_KEY}"\n', encoding="utf-8")
        (tmp_path / "package-lock.json").write_text(f'{{"k": "{STRIPE_KEY}"}}\n', encoding="utf-8")
        return tmp_path

    def _run(self, tmp_path: Path, *args: str):
        from click.testing import CliRunner

        from fusion_security.cli import cli

        runner = CliRunner()
        return runner.invoke(cli, ["secrets-scan", str(tmp_path), *args])

    @staticmethod
    def _json_out(result) -> dict:
        # CliRunner may merge stderr log lines into output; JSON starts at first brace
        return json.loads(result.output[result.output.index("{") :])

    def test_default_excludes_skip_build_dirs(self, tmp_path):
        self._make_tree(tmp_path)
        result = self._run(tmp_path)
        assert result.exit_code == 1
        payload = self._json_out(result)
        assert payload["files_scanned"] == 1  # only src/app.py survives excludes
        files = {f["file"] for f in payload["findings"]}
        assert files == {os.path.join("src", "app.py")}

    def test_findings_carry_file_field(self, tmp_path):
        self._make_tree(tmp_path)
        payload = json.loads(self._run(tmp_path).output)
        assert payload["findings"]
        for f in payload["findings"]:
            assert f["file"] == os.path.join("src", "app.py")

    def test_no_default_excludes_restores_full_walk(self, tmp_path):
        self._make_tree(tmp_path)
        payload = json.loads(self._run(tmp_path, "--no-default-excludes").output)
        assert payload["files_scanned"] == 6
        files = {f["file"] for f in payload["findings"]}
        assert any("node_modules" in f for f in files)

    def test_exclude_option_overrides(self, tmp_path):
        self._make_tree(tmp_path)
        payload = json.loads(
            self._run(tmp_path, "--no-default-excludes", "--exclude", "node_modules", "--exclude", "*.min.js").output
        )
        files = {f["file"] for f in payload["findings"]}
        assert files
        assert not any("node_modules" in f or f.endswith(".min.js") for f in files)

    def test_output_writes_file_and_summary_stdout(self, tmp_path):
        self._make_tree(tmp_path)
        out_file = tmp_path.parent / "report.json"
        result = self._run(tmp_path, "--output", str(out_file))
        assert result.exit_code == 1
        assert out_file.exists()
        full = json.loads(out_file.read_text(encoding="utf-8"))
        assert full["findings"]
        summary = self._json_out(result)
        assert summary["total_findings"] == len(full["findings"])
        assert summary["files_scanned"] == full["files_scanned"]
        assert summary["rules"].get("SEC-STRIPE_SECRET_KEY") == len(full["findings"])
        assert summary["top_findings"] == []

    def test_summary_mode_counts(self, tmp_path):
        self._make_tree(tmp_path)
        result = self._run(tmp_path, "--summary")
        assert result.exit_code == 1
        summary = self._json_out(result)
        assert summary["total_findings"] >= 1
        assert summary["rules"]
        assert 0 < len(summary["top_findings"]) <= 10
        assert summary["top_findings"][0]["severity"] in {"critical", "high", "medium", "low"}
        assert "findings" not in summary

    def test_scan_text_sets_file_field(self):
        scanner = SecretScanner()
        findings = scanner.scan_text(f'k = "{STRIPE_KEY}"\n', rel_path="cfg/prod.py")
        assert findings
        assert findings[0].file == "cfg/prod.py"
        assert findings[0].to_dict()["file"] == "cfg/prod.py"
