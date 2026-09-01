from unittest.mock import patch

import pytest

from fusion_security.engine.vcs.git import DiffResult, GitHelper


class TestDiffResult:
    def test_default(self):
        d = DiffResult()
        assert d.changed_files == []
        assert d.base_commit == ""

    def test_with_values(self):
        d = DiffResult(
            base_commit="abc",
            head_commit="def",
            changed_files=["a.py", "b.js"],
            added_files=["a.py"],
            modified_files=["b.js"],
        )
        assert len(d.changed_files) == 2
        assert len(d.added_files) == 1


class TestGitHelper:
    def test_init_valid_repo(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / ".git").mkdir()
        git = GitHelper(str(repo))
        assert git.repo_path == repo.resolve()

    def test_init_invalid_repo(self, tmp_path):
        not_repo = tmp_path / "not_repo"
        not_repo.mkdir()
        with pytest.raises(ValueError, match="不是git仓库"):
            GitHelper(str(not_repo))

    def test_get_changed_files_no_diff(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / ".git").mkdir()
        git = GitHelper(str(repo))

        def mock_git(*args):
            if "rev-parse" in args:
                return "abc123"
            return ""

        with patch.object(git, "_run_git", side_effect=mock_git):
            diff = git.get_changed_files("HEAD~1", "HEAD")
            assert diff.changed_files == []

    def test_get_changed_files_with_changes(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / ".git").mkdir()
        git = GitHelper(str(repo))

        name_status = "M\tapp/main.py\nA\tapp/new.js\nD\tapp/old.c"
        diff_content = "diff content..."

        def mock_git(*args):
            if "rev-parse" in args:
                return "abc123"
            if "--name-status" in args:
                return name_status
            return diff_content

        with patch.object(git, "_run_git", side_effect=mock_git):
            diff = git.get_changed_files("HEAD~1", "HEAD")
            assert "app/main.py" in diff.changed_files
            assert "app/new.js" in diff.added_files
            assert "app/main.py" in diff.modified_files
            assert "app/old.c" in diff.deleted_files
            assert diff.diff_content == diff_content

    def test_get_changed_files_filters_extensions(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / ".git").mkdir()
        git = GitHelper(str(repo))

        name_status = "M\tapp/main.py\nM\tREADME.md\nM\timage.png"

        def mock_git(*args):
            if "rev-parse" in args:
                return "abc123"
            return name_status

        with patch.object(git, "_run_git", side_effect=mock_git):
            diff = git.get_changed_files("HEAD~1", "HEAD")
            assert len(diff.changed_files) == 1
            assert "app/main.py" in diff.changed_files

    def test_get_current_branch(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / ".git").mkdir()
        git = GitHelper(str(repo))
        with patch.object(git, "_run_git", return_value="feature/scan"):
            assert git.get_current_branch() == "feature/scan"

    def test_get_head_commit(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / ".git").mkdir()
        git = GitHelper(str(repo))
        with patch.object(git, "_run_git", return_value="abc123"):
            assert git.get_head_commit() == "abc123"

    def test_list_commits(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / ".git").mkdir()
        git = GitHelper(str(repo))
        log = "abc|fix bug|dev|2025-01-01\ndef|add feature|dev|2025-01-02"
        with patch.object(git, "_run_git", return_value=log):
            commits = git.list_commits()
            assert len(commits) == 2
            assert commits[0]["hash"] == "abc"

    def test_get_changed_files_rejects_option_injection(self, tmp_path):
        from fusion_security.engine.vcs.git import GitArgError

        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / ".git").mkdir()
        git = GitHelper(str(repo))
        with pytest.raises(GitArgError):
            git.get_changed_files(base="--output=/tmp/x", head="HEAD")

    def test_get_file_at_commit_rejects_path_injection(self, tmp_path):
        from fusion_security.engine.vcs.git import GitArgError

        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / ".git").mkdir()
        git = GitHelper(str(repo))
        with pytest.raises(GitArgError):
            git.get_file_at_commit(filepath="-anything", commit="HEAD")


class TestIncrementalScan:
    def test_scan_incremental_via_scanner(self, tmp_path):
        from fusion_security.engine.scanner import Scanner, ScanTarget

        test_file = tmp_path / "vuln.py"
        test_file.write_text("eval(user_input)")
        target = ScanTarget(str(tmp_path))
        scanner = Scanner(use_ai=False)
        import asyncio

        result = asyncio.run(scanner.scan_incremental(target, ["vuln.py"], severity_threshold="low"))
        assert result.files_scanned >= 0
