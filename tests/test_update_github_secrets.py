import json
import logging
import os
import subprocess
import sys
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from gywadmin_oci.update_github_secrets import (
    GitHubSecrets,
    load_summary,
    main,
    preflight_gh,
    process_secrets,
    set_github_secret,
    validate_summary_file,
)

@pytest.fixture
def valid_summary() -> dict:
    return {
        "tenancy_ocid": "ocid1.tenancy.oc1..aaaa",
        "service_account": {
            "ocid": "ocid1.user.oc1..bbbb",
            "customer_secret_key": {
                "access_key": "AKIAEXAMPLE",
                "secret_key": "secretvalue123",
            },
            "api_key": {
                "fingerprint": "aa:bb:cc:dd",
                "private_pem": "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----\n",
                "passphrase": "p@ssw0rd",
            },
        },
    }

@pytest.fixture
def summary_file(tmp_path, valid_summary):
    p = tmp_path / "summary.json"
    p.write_text(json.dumps(valid_summary), encoding="utf-8")
    if os.name == "posix":
        p.chmod(0o600)
    return p

@pytest.fixture
def log():
    return logging.getLogger("test_logger")

class FakeRunner:
    def __init__(self, *, returncode=0, stderr=b"", raise_exc=None):
        self.calls = []
        self.returncode = returncode
        self.stderr = stderr
        self.raise_exc = raise_exc
    def __call__(self, argv, stdin_bytes, timeout):
        self.calls.append({"argv": argv, "stdin": stdin_bytes, "timeout": timeout})
        if self.raise_exc:
            raise self.raise_exc
        return subprocess.CompletedProcess(args=argv, returncode=self.returncode, stdout=b"", stderr=self.stderr)

class MultiRunner:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []
    def __call__(self, argv, stdin_bytes, timeout):
        self.calls.append({"argv": argv, "stdin": stdin_bytes, "timeout": timeout})
        if not self.responses:
            return subprocess.CompletedProcess(args=argv, returncode=0, stdout=b"", stderr=b"")
        r = self.responses.pop(0)
        if callable(r):
            return r(argv, stdin_bytes, timeout)
        return subprocess.CompletedProcess(args=argv, returncode=r["returncode"], stdout=b"", stderr=r.get("stderr", b""))

class TestGitHubSecrets:
    def test_from_summary_valid(self, valid_summary):
        secrets = GitHubSecrets.from_initialize_oci_summary(valid_summary)
        assert secrets.AWS_ACCESS_KEY_ID == "AKIAEXAMPLE"
        assert secrets.AWS_SECRET_ACCESS_KEY == "secretvalue123"
        assert secrets.OCI_CLI_TENANCY == "ocid1.tenancy.oc1..aaaa"
        assert secrets.OCI_CLI_USER == "ocid1.user.oc1..bbbb"
        assert secrets.OCI_CLI_FINGERPRINT == "aa:bb:cc:dd"
        assert secrets.OCI_CLI_KEY_CONTENT == "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----\n"
        assert secrets.TF_VAR_private_key_password == "p@ssw0rd"

    @pytest.mark.parametrize("path_to_delete, expected_substring", [
        (["tenancy_ocid"], "tenancy_ocid"),
        (["service_account", "ocid"], "ocid"),
        (["service_account", "customer_secret_key", "access_key"], "access_key"),
        (["service_account", "customer_secret_key", "secret_key"], "secret_key"),
        (["service_account", "api_key", "fingerprint"], "fingerprint"),
        (["service_account", "api_key", "private_pem"], "private_pem"),
        (["service_account", "api_key", "passphrase"], "passphrase"),
    ])
    def test_from_summary_missing_required(self, valid_summary, path_to_delete, expected_substring):
        data = valid_summary
        for key in path_to_delete[:-1]:
            data = data[key]
        del data[path_to_delete[-1]]
        
        with pytest.raises(KeyError) as exc:
            GitHubSecrets.from_initialize_oci_summary(valid_summary)
        assert expected_substring in str(exc.value)

    def test_from_summary_passphrase_none(self, valid_summary):
        valid_summary["service_account"]["api_key"]["passphrase"] = None
        with pytest.raises(TypeError):
            GitHubSecrets.from_initialize_oci_summary(valid_summary)

    def test_from_summary_passphrase_empty(self, valid_summary):
        valid_summary["service_account"]["api_key"]["passphrase"] = ""
        with pytest.raises(ValueError):
            GitHubSecrets.from_initialize_oci_summary(valid_summary)

    def test_from_summary_passphrase_missing_key(self, valid_summary):
        del valid_summary["service_account"]["api_key"]["passphrase"]
        with pytest.raises(KeyError):
            GitHubSecrets.from_initialize_oci_summary(valid_summary)

    def test_dataclass_rejects_non_string(self):
        with pytest.raises(TypeError):
            GitHubSecrets(
                AWS_ACCESS_KEY_ID=123,
                AWS_SECRET_ACCESS_KEY="a",
                OCI_CLI_TENANCY="a",
                OCI_CLI_USER="a",
                OCI_CLI_FINGERPRINT="a",
                OCI_CLI_KEY_CONTENT="a",
                TF_VAR_private_key_password="a",
            )

    def test_dataclass_rejects_empty_string(self):
        with pytest.raises(ValueError):
            GitHubSecrets(
                AWS_ACCESS_KEY_ID="",
                AWS_SECRET_ACCESS_KEY="a",
                OCI_CLI_TENANCY="a",
                OCI_CLI_USER="a",
                OCI_CLI_FINGERPRINT="a",
                OCI_CLI_KEY_CONTENT="a",
                TF_VAR_private_key_password="a",
            )

    def test_dataclass_is_frozen(self, valid_summary):
        secrets = GitHubSecrets.from_initialize_oci_summary(valid_summary)
        with pytest.raises(FrozenInstanceError):
            secrets.AWS_ACCESS_KEY_ID = "new"

    def test_as_ordered_items_declaration_order(self, valid_summary):
        secrets = GitHubSecrets.from_initialize_oci_summary(valid_summary)
        items = secrets.as_ordered_items()
        names = [name for name, _ in items]
        assert names == [
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "OCI_CLI_TENANCY",
            "OCI_CLI_USER",
            "OCI_CLI_FINGERPRINT",
            "OCI_CLI_KEY_CONTENT",
            "TF_VAR_private_key_password",
        ]

class TestValidateSummaryFile:
    def test_validate_missing(self, tmp_path, log):
        with pytest.raises(SystemExit) as exc:
            validate_summary_file(tmp_path / "missing.json", log=log)
        assert exc.value.code == 3

    def test_validate_not_regular_file(self, tmp_path, log):
        with pytest.raises(SystemExit) as exc:
            validate_summary_file(tmp_path, log=log)
        assert exc.value.code == 3

    @pytest.mark.skipif(os.name != "posix", reason="POSIX only")
    def test_validate_insecure_perms_warns_continues(self, tmp_path, log, caplog):
        p = tmp_path / "insecure.json"
        p.write_text("{}")
        p.chmod(0o644)
        validate_summary_file(p, log=log)
        assert "insecure permissions" in caplog.text

    @pytest.mark.skipif(os.name != "posix", reason="POSIX only")
    def test_validate_secure_perms_no_warning(self, tmp_path, log, caplog):
        p = tmp_path / "secure.json"
        p.write_text("{}")
        p.chmod(0o600)
        validate_summary_file(p, log=log)
        assert "insecure permissions" not in caplog.text

class TestLoadSummary:
    def test_load_valid_json(self, tmp_path, log):
        p = tmp_path / "valid.json"
        p.write_text('{"a": 1}')
        assert load_summary(p, log=log) == {"a": 1}

    def test_load_invalid_json(self, tmp_path, log):
        p = tmp_path / "invalid.json"
        p.write_text('not json{')
        with pytest.raises(SystemExit) as exc:
            load_summary(p, log=log)
        assert exc.value.code == 3

    def test_load_oserror(self, tmp_path, log, monkeypatch):
        p = tmp_path / "error.json"
        p.write_text('{}')
        def mock_read_text(*args, **kwargs):
            raise OSError("mock error")
        monkeypatch.setattr(Path, "read_text", mock_read_text)
        with pytest.raises(SystemExit) as exc:
            load_summary(p, log=log)
        assert exc.value.code == 3

class TestSetGithubSecret:
    def test_set_secret_success_argv_has_repo_flag(self, log):
        runner = FakeRunner()
        res = set_github_secret("FOO", "barvalue", repo="owner/repo", runner=runner, log=log)
        assert res is True
        assert runner.calls[0]["argv"] == ["gh", "secret", "set", "FOO", "--repo", "owner/repo"]

    def test_set_secret_passes_value_via_stdin_as_bytes(self, log):
        runner = FakeRunner()
        set_github_secret("FOO", "barvalue", repo="owner/repo", runner=runner, log=log)
        assert runner.calls[0]["stdin"] == b"barvalue"
        assert "barvalue" not in runner.calls[0]["argv"]

    def test_set_secret_uses_default_timeout(self, log):
        runner = FakeRunner()
        set_github_secret("FOO", "barvalue", repo="owner/repo", runner=runner, log=log)
        assert runner.calls[0]["timeout"] == 30

    def test_set_secret_nonzero_returns_false(self, log, caplog):
        runner = FakeRunner(returncode=1, stderr=b"some error")
        res = set_github_secret("FOO", "barvalue", repo="owner/repo", runner=runner, log=log)
        assert res is False
        assert "some error" in caplog.text

    def test_set_secret_redacts_value_if_echoed(self, log, caplog):
        runner = FakeRunner(returncode=1, stderr=b"failed for value 'super-secret'")
        res = set_github_secret("FOO", "super-secret", repo="owner/repo", runner=runner, log=log)
        assert res is False
        assert "<redacted>" in caplog.text
        assert "super-secret" not in caplog.text

    def test_set_secret_timeout_returns_false(self, log, caplog):
        runner = FakeRunner(raise_exc=subprocess.TimeoutExpired(cmd=["gh"], timeout=30))
        res = set_github_secret("FOO", "barvalue", repo="owner/repo", runner=runner, log=log)
        assert res is False
        assert "Timed out" in caplog.text

    def test_set_secret_gh_missing_reraises(self, log):
        runner = FakeRunner(raise_exc=FileNotFoundError())
        with pytest.raises(FileNotFoundError):
            set_github_secret("FOO", "barvalue", repo="owner/repo", runner=runner, log=log)

    def test_set_secret_never_logs_value(self, log, caplog):
        runner = FakeRunner(returncode=1, stderr=b"failed for value 'super-secret'")
        set_github_secret("FOO", "super-secret", repo="owner/repo", runner=runner, log=log)
        for record in caplog.records:
            assert "super-secret" not in record.getMessage()

class TestPreflightGh:
    def test_preflight_auth_failure_exits_4(self, log, caplog):
        runner = MultiRunner([{"returncode": 1, "stderr": b"auth error"}])
        with pytest.raises(SystemExit) as exc:
            preflight_gh("owner/repo", runner=runner, log=log)
        assert exc.value.code == 4
        assert "auth error" in caplog.text

    def test_preflight_repo_failure_exits_4(self, log):
        runner = MultiRunner([{"returncode": 0}, {"returncode": 1, "stderr": b"repo error"}])
        with pytest.raises(SystemExit) as exc:
            preflight_gh("owner/repo", runner=runner, log=log)
        assert exc.value.code == 4

    def test_preflight_success(self, log):
        runner = MultiRunner([{"returncode": 0}, {"returncode": 0}])
        res = preflight_gh("owner/repo", runner=runner, log=log)
        assert res is None
        assert len(runner.calls) == 2
        assert runner.calls[0]["argv"] == ["gh", "auth", "status"]
        assert runner.calls[1]["argv"] == ["gh", "repo", "view", "owner/repo", "--json", "name", "-q", ".name"]

    def test_preflight_gh_missing_exits_2(self, log):
        def raise_fn(*args, **kwargs):
            raise FileNotFoundError()
        runner = MultiRunner([raise_fn])
        with pytest.raises(SystemExit) as exc:
            preflight_gh("owner/repo", runner=runner, log=log)
        assert exc.value.code == 2

class TestProcessSecrets:
    def test_process_dry_run_makes_no_calls(self, summary_file, log):
        runner = MultiRunner([])
        res = process_secrets(summary_file, repo="owner/repo", dry_run=True, yes=True, fail_fast=False, runner=runner, log=log)
        assert res == 0
        assert len(runner.calls) == 0

    def test_process_dry_run_logs_plan_with_names_only(self, summary_file, log, caplog):
        caplog.set_level(logging.INFO)
        runner = MultiRunner([])
        process_secrets(summary_file, repo="owner/repo", dry_run=True, yes=True, fail_fast=False, runner=runner, log=log)
        plan_line = next(r.getMessage() for r in caplog.records if "Dry run: would set" in r.getMessage())
        assert "AWS_ACCESS_KEY_ID" in plan_line
        assert "TF_VAR_private_key_password" in plan_line
        for record in caplog.records:
            assert "AKIAEXAMPLE" not in record.getMessage()
            assert "secretvalue123" not in record.getMessage()

    def test_process_full_success(self, summary_file, log):
        runner = MultiRunner([{"returncode": 0}] * 9)
        res = process_secrets(summary_file, repo="owner/repo", dry_run=False, yes=True, fail_fast=False, runner=runner, log=log)
        assert res == 0
        assert len(runner.calls) == 9
        for call in runner.calls[2:]:
            assert "--repo" in call["argv"]
            assert "owner/repo" in call["argv"]

    def test_process_partial_failure_best_effort_returns_1(self, summary_file, log, caplog):
        runner = MultiRunner([{"returncode": 0}, {"returncode": 0}, {"returncode": 0}, {"returncode": 1}, {"returncode": 0}, {"returncode": 0}, {"returncode": 0}, {"returncode": 0}, {"returncode": 0}])
        res = process_secrets(summary_file, repo="owner/repo", dry_run=False, yes=True, fail_fast=False, runner=runner, log=log)
        assert res == 1
        assert len(runner.calls) == 9
        assert "AWS_SECRET_ACCESS_KEY" in caplog.text

    def test_process_fail_fast_aborts(self, summary_file, log):
        runner = MultiRunner([{"returncode": 0}, {"returncode": 0}, {"returncode": 0}, {"returncode": 1}])
        res = process_secrets(summary_file, repo="owner/repo", dry_run=False, yes=True, fail_fast=True, runner=runner, log=log)
        assert res == 1
        assert len(runner.calls) == 4

    def test_process_missing_summary_file_exits_3(self, tmp_path, log):
        with pytest.raises(SystemExit) as exc:
            process_secrets(tmp_path / "missing.json", repo="owner/repo", dry_run=False, yes=True, fail_fast=False, log=log)
        assert exc.value.code == 3

    def test_process_invalid_json_exits_3(self, tmp_path, log):
        p = tmp_path / "invalid.json"
        p.write_text("not json")
        with pytest.raises(SystemExit) as exc:
            process_secrets(p, repo="owner/repo", dry_run=False, yes=True, fail_fast=False, log=log)
        assert exc.value.code == 3

    def test_process_invalid_summary_shape_exits_3(self, tmp_path, log, caplog):
        p = tmp_path / "empty.json"
        p.write_text("{}")
        with pytest.raises(SystemExit) as exc:
            process_secrets(p, repo="owner/repo", dry_run=False, yes=True, fail_fast=False, log=log)
        assert exc.value.code == 3
        for record in caplog.records:
            assert "AKIAEXAMPLE" not in record.getMessage()

    def test_process_gh_missing_during_secrets_returns_2(self, summary_file, log, caplog):
        def raise_fn(*args, **kwargs):
            raise FileNotFoundError()
        runner = MultiRunner([{"returncode": 0}, {"returncode": 0}, raise_fn])
        res = process_secrets(summary_file, repo="owner/repo", dry_run=False, yes=True, fail_fast=False, runner=runner, log=log)
        assert res == 2
        assert "gh CLI" in caplog.text

    def test_process_preflight_failure_exits_4(self, summary_file, log):
        runner = MultiRunner([{"returncode": 1}])
        with pytest.raises(SystemExit) as exc:
            process_secrets(summary_file, repo="owner/repo", dry_run=False, yes=True, fail_fast=False, runner=runner, log=log)
        assert exc.value.code == 4
        assert len(runner.calls) == 1

    def test_process_user_declines_confirmation_exits_11(self, summary_file, log, monkeypatch):
        monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
        runner = MultiRunner([{"returncode": 0}, {"returncode": 0}])
        with pytest.raises(SystemExit) as exc:
            process_secrets(summary_file, repo="owner/repo", dry_run=False, yes=False, fail_fast=False, runner=runner, log=log)
        assert exc.value.code == 11
        assert len(runner.calls) == 2

    def test_process_no_secret_values_in_any_log(self, summary_file, log, caplog):
        runner = MultiRunner([{"returncode": 0}] * 9)
        process_secrets(summary_file, repo="owner/repo", dry_run=False, yes=True, fail_fast=False, runner=runner, log=log)
        secret_values = [
            "AKIAEXAMPLE",
            "secretvalue123",
            "ocid1.tenancy.oc1..aaaa",
            "ocid1.user.oc1..bbbb",
            "aa:bb:cc:dd",
            "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----\n",
            "p@ssw0rd",
        ]
        for record in caplog.records:
            msg = record.getMessage()
            for val in secret_values:
                assert val not in msg

class TestMain:
    def test_main_requires_repo(self):
        with pytest.raises(SystemExit) as exc:
            main(["-f", "/tmp/x.json"])
        assert exc.value.code == 2

    def test_main_dry_run_returns_0(self, summary_file, monkeypatch):
        runner = MultiRunner([])
        from gywadmin_oci import update_github_secrets
        monkeypatch.setattr(update_github_secrets, "default_runner", runner)
        res = main(["--repo", "o/r", "-f", str(summary_file), "--dry-run"])
        assert res == 0
        assert len(runner.calls) == 0

    def test_main_propagates_exit_code_from_process_secrets(self, monkeypatch):
        from gywadmin_oci import update_github_secrets
        monkeypatch.setattr(update_github_secrets, "process_secrets", lambda *args, **kwargs: 1)
        res = main(["--repo", "o/r", "-f", "/tmp/x.json"])
        assert res == 1

    def test_main_help_lists_all_flags(self, capsys):
        with pytest.raises(SystemExit) as exc:
            main(["--help"])
        assert exc.value.code == 0
        out = capsys.readouterr().out
        assert "--repo" in out
        assert "--summary-file" in out
        assert "--dry-run" in out
        assert "--yes" in out
        assert "--fail-fast" in out
        assert "--verbose" in out

class TestSecurityRegression:
    def test_no_secret_value_appears_in_any_argv(self, summary_file, log):
        runner = MultiRunner([{"returncode": 0}] * 9)
        process_secrets(summary_file, repo="owner/repo", dry_run=False, yes=True, fail_fast=False, runner=runner, log=log)
        secret_values = [
            "AKIAEXAMPLE",
            "secretvalue123",
            "ocid1.tenancy.oc1..aaaa",
            "ocid1.user.oc1..bbbb",
            "aa:bb:cc:dd",
            "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----\n",
            "p@ssw0rd",
        ]
        for call in runner.calls:
            for arg in call["argv"]:
                for val in secret_values:
                    assert val not in arg

    def test_secret_values_only_on_stdin(self, summary_file, log):
        runner = MultiRunner([{"returncode": 0}] * 9)
        process_secrets(summary_file, repo="owner/repo", dry_run=False, yes=True, fail_fast=False, runner=runner, log=log)
        secret_values = [
            "AKIAEXAMPLE",
            "secretvalue123",
            "ocid1.tenancy.oc1..aaaa",
            "ocid1.user.oc1..bbbb",
            "aa:bb:cc:dd",
            "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----\n",
            "p@ssw0rd",
        ]
        # First two calls are preflight
        for i, call in enumerate(runner.calls[2:]):
            assert call["stdin"].decode("utf-8") == secret_values[i]
            for arg in call["argv"]:
                assert secret_values[i] not in arg

    def test_log_redaction_of_echoed_secret(self, log, caplog):
        runner = FakeRunner(returncode=1, stderr=b"failed for value 'super-secret'")
        set_github_secret("FOO", "super-secret", repo="owner/repo", runner=runner, log=log)
        assert "<redacted>" in caplog.text
        assert "super-secret" not in caplog.text
