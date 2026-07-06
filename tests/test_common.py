import json
import logging
import os
from dataclasses import is_dataclass
from pathlib import Path

import pytest

from gywadmin_oci.common import (
    DEFAULT_SUMMARY_PATH,
    OciSummarySecrets,
    atomic_write,
    load_oci_config_from_summary,
    load_summary,
    validate_summary_file,
)


class TestOciSummarySecretsMoved:
    def test_dataclass_importable_from_common(self):
        assert is_dataclass(OciSummarySecrets)

    def test_dataclass_field_names_unchanged(self):
        fields = [
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "OCI_CLI_TENANCY",
            "OCI_CLI_USER",
            "OCI_CLI_FINGERPRINT",
            "OCI_CLI_KEY_CONTENT",
            "TF_VAR_private_key_password",
        ]
        from dataclasses import fields as dc_fields

        assert [f.name for f in dc_fields(OciSummarySecrets)] == fields

    def test_from_initialize_oci_summary_works(self):
        valid_dict = {
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
        instance = OciSummarySecrets.from_initialize_oci_summary(valid_dict)
        assert instance.AWS_ACCESS_KEY_ID == "AKIAEXAMPLE"
        assert instance.AWS_SECRET_ACCESS_KEY == "secretvalue123"
        assert instance.OCI_CLI_TENANCY == "ocid1.tenancy.oc1..aaaa"
        assert instance.OCI_CLI_USER == "ocid1.user.oc1..bbbb"
        assert instance.OCI_CLI_FINGERPRINT == "aa:bb:cc:dd"
        assert (
            instance.OCI_CLI_KEY_CONTENT
            == "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----\n"
        )
        assert instance.TF_VAR_private_key_password == "p@ssw0rd"

    def test_validate_summary_file_importable(self, tmp_path):
        log = logging.getLogger("test")
        missing_path = tmp_path / "missing.json"
        with pytest.raises(SystemExit) as exc:
            validate_summary_file(missing_path, log=log)
        assert exc.value.code == 3

    def test_load_summary_importable(self, tmp_path):
        log = logging.getLogger("test")
        valid_path = tmp_path / "valid.json"
        valid_path.write_text('{"foo": "bar"}')
        data = load_summary(valid_path, log=log)
        assert data == {"foo": "bar"}


class TestAtomicWrite:
    def test_atomic_write_creates_file(self, tmp_path):
        target = tmp_path / "file.bin"
        atomic_write(target, b"hello")
        assert target.exists()
        assert target.read_bytes() == b"hello"

    def test_atomic_write_default_mode_0600(self, tmp_path):
        if os.name != "posix":
            pytest.skip("POSIX only")
        target = tmp_path / "file.bin"
        atomic_write(target, b"hello")
        assert target.stat().st_mode & 0o777 == 0o600

    def test_atomic_write_custom_mode(self, tmp_path):
        if os.name != "posix":
            pytest.skip("POSIX only")
        target = tmp_path / "file.bin"
        atomic_write(target, b"hello", mode=0o644)
        assert target.stat().st_mode & 0o777 == 0o644

    def test_atomic_write_overwrites(self, tmp_path):
        target = tmp_path / "file.bin"
        atomic_write(target, b"first")
        atomic_write(target, b"second")
        assert target.read_bytes() == b"second"

    def test_atomic_write_creates_parent_dir(self, tmp_path):
        target = tmp_path / "newdir" / "file.bin"
        atomic_write(target, b"hello")
        assert target.exists()
        assert target.read_bytes() == b"hello"

    def test_atomic_write_no_tempfile_left_on_success(self, tmp_path):
        target = tmp_path / "file.bin"
        atomic_write(target, b"hello")
        files = list(tmp_path.iterdir())
        assert len(files) == 1
        assert files[0].name == "file.bin"

    def test_atomic_write_cleans_up_tempfile_on_failure(self, tmp_path, monkeypatch):
        target = tmp_path / "file.bin"

        def mock_replace(src, dst):
            raise OSError("mock error")

        monkeypatch.setattr(os, "replace", mock_replace)

        with pytest.raises(OSError, match="mock error"):
            atomic_write(target, b"hello")

        assert not target.exists()
        files = list(tmp_path.iterdir())
        assert len(files) == 0

    def test_atomic_write_atomic_rename(self, tmp_path):
        target = tmp_path / "file.bin"
        atomic_write(target, b"old")

        # We can't easily test the exact moment of rename without threading,
        # but we can verify that after the call, it's exactly the new content.
        atomic_write(target, b"new")
        assert target.read_bytes() == b"new"

    def test_atomic_write_bytes_preserved(self, tmp_path):
        target = tmp_path / "file.bin"
        content = b"hello\nworld\r\n\x00test"
        atomic_write(target, content)
        assert target.read_bytes() == content


class TestModuleConstants:
    def test_default_summary_path_constant(self):
        assert DEFAULT_SUMMARY_PATH == Path("output/initialize-oci-summary.json")


# Fake credentials whose FORMAT satisfies oci.config.validate_config:
# tenancy/user match the OCID regex and the fingerprint matches
# ``^([0-9a-f]{2}:){15}[0-9a-f]{2}$``. The private_pem is not a real key,
# but validate_config only checks presence for key_content.
_VALID_FINGERPRINT = "12:34:56:78:90:ab:cd:ef:12:34:56:78:90:ab:cd:ef"
_FAKE_PEM = "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----\n"
_FAKE_PASSPHRASE = "p@ssw0rd"


def _valid_summary():
    return {
        "tenancy_ocid": "ocid1.tenancy.oc1..aaaa",
        "region": "us-ashburn-1",
        "service_account": {
            "ocid": "ocid1.user.oc1..bbbb",
            "customer_secret_key": {
                "access_key": "AKIAEXAMPLE",
                "secret_key": "secretvalue123",
            },
            "api_key": {
                "fingerprint": _VALID_FINGERPRINT,
                "private_pem": _FAKE_PEM,
                "passphrase": _FAKE_PASSPHRASE,
            },
        },
    }


def _write_summary(tmp_path, data):
    path = tmp_path / "initialize-oci-summary.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    if os.name == "posix":
        os.chmod(path, 0o600)
    return path


class TestLoadOciConfigFromSummary:
    def test_happy_path(self, tmp_path):
        log = logging.getLogger("test")
        path = _write_summary(tmp_path, _valid_summary())
        config = load_oci_config_from_summary(path, None, log)
        assert config["user"] == "ocid1.user.oc1..bbbb"
        assert config["tenancy"] == "ocid1.tenancy.oc1..aaaa"
        assert config["fingerprint"] == _VALID_FINGERPRINT
        assert config["key_content"] == _FAKE_PEM
        assert config["pass_phrase"] == _FAKE_PASSPHRASE
        assert config["region"] == "us-ashburn-1"

    def test_region_override(self, tmp_path):
        log = logging.getLogger("test")
        path = _write_summary(tmp_path, _valid_summary())
        config = load_oci_config_from_summary(path, "us-phoenix-1", log)
        assert config["region"] == "us-phoenix-1"

    def test_missing_field_fingerprint(self, tmp_path):
        log = logging.getLogger("test")
        data = _valid_summary()
        del data["service_account"]["api_key"]["fingerprint"]
        path = _write_summary(tmp_path, data)
        with pytest.raises(SystemExit) as exc:
            load_oci_config_from_summary(path, None, log)
        assert exc.value.code == 3

    def test_missing_service_account(self, tmp_path):
        log = logging.getLogger("test")
        data = _valid_summary()
        del data["service_account"]
        path = _write_summary(tmp_path, data)
        with pytest.raises(SystemExit) as exc:
            load_oci_config_from_summary(path, None, log)
        assert exc.value.code == 3

    def test_empty_required_field(self, tmp_path):
        log = logging.getLogger("test")
        data = _valid_summary()
        data["service_account"]["ocid"] = ""
        path = _write_summary(tmp_path, data)
        with pytest.raises(SystemExit) as exc:
            load_oci_config_from_summary(path, None, log)
        assert exc.value.code == 3

    def test_missing_file(self, tmp_path):
        log = logging.getLogger("test")
        missing = tmp_path / "nope.json"
        with pytest.raises(SystemExit) as exc:
            load_oci_config_from_summary(missing, None, log)
        assert exc.value.code == 3

    def test_bad_json(self, tmp_path):
        log = logging.getLogger("test")
        path = tmp_path / "bad.json"
        path.write_text("not json", encoding="utf-8")
        if os.name == "posix":
            os.chmod(path, 0o600)
        with pytest.raises(SystemExit) as exc:
            load_oci_config_from_summary(path, None, log)
        assert exc.value.code == 3

    def test_no_secret_leak(self, tmp_path, caplog):
        log = logging.getLogger("test")
        path = _write_summary(tmp_path, _valid_summary())
        with caplog.at_level(logging.DEBUG):
            load_oci_config_from_summary(path, None, log)
        assert "MIIE" not in caplog.text
        assert _FAKE_PASSPHRASE not in caplog.text
