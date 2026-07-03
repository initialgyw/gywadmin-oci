"""Tests for OCI session-token (security-token) authentication support.

Covers the helpers added to :mod:`gywadmin_oci.common` so that configs
produced by ``oci session authenticate`` (which omit the ``user`` OCID and
carry a ``security_token_file``) work end-to-end:

* :func:`build_signer`
* :func:`make_client`
* :func:`load_oci_config` (session vs API-key validation branch)
* :func:`verify_oci_authenticated` (session vs API-key preflight branch)
"""

from __future__ import annotations

import logging
import types
from pathlib import Path

import oci
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import gywadmin_oci.common as common

# Generate one unencrypted RSA key for the whole module (keeps tests fast).
_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_KEY_PEM = _KEY.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.TraditionalOpenSSL,
    serialization.NoEncryption(),
)

_TENANCY = "ocid1.tenancy.oc1..aaaatest"


def _write_session_files(tmp_path: Path) -> dict:
    """Write a key + token file and return a session-style config dict."""
    key_file = tmp_path / "oci_api_key.pem"
    token_file = tmp_path / "token"
    key_file.write_bytes(_KEY_PEM)
    token_file.write_text("eyJraWQ.eyJzdWIi.fakesig\n")
    return {
        "region": "us-ashburn-1",
        "tenancy": _TENANCY,
        "fingerprint": "aa:bb:cc:dd",
        "key_file": str(key_file),
        "security_token_file": str(token_file),
    }


def _write_session_config_file(tmp_path: Path) -> Path:
    """Write a full INI config file with a session-token DEFAULT profile."""
    cfg = _write_session_files(tmp_path)
    config_path = tmp_path / "config"
    config_path.write_text(
        "[DEFAULT]\n"
        f"fingerprint={cfg['fingerprint']}\n"
        f"key_file={cfg['key_file']}\n"
        f"tenancy={cfg['tenancy']}\n"
        f"region={cfg['region']}\n"
        f"security_token_file={cfg['security_token_file']}\n"
    )
    return config_path


class _RecordingClient:
    """Fake OCI client that records the config and kwargs it was built with."""

    def __init__(self, config, **kwargs):  # noqa: ANN001,ANN003
        self.config = config
        self.kwargs = kwargs


class TestBuildSigner:
    def test_returns_none_for_api_key_config(self):
        assert common.build_signer({"region": "us-ashburn-1"}) is None

    def test_returns_security_token_signer_for_session_config(self, tmp_path):
        cfg = _write_session_files(tmp_path)
        signer = common.build_signer(cfg)
        assert isinstance(signer, oci.auth.signers.SecurityTokenSigner)

    def test_token_is_stripped_of_trailing_whitespace(self, tmp_path):
        cfg = _write_session_files(tmp_path)
        # Should not raise; the trailing newline in the token file is stripped.
        assert common.build_signer(cfg) is not None

    def test_missing_key_file_raises(self, tmp_path):
        cfg = _write_session_files(tmp_path)
        cfg["key_file"] = str(tmp_path / "does-not-exist.pem")
        with pytest.raises(Exception):  # noqa: B017 - any load error is fine
            common.build_signer(cfg)

    def test_missing_token_file_raises(self, tmp_path):
        cfg = _write_session_files(tmp_path)
        cfg["security_token_file"] = str(tmp_path / "no-token")
        with pytest.raises(OSError):
            common.build_signer(cfg)


class TestMakeClient:
    def test_api_key_config_gets_no_signer(self):
        client = common.make_client(_RecordingClient, {"region": "x"})
        assert "signer" not in client.kwargs

    def test_session_config_gets_security_token_signer(self, tmp_path):
        cfg = _write_session_files(tmp_path)
        client = common.make_client(_RecordingClient, cfg)
        assert isinstance(client.kwargs["signer"], oci.auth.signers.SecurityTokenSigner)

    def test_service_endpoint_forwarded(self):
        client = common.make_client(
            _RecordingClient, {"region": "x"}, service_endpoint="https://ep"
        )
        assert client.kwargs["service_endpoint"] == "https://ep"

    def test_config_passed_through(self):
        cfg = {"region": "x"}
        client = common.make_client(_RecordingClient, cfg)
        assert client.config is cfg

    def test_real_identity_client_carries_signer(self, tmp_path):
        cfg = _write_session_files(tmp_path)
        client = common.make_client(oci.identity.IdentityClient, cfg)
        assert isinstance(
            client.base_client.signer, oci.auth.signers.SecurityTokenSigner
        )


class TestLoadOciConfigSession:
    def test_session_config_validates_without_user(self, tmp_path):
        log = logging.getLogger("test")
        config_path = _write_session_config_file(tmp_path)
        config = common.load_oci_config(config_path, "DEFAULT", None, log)
        assert config["tenancy"] == _TENANCY
        assert "user" not in config

    def test_region_override_applied(self, tmp_path):
        log = logging.getLogger("test")
        config_path = _write_session_config_file(tmp_path)
        config = common.load_oci_config(config_path, "DEFAULT", "us-phoenix-1", log)
        assert config["region"] == "us-phoenix-1"

    def test_missing_token_file_exits_3(self, tmp_path):
        log = logging.getLogger("test")
        cfg = _write_session_files(tmp_path)
        config_path = tmp_path / "config"
        config_path.write_text(
            "[DEFAULT]\n"
            f"fingerprint={cfg['fingerprint']}\n"
            f"key_file={cfg['key_file']}\n"
            f"tenancy={cfg['tenancy']}\n"
            f"region={cfg['region']}\n"
            f"security_token_file={tmp_path / 'missing-token'}\n"
        )
        with pytest.raises(SystemExit) as exc:
            common.load_oci_config(config_path, "DEFAULT", None, log)
        assert exc.value.code == 3

    def test_missing_config_file_exits_3(self, tmp_path):
        log = logging.getLogger("test")
        with pytest.raises(SystemExit) as exc:
            common.load_oci_config(tmp_path / "nope", "DEFAULT", None, log)
        assert exc.value.code == 3


class _FakeIdentity:
    def __init__(self, *, region_subs=None, user=None, raise_exc=None):
        self._region_subs = region_subs if region_subs is not None else []
        self._user = user
        self._raise = raise_exc
        self.region_calls: list = []
        self.user_calls: list = []

    def list_region_subscriptions(self, tenancy_id):  # noqa: ANN001,ANN201
        self.region_calls.append(tenancy_id)
        if self._raise is not None:
            raise self._raise
        return types.SimpleNamespace(data=self._region_subs)

    def get_user(self, user_id):  # noqa: ANN001,ANN201
        self.user_calls.append(user_id)
        if self._raise is not None:
            raise self._raise
        return types.SimpleNamespace(data=self._user)


class TestVerifyOciAuthenticatedSession:
    def test_session_uses_list_region_subscriptions(self, monkeypatch):
        log = logging.getLogger("test")
        fake = _FakeIdentity(region_subs=[object()])
        monkeypatch.setattr(common, "make_client", lambda *a, **k: fake)

        config = {
            "region": "us-ashburn-1",
            "tenancy": _TENANCY,
            "security_token_file": "/root/.oci/sessions/DEFAULT/token",
        }
        tenancy = common.verify_oci_authenticated(config, log)
        assert tenancy == _TENANCY
        assert fake.region_calls == [_TENANCY]
        assert fake.user_calls == []  # never calls get_user for sessions

    def test_session_missing_tenancy_exits_4(self, monkeypatch):
        log = logging.getLogger("test")
        monkeypatch.setattr(common, "make_client", lambda *a, **k: _FakeIdentity())
        config = {"region": "x", "security_token_file": "/root/.oci/token"}
        with pytest.raises(SystemExit) as exc:
            common.verify_oci_authenticated(config, log)
        assert exc.value.code == 4

    def test_session_service_error_exits_4(self, monkeypatch):
        log = logging.getLogger("test")
        err = oci.exceptions.ServiceError(401, "NotAuthenticated", {}, "expired")
        monkeypatch.setattr(
            common, "make_client", lambda *a, **k: _FakeIdentity(raise_exc=err)
        )
        config = {
            "region": "x",
            "tenancy": _TENANCY,
            "security_token_file": "/root/.oci/token",
        }
        with pytest.raises(SystemExit) as exc:
            common.verify_oci_authenticated(config, log)
        assert exc.value.code == 4

    def test_api_key_still_uses_get_user(self, monkeypatch):
        log = logging.getLogger("test")
        user = types.SimpleNamespace(name="svc", id="ocid1.user.oc1..u")
        fake = _FakeIdentity(user=user)
        monkeypatch.setattr(common, "make_client", lambda *a, **k: fake)

        config = {
            "region": "us-ashburn-1",
            "tenancy": _TENANCY,
            "user": "ocid1.user.oc1..u",
            "fingerprint": "aa:bb",
            "key_file": "/root/.oci/oci_api_key.pem",
        }
        tenancy = common.verify_oci_authenticated(config, log)
        assert tenancy == _TENANCY
        assert fake.user_calls == ["ocid1.user.oc1..u"]
        assert fake.region_calls == []  # never lists regions for API-key auth
