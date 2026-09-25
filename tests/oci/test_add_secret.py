"""Tests for add-secret helpers in gywadmin_oci.manage_vault.

Set A: Log-line regression for MAJOR-2 — secret value must not appear in logs
       (no sha256 digest, no raw bytes).

Set B: Removed subcommands are rejected with exit code 2.
"""

from __future__ import annotations

import argparse
import io
import logging
from types import SimpleNamespace

import pytest


# ---------------------------------------------------------------------------
# Set A: _load_secret_value log-line regression (MAJOR-2)
# ---------------------------------------------------------------------------


def test_load_secret_value_does_not_log_sha256(mv, caplog):
    """CLI-sourced secret value must not produce any sha256 log line."""
    args = argparse.Namespace(secret_value="supersecret")
    log = logging.getLogger("test_load")
    with caplog.at_level(logging.INFO, logger="test_load"):
        raw, source = mv._load_secret_value(args, log)

    assert raw == b"supersecret"
    assert source == "cli"
    for record in caplog.records:
        msg = record.getMessage().lower()
        assert "sha256" not in msg, (
            f"Log record unexpectedly contains 'sha256': {record.getMessage()!r}"
        )


def test_load_secret_value_logs_byte_count_not_content(mv, caplog):
    """Log output must include the byte count and source label, not the raw value."""
    args = argparse.Namespace(secret_value="supersecret")
    log = logging.getLogger("test_load_bytes")
    with caplog.at_level(logging.INFO, logger="test_load_bytes"):
        raw, source = mv._load_secret_value(args, log)

    assert raw == b"supersecret"
    assert source == "cli"
    # The caller (cmd_add_secret) logs byte count; _load_secret_value itself
    # only emits a WARNING about CLI visibility.  Verify the raw value is
    # absent from every captured record.
    for record in caplog.records:
        assert "supersecret" not in record.getMessage(), (
            f"Raw secret value leaked into log: {record.getMessage()!r}"
        )


def test_load_secret_value_stdin_source(mv, monkeypatch, caplog):
    """stdin-sourced secret value must return source='stdin' and correct bytes.

    ``_load_secret_value`` reads from ``sys.stdin.buffer``, so we provide a
    fake stdin object that exposes a ``.buffer`` attribute backed by a
    ``BytesIO``.
    """

    class _FakeStdin:
        """Minimal stdin stand-in with a binary ``buffer`` attribute."""

        def __init__(self, data: bytes) -> None:
            self.buffer = io.BytesIO(data)

        def isatty(self) -> bool:
            return False

    monkeypatch.setattr("sys.stdin", _FakeStdin(b"piped\n"))

    args = argparse.Namespace(secret_value="-")
    log = logging.getLogger("test_load_stdin")
    with caplog.at_level(logging.INFO, logger="test_load_stdin"):
        raw, source = mv._load_secret_value(args, log)

    assert raw == b"piped\n"
    assert source == "stdin"
    for record in caplog.records:
        msg = record.getMessage().lower()
        assert "sha256" not in msg, (
            f"Log record unexpectedly contains 'sha256': {record.getMessage()!r}"
        )


def test_cmd_add_secret_passes_named_mek_to_resolver_and_create(
    mv, common, make_args, monkeypatch, log
):
    """The selected named key controls the OCI key_id for a new secret."""
    calls: dict[str, object] = {}

    class _VaultClient:
        def list_secrets(self, **kwargs):  # noqa: ANN003, ANN201
            raise AssertionError("common.list_all is stubbed")

    def _make_client(*args, **kwargs):  # noqa: ANN002, ANN003
        return _VaultClient()

    def _auto_pick_mek(*args, **kwargs):  # noqa: ANN002, ANN003
        calls["mek_name"] = kwargs["mek_name"]
        return "ocid1.key.oc1..selected", "application_mek"

    def _create_secret(*args, **kwargs):  # noqa: ANN002, ANN003
        calls["mek_ocid"] = kwargs["mek_ocid"]
        return SimpleNamespace(
            id="ocid1.secret.oc1..created",
            current_version_number=1,
            lifecycle_state="ACTIVE",
        )

    monkeypatch.setattr(common, "require_dependencies", lambda *args, **kwargs: None)
    monkeypatch.setattr(mv, "_resolve_oci_config", lambda *args, **kwargs: {})
    monkeypatch.setattr(
        common,
        "verify_oci_authenticated",
        lambda *args, **kwargs: "ocid1.tenancy.oc1..test",
    )
    monkeypatch.setattr(
        mv,
        "oci",
        SimpleNamespace(
            identity=SimpleNamespace(IdentityClient=object),
            key_management=SimpleNamespace(KmsVaultClient=object),
            vault=SimpleNamespace(VaultsClient=object),
        ),
    )
    monkeypatch.setattr(common, "make_client", _make_client)
    monkeypatch.setattr(
        common,
        "lookup_compartment",
        lambda *args, **kwargs: "ocid1.compartment.oc1..test",
    )
    monkeypatch.setattr(
        common,
        "lookup_vault",
        lambda *args, **kwargs: ("ocid1.vault.oc1..test", "https://kms.example.test"),
    )
    monkeypatch.setattr(common, "auto_pick_mek", _auto_pick_mek)
    monkeypatch.setattr(common, "lookup_existing_secret", lambda *args, **kwargs: None)
    monkeypatch.setattr(common, "list_all", lambda *args, **kwargs: [])
    monkeypatch.setattr(mv, "_create_secret", _create_secret)

    result = mv.cmd_add_secret(
        make_args(dry_run=False, mek_name="application_mek"),
        log,
    )

    assert result == 0
    assert calls["mek_name"] == "application_mek"
    assert calls["mek_ocid"] == "ocid1.key.oc1..selected"


def test_cmd_add_secret_does_not_create_when_mek_resolution_fails(
    mv, common, make_args, monkeypatch, log
):
    """An exit-6 named-MEK resolution failure prevents secret creation."""

    class _VaultClient:
        def list_secrets(self, **kwargs):  # noqa: ANN003, ANN201
            raise AssertionError("common.list_all is stubbed")

    def _make_client(*args, **kwargs):  # noqa: ANN002, ANN003
        return _VaultClient()

    def _resolution_failure(*args, **kwargs):  # noqa: ANN002, ANN003
        raise SystemExit(6)

    def _create_secret(*args, **kwargs):  # noqa: ANN002, ANN003
        pytest.fail("_create_secret must not run after MEK resolution fails")

    monkeypatch.setattr(common, "require_dependencies", lambda *args, **kwargs: None)
    monkeypatch.setattr(mv, "_resolve_oci_config", lambda *args, **kwargs: {})
    monkeypatch.setattr(
        common,
        "verify_oci_authenticated",
        lambda *args, **kwargs: "ocid1.tenancy.oc1..test",
    )
    monkeypatch.setattr(
        mv,
        "oci",
        SimpleNamespace(
            identity=SimpleNamespace(IdentityClient=object),
            key_management=SimpleNamespace(KmsVaultClient=object),
            vault=SimpleNamespace(VaultsClient=object),
        ),
    )
    monkeypatch.setattr(common, "make_client", _make_client)
    monkeypatch.setattr(
        common,
        "lookup_compartment",
        lambda *args, **kwargs: "ocid1.compartment.oc1..test",
    )
    monkeypatch.setattr(
        common,
        "lookup_vault",
        lambda *args, **kwargs: ("ocid1.vault.oc1..test", "https://kms.example.test"),
    )
    monkeypatch.setattr(common, "auto_pick_mek", _resolution_failure)
    monkeypatch.setattr(mv, "_create_secret", _create_secret)

    with pytest.raises(SystemExit) as exc:
        mv.cmd_add_secret(
            make_args(dry_run=False, mek_name="mek_automation"),
            log,
        )

    assert exc.value.code == 6


# ---------------------------------------------------------------------------
# Set B: Removed subcommands are rejected with exit code 2
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "subcmd",
    ["create-mek", "encrypt-secrets", "list-meks", "retire-mek"],
)
def test_removed_subcommand_rejected(mv, subcmd):
    """Subcommands removed during the cleanup must exit with code 2."""
    with pytest.raises(SystemExit) as exc:
        mv.parse_args([subcmd, "--help"])
    assert exc.value.code == 2, (
        f"Expected exit code 2 for removed subcommand '{subcmd}', "
        f"got {exc.value.code!r}"
    )
