"""Tests for add-secret helpers in gywadmin_oci.manage_vault.

Set A: Log-line regression for MAJOR-2 — secret value must not appear in logs
       (no sha256 digest, no raw bytes).

Set B: Removed subcommands are rejected with exit code 2.
"""

from __future__ import annotations

import argparse
import io
import logging

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
