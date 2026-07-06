"""Tests for the --summary-file / -f flag and _resolve_oci_config selection.

Covers the argparse wiring (all subcommands inherit ``--summary-file`` from
the common parent parser) and the resolver's choice between the summary-based
service-account config and the classic ``--oci-config-file`` path.
"""

from __future__ import annotations

import argparse
from pathlib import Path


def test_summary_file_defaults_to_none(mv):
    """When omitted, ``summary_file`` is ``None``."""
    args = mv.parse_args(["list-secrets"])
    assert args.summary_file is None


def test_summary_file_short_flag_resolves_to_path(mv):
    """``-f`` yields a resolved ``pathlib.Path`` ending in the filename."""
    args = mv.parse_args(["list-secrets", "-f", "/tmp/x/summary.json"])
    assert isinstance(args.summary_file, Path)
    assert args.summary_file.name == "summary.json"


def test_summary_file_long_flag_on_add_secret(mv):
    """``--summary-file`` long form works on add-secret (requires -n)."""
    args = mv.parse_args(
        ["add-secret", "-n", "foo", "--summary-file", "/tmp/x/summary.json"]
    )
    assert isinstance(args.summary_file, Path)
    assert args.summary_file.name == "summary.json"


def test_resolve_uses_config_file_when_summary_none(mv, common, monkeypatch):
    """``summary_file=None`` selects ``load_oci_config`` (not the summary path)."""
    calls: dict[str, object] = {}

    def _fake_config(**kw):
        calls["config"] = kw
        return {"source": "config-file"}

    def _fake_summary(**kw):
        calls["summary"] = kw
        return {"source": "summary"}

    monkeypatch.setattr(common, "load_oci_config", _fake_config)
    monkeypatch.setattr(common, "load_oci_config_from_summary", _fake_summary)

    args = argparse.Namespace(
        summary_file=None,
        oci_config_file=Path("/tmp/config"),
        oci_profile="DEFAULT",
        region=None,
    )
    result = mv._resolve_oci_config(args, mv.logging.getLogger("test"))
    assert result == {"source": "config-file"}
    assert "config" in calls
    assert "summary" not in calls


def test_resolve_uses_summary_when_provided(mv, common, monkeypatch):
    """``summary_file`` set selects the summary path and forwards region."""
    calls: dict[str, object] = {}

    def _fake_config(**kw):
        calls["config"] = kw
        return {"source": "config-file"}

    def _fake_summary(**kw):
        calls["summary"] = kw
        return {"source": "summary"}

    monkeypatch.setattr(common, "load_oci_config", _fake_config)
    monkeypatch.setattr(common, "load_oci_config_from_summary", _fake_summary)

    args = argparse.Namespace(
        summary_file=Path("/tmp/x/summary.json"),
        oci_config_file=Path("/tmp/config"),
        oci_profile="DEFAULT",
        region="us-phoenix-1",
    )
    result = mv._resolve_oci_config(args, mv.logging.getLogger("test"))
    assert result == {"source": "summary"}
    assert "summary" in calls
    assert "config" not in calls
    assert calls["summary"]["region_override"] == "us-phoenix-1"
    assert calls["summary"]["summary_path"] == Path("/tmp/x/summary.json")
