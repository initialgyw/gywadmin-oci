"""CLI parsing tests for update-secret, get-secret, and add-secret --tags.

Argparse-only; no OCI mocking required.
"""

from __future__ import annotations

import pytest


# ---------------------------------------------------------------------------
# add-secret --tags
# ---------------------------------------------------------------------------
def test_add_secret_tags_flag_parses(mv):
    args = mv.parse_args(
        ["add-secret", "-n", "s", "--value", "v", "--tags", "env=prod,role=db"]
    )
    assert args.tags == "env=prod,role=db"


def test_add_secret_tags_flag_default_none(mv):
    args = mv.parse_args(["add-secret", "-n", "s", "--value", "v"])
    assert args.tags is None


# ---------------------------------------------------------------------------
# update-secret tag mutual exclusion
# ---------------------------------------------------------------------------
def test_update_secret_add_tags_parses(mv):
    args = mv.parse_args(
        ["update-secret", "-n", "s", "--value", "v", "--add-tags", "env=prod"]
    )
    assert args.add_tags == "env=prod"
    assert args.remove_tags is None
    assert args.set_tags is None


def test_update_secret_remove_tags_parses(mv):
    args = mv.parse_args(
        ["update-secret", "-n", "s", "--value", "v", "--remove-tags", "env"]
    )
    assert args.remove_tags == "env"


def test_update_secret_set_tags_parses(mv):
    args = mv.parse_args(
        ["update-secret", "-n", "s", "--value", "v", "--set-tags", "env=prod"]
    )
    assert args.set_tags == "env=prod"


def test_update_secret_set_tags_empty_string(mv):
    """--set-tags '' is allowed (means 'clear all tags')."""
    args = mv.parse_args(["update-secret", "-n", "s", "--value", "v", "--set-tags", ""])
    assert args.set_tags == ""


def test_update_secret_tag_flags_mutually_exclusive(mv):
    """--add-tags and --set-tags together must error."""
    with pytest.raises(SystemExit):
        mv.parse_args(
            [
                "update-secret",
                "-n",
                "s",
                "--value",
                "v",
                "--add-tags",
                "env=prod",
                "--set-tags",
                "role=db",
            ]
        )


def test_update_secret_add_and_remove_mutually_exclusive(mv):
    with pytest.raises(SystemExit):
        mv.parse_args(
            [
                "update-secret",
                "-n",
                "s",
                "--value",
                "v",
                "--add-tags",
                "env=prod",
                "--remove-tags",
                "role",
            ]
        )


def test_update_secret_no_tag_flags_defaults_all_none(mv):
    args = mv.parse_args(["update-secret", "-n", "s", "--value", "v"])
    assert args.add_tags is None
    assert args.remove_tags is None
    assert args.set_tags is None


# ---------------------------------------------------------------------------
# get-secret: --version-number / --stage removed
# ---------------------------------------------------------------------------
def test_get_secret_minimal(mv):
    args = mv.parse_args(["get-secret", "-n", "s"])
    assert args.secret_name == "s"
    assert args.output_format == "raw"


def test_get_secret_output_format_json(mv):
    args = mv.parse_args(["get-secret", "-n", "s", "--output-format", "json"])
    assert args.output_format == "json"


def test_get_secret_version_number_rejected(mv):
    """--version-number was removed; argparse rejects it."""
    with pytest.raises(SystemExit):
        mv.parse_args(["get-secret", "-n", "s", "--version-number", "1"])


def test_get_secret_stage_rejected(mv):
    """--stage was removed; argparse rejects it."""
    with pytest.raises(SystemExit):
        mv.parse_args(["get-secret", "-n", "s", "--stage", "CURRENT"])


# ---------------------------------------------------------------------------
# update-secret: tags-only mode (no --secret-value)
# ---------------------------------------------------------------------------
def test_update_secret_tags_only_parses_without_value(mv):
    """update-secret with only a tag flag (no --secret-value) parses cleanly."""
    args = mv.parse_args(["update-secret", "-n", "s", "--set-tags", "k=v"])
    assert args.secret_value is None
    assert args.set_tags == "k=v"
