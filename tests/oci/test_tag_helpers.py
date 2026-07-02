"""Unit tests for the tag-parsing helpers in gywadmin_oci.manage_vault.

Covers ``_parse_tags_kv``, ``_parse_tag_keys``, and ``_resolve_tag_mutation``.
These helpers are pure-Python and have no OCI dependency, so the tests do
not need any mock fixtures.
"""
from __future__ import annotations

import argparse
import logging

import pytest


# ---------------------------------------------------------------------------
# _parse_tags_kv
# ---------------------------------------------------------------------------
def test_parse_tags_kv_none_returns_empty(mv, log):
    assert mv._parse_tags_kv(None, log) == {}


def test_parse_tags_kv_empty_string_returns_empty(mv, log):
    assert mv._parse_tags_kv("", log) == {}


def test_parse_tags_kv_single_pair(mv, log):
    assert mv._parse_tags_kv("env=prod", log) == {"env": "prod"}


def test_parse_tags_kv_multiple_pairs(mv, log):
    assert mv._parse_tags_kv("env=prod,role=db", log) == {"env": "prod", "role": "db"}


def test_parse_tags_kv_strips_whitespace(mv, log):
    assert mv._parse_tags_kv(" env = prod , role = db ", log) == {
        "env": "prod",
        "role": "db",
    }


def test_parse_tags_kv_empty_value_allowed(mv, log):
    assert mv._parse_tags_kv("env=", log) == {"env": ""}


def test_parse_tags_kv_missing_equals_rejected(mv, log):
    with pytest.raises(SystemExit) as exc:
        mv._parse_tags_kv("env", log)
    assert exc.value.code == 10


def test_parse_tags_kv_empty_key_rejected(mv, log):
    with pytest.raises(SystemExit) as exc:
        mv._parse_tags_kv("=value", log)
    assert exc.value.code == 10


def test_parse_tags_kv_multiple_equals_rejected(mv, log):
    with pytest.raises(SystemExit) as exc:
        mv._parse_tags_kv("env=a=b", log)
    assert exc.value.code == 10


def test_parse_tags_kv_empty_pair_in_list_rejected(mv, log):
    with pytest.raises(SystemExit) as exc:
        mv._parse_tags_kv("env=prod,,role=db", log)
    assert exc.value.code == 10


# ---------------------------------------------------------------------------
# _parse_tag_keys
# ---------------------------------------------------------------------------
def test_parse_tag_keys_none_returns_empty(mv, log):
    assert mv._parse_tag_keys(None, log) == []


def test_parse_tag_keys_empty_string_returns_empty(mv, log):
    assert mv._parse_tag_keys("", log) == []


def test_parse_tag_keys_single(mv, log):
    assert mv._parse_tag_keys("env", log) == ["env"]


def test_parse_tag_keys_multiple(mv, log):
    assert mv._parse_tag_keys("env,role,app", log) == ["env", "role", "app"]


def test_parse_tag_keys_deduplicates(mv, log):
    assert mv._parse_tag_keys("env,role,env", log) == ["env", "role"]


def test_parse_tag_keys_strips_whitespace(mv, log):
    assert mv._parse_tag_keys(" env , role ", log) == ["env", "role"]


def test_parse_tag_keys_rejects_kv_pair(mv, log):
    with pytest.raises(SystemExit) as exc:
        mv._parse_tag_keys("env=prod", log)
    assert exc.value.code == 10


def test_parse_tag_keys_rejects_empty_key(mv, log):
    with pytest.raises(SystemExit) as exc:
        mv._parse_tag_keys("env,,role", log)
    assert exc.value.code == 10


# ---------------------------------------------------------------------------
# _resolve_tag_mutation
# ---------------------------------------------------------------------------
def _ns(**overrides):
    """argparse.Namespace with all three tag flags defaulting to None."""
    defaults = {"add_tags": None, "remove_tags": None, "set_tags": None}
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


def test_resolve_tag_mutation_no_flags(mv, log):
    existing = {"env": "prod"}
    out, mode = mv._resolve_tag_mutation(existing, _ns(), log)
    assert mode is None
    assert out == {"env": "prod"}
    # Returned dict must not be the same instance (defensive copy).
    assert out is not existing


def test_resolve_tag_mutation_add(mv, log):
    existing = {"env": "prod"}
    out, mode = mv._resolve_tag_mutation(existing, _ns(add_tags="role=db"), log)
    assert mode == "add"
    assert out == {"env": "prod", "role": "db"}


def test_resolve_tag_mutation_add_overwrites(mv, log):
    existing = {"env": "prod"}
    out, mode = mv._resolve_tag_mutation(existing, _ns(add_tags="env=staging"), log)
    assert mode == "add"
    assert out == {"env": "staging"}


def test_resolve_tag_mutation_remove(mv, log):
    existing = {"env": "prod", "role": "db", "app": "web"}
    out, mode = mv._resolve_tag_mutation(existing, _ns(remove_tags="env,role"), log)
    assert mode == "remove"
    assert out == {"app": "web"}


def test_resolve_tag_mutation_remove_missing_keys_ignored(mv, log):
    existing = {"env": "prod"}
    out, mode = mv._resolve_tag_mutation(existing, _ns(remove_tags="not-there"), log)
    assert mode == "remove"
    assert out == {"env": "prod"}


def test_resolve_tag_mutation_set_replaces(mv, log):
    existing = {"env": "prod", "role": "db"}
    out, mode = mv._resolve_tag_mutation(existing, _ns(set_tags="only=this"), log)
    assert mode == "set"
    assert out == {"only": "this"}


def test_resolve_tag_mutation_set_empty_clears(mv, log):
    existing = {"env": "prod"}
    out, mode = mv._resolve_tag_mutation(existing, _ns(set_tags=""), log)
    assert mode == "set"
    assert out == {}


def test_resolve_tag_mutation_existing_none(mv, log):
    out, mode = mv._resolve_tag_mutation(None, _ns(add_tags="k=v"), log)
    assert mode == "add"
    assert out == {"k": "v"}


# ---------------------------------------------------------------------------
# cmd_update_secret tags-only mode
# ---------------------------------------------------------------------------
def test_cmd_update_secret_tags_only_dry_run_skips_value_loading(
    mv, mock_oci, make_args, log, monkeypatch
):
    """A tags-only invocation must NOT call _load_secret_value.

    We replace _load_secret_value with a tripwire that raises if reached;
    the command must complete (return 0) without tripping it.
    """

    def _tripwire(*a, **kw):
        raise AssertionError(
            "_load_secret_value should NOT be called in tags-only mode"
        )

    monkeypatch.setattr(mv, "_load_secret_value", _tripwire)

    # Provide an `existing` secret summary via lookup_existing_secret so the
    # command reaches the tags-only branch.
    class _Existing:
        id = "ocid1.secret.oc1..fake"
        secret_name = "test1"
        lifecycle_state = "ACTIVE"
        current_version_number = 1
        freeform_tags = {"old": "tag"}

    monkeypatch.setattr(
        mv.common, "lookup_existing_secret", lambda *a, **kw: _Existing()
    )

    args = make_args(
        subcommand="update-secret",
        secret_name="test1",
        secret_value=None,  # no value provided
        add_tags=None,
        remove_tags=None,
        set_tags="k=v",
        dry_run=True,
    )
    rc = mv.cmd_update_secret(args, log)
    assert rc == 0


def test_cmd_update_secret_tags_only_non_dry_run_calls_helper(
    mv, mock_oci, make_args, log, monkeypatch
):
    """Non-dry-run tags-only update calls _update_secret_tags_only (not _update_secret)."""

    # Tripwire both value-loading and the version-pushing helper.
    monkeypatch.setattr(
        mv,
        "_load_secret_value",
        lambda *a, **kw: (_ for _ in ()).throw(
            AssertionError("must not load secret value")
        ),
    )
    monkeypatch.setattr(
        mv,
        "_update_secret",
        lambda *a, **kw: (_ for _ in ()).throw(
            AssertionError("must not call value-push update helper")
        ),
    )

    class _Existing:
        id = "ocid1.secret.oc1..fake"
        secret_name = "test1"
        lifecycle_state = "ACTIVE"
        current_version_number = 1
        freeform_tags = {"old": "tag"}

    monkeypatch.setattr(
        mv.common, "lookup_existing_secret", lambda *a, **kw: _Existing()
    )

    called = {"tags_only": 0}

    def _fake_tags_only(*a, **kw):
        called["tags_only"] += 1
        # Return a fake "after" secret with the expected attributes.
        result = type(
            "S",
            (),
            {
                "id": kw["secret_id"],
                "current_version_number": 1,
                "lifecycle_state": "ACTIVE",
                "freeform_tags": kw["freeform_tags"],
            },
        )()
        return result

    monkeypatch.setattr(mv, "_update_secret_tags_only", _fake_tags_only)

    args = make_args(
        subcommand="update-secret",
        secret_name="test1",
        secret_value=None,
        add_tags=None,
        remove_tags=None,
        set_tags="k=v",
        dry_run=False,
    )
    rc = mv.cmd_update_secret(args, log)
    assert rc == 0
    assert called["tags_only"] == 1


def test_cmd_update_secret_value_push_mode_still_loads_value(
    mv, mock_oci, make_args, log, monkeypatch
):
    """When --secret-value is given, _load_secret_value IS called."""
    import oci  # type: ignore[import]

    loaded = {"calls": 0}

    def _spy_load(args_ns, log_arg):
        loaded["calls"] += 1
        return b"value", "cli"

    monkeypatch.setattr(mv, "_load_secret_value", _spy_load)

    class _Existing:
        id = "ocid1.secret.oc1..fake"
        secret_name = "test1"
        lifecycle_state = "ACTIVE"
        current_version_number = 1
        freeform_tags = {}

    monkeypatch.setattr(
        mv.common, "lookup_existing_secret", lambda *a, **kw: _Existing()
    )

    # Value-push mode references vaults_client.list_secret_versions when
    # passing it to common.list_all. The conftest mock client doesn't have
    # that attribute; patch a richer client onto VaultsClient and stub
    # list_all to short-circuit the actual enumeration.
    class _ClientWithVersions:
        def __init__(self, *a, **kw):
            pass

        def list_secret_versions(self, *a, **kw):
            return None

    monkeypatch.setattr(oci.vault, "VaultsClient", _ClientWithVersions, raising=False)
    monkeypatch.setattr(mv.common, "list_all", lambda *a, **kw: [])

    args = make_args(
        subcommand="update-secret",
        secret_name="test1",
        secret_value="newval",
        add_tags=None,
        remove_tags=None,
        set_tags=None,
        dry_run=True,
    )
    rc = mv.cmd_update_secret(args, log)
    # dry-run value-push returns 0 after logging
    assert rc == 0
    assert loaded["calls"] == 1
