"""Tests for list-secrets helpers in gywadmin_oci.manage_vault.

Updated to match the simplified 3-column shape (Name | Lifecycle | Tags).
The Versions column was removed, and per-secret get_secret /
list_secret_versions calls were eliminated; rows are built directly from
list_secrets summaries.
"""

import json
import pytest
from unittest.mock import MagicMock


def test_render_lifecycle_cell(mv):
    assert mv._render_lifecycle_cell("ACTIVE") == ""
    assert mv._render_lifecycle_cell("PENDING_DELETION") == "PENDING_DELETION"


def test_render_freeform_tags_kv(mv):
    assert mv._render_freeform_tags_kv({}) == ""
    assert mv._render_freeform_tags_kv({"b": "2", "a": "1"}) == "a=1, b=2"


def test_list_secrets_rows(mv, common, log, monkeypatch):
    """Rows are built directly from summaries; no per-secret API call."""
    client = MagicMock()

    def make_summary(name, lc, **extra):
        s = MagicMock()
        s.secret_name = name
        s.id = f"id-{name}"
        s.lifecycle_state = lc
        s.freeform_tags = extra.get("freeform_tags")
        s.defined_tags = extra.get("defined_tags")
        s.system_tags = extra.get("system_tags")
        return s

    summaries = [
        make_summary(
            "b-secret",
            "ACTIVE",
            freeform_tags={"env": "prod"},
            defined_tags={"ns": {"k": "v"}},
            system_tags={},
        ),
        make_summary(
            "a-secret",
            "PENDING_DELETION",
            freeform_tags=None,
            defined_tags=None,
            system_tags=None,
        ),
    ]

    def mock_list_all(func, **kwargs):
        assert func == client.list_secrets
        return summaries

    monkeypatch.setattr(common, "list_all", mock_list_all)

    rows = mv._list_secrets_rows(client, "comp_id", "vault_id", None, log)

    assert len(rows) == 2
    # Sorted ascending by name
    assert rows[0]["name"] == "a-secret"
    assert rows[1]["name"] == "b-secret"

    # Row 0
    assert rows[0]["id"] == "id-a-secret"
    assert rows[0]["lifecycle_state"] == "PENDING_DELETION"
    assert rows[0]["freeform_tags"] == {}
    assert rows[0]["defined_tags"] == {}
    assert rows[0]["system_tags"] == {}

    # Row 1
    assert rows[1]["id"] == "id-b-secret"
    assert rows[1]["lifecycle_state"] == "ACTIVE"
    assert rows[1]["freeform_tags"] == {"env": "prod"}
    assert rows[1]["defined_tags"] == {"ns": {"k": "v"}}
    assert rows[1]["system_tags"] == {}

    # Per-secret APIs are NOT called.
    client.get_secret.assert_not_called()
    client.list_secret_versions.assert_not_called()


def test_list_secrets_rows_name_prefix(mv, common, log, monkeypatch):
    client = MagicMock()

    def mock_list_all(func, **kwargs):
        if func == client.list_secrets:
            assert kwargs.get("name") == "foo"
            return []
        return []

    monkeypatch.setattr(common, "list_all", mock_list_all)

    mv._list_secrets_rows(client, "comp_id", "vault_id", "foo", log)


def test_print_table_empty(mv, capsys):
    mv._print_table([])
    captured = capsys.readouterr()
    lines = captured.out.splitlines()
    assert len(lines) == 2
    assert "Name" in lines[0]
    assert "Lifecycle" in lines[0]
    assert "Tags" in lines[0]
    # Versions column is gone.
    assert "Versions" not in lines[0]
    assert set(lines[1]) == {"-", " "}  # separator


def test_print_table_data(mv, capsys):
    rows = [
        {
            "name": "a-secret",
            "id": "id1",
            "lifecycle_state": "PENDING_DELETION",
            "freeform_tags": {},
            "defined_tags": {"hidden": "yes"},
            "system_tags": {},
        },
        {
            "name": "b-secret",
            "id": "id2",
            "lifecycle_state": "ACTIVE",
            "freeform_tags": {"env": "prod", "app": "web"},
            "defined_tags": {},
            "system_tags": {},
        },
    ]
    mv._print_table(rows)
    captured = capsys.readouterr()
    lines = captured.out.splitlines()

    assert len(lines) == 4
    assert "Name" in lines[0]
    assert "Versions" not in lines[0]  # gone
    assert set(lines[1]) == {"-", " "}

    # Row 1 (a-secret)
    assert "a-secret" in lines[2]
    assert "PENDING_DELETION" in lines[2]
    assert "hidden" not in lines[2]  # defined_tags not shown in table

    # Row 2 (b-secret)
    assert "b-secret" in lines[3]
    assert "ACTIVE" not in lines[3]  # blanked for ACTIVE
    assert "app=web, env=prod" in lines[3]


def test_print_json(mv, capsys):
    rows = [
        {
            "name": "a-secret",
            "id": "id1",
            "lifecycle_state": "ACTIVE",
            "freeform_tags": {},
            "defined_tags": {},
            "system_tags": {},
        }
    ]
    mv._print_json(rows)
    captured = capsys.readouterr()

    data = json.loads(captured.out)
    assert len(data) == 1
    assert data[0]["name"] == "a-secret"
    assert data[0]["lifecycle_state"] == "ACTIVE"  # not blanked in JSON
    # current_version / total_versions are no longer in the payload.
    assert "current_version" not in data[0]
    assert "total_versions" not in data[0]
    assert "freeform_tags" in data[0]
    assert "defined_tags" in data[0]
    assert "system_tags" in data[0]


def test_cmd_list_secrets_empty(mv, mock_oci, make_args, log, monkeypatch):
    import oci

    class _FakeVaultsClient:
        def __init__(self, *a, **kw):
            pass

        def list_secrets(self, *a, **kw):
            pass

    monkeypatch.setattr(oci.vault, "VaultsClient", _FakeVaultsClient, raising=False)

    def mock_list_all(func, **kwargs):
        return []

    monkeypatch.setattr(mv.common, "list_all", mock_list_all)

    args = make_args(
        subcommand="list-secrets",
        name_prefix=None,
        output_format="table",
        dry_run=False,
    )
    rc = mv.cmd_list_secrets(args, log)
    assert rc == 0


def test_cmd_list_secrets_dry_run(mv, mock_oci, make_args, log, monkeypatch):
    import oci

    class _FakeVaultsClient:
        def __init__(self, *a, **kw):
            pass

        def list_secrets(self, *a, **kw):
            pass

    monkeypatch.setattr(oci.vault, "VaultsClient", _FakeVaultsClient, raising=False)

    called = False

    def mock_list_all(func, **kwargs):
        nonlocal called
        called = True
        return []

    monkeypatch.setattr(mv.common, "list_all", mock_list_all)

    args = make_args(
        subcommand="list-secrets", name_prefix=None, output_format="table", dry_run=True
    )
    rc = mv.cmd_list_secrets(args, log)
    assert rc == 0
    assert called is True  # dry-run still calls API (read-only)


def test_cmd_list_secrets_service_error(mv, mock_oci, make_args, log, monkeypatch):
    import oci

    class _FakeVaultsClient:
        def __init__(self, *a, **kw):
            pass

        def list_secrets(self, *a, **kw):
            pass

    monkeypatch.setattr(oci.vault, "VaultsClient", _FakeVaultsClient, raising=False)

    def mock_list_all(func, **kwargs):
        raise mv.ServiceError(
            status=500, code="InternalError", message="Boom", headers={}
        )

    monkeypatch.setattr(mv.common, "list_all", mock_list_all)

    args = make_args(
        subcommand="list-secrets",
        name_prefix=None,
        output_format="table",
        dry_run=False,
    )
    rc = mv.cmd_list_secrets(args, log)
    assert rc == 1


def test_cmd_list_secrets_not_found(mv, mock_oci, make_args, log, monkeypatch):
    def mock_lookup_compartment(*a, **kw):
        raise SystemExit(5)

    monkeypatch.setattr(mv.common, "lookup_compartment", mock_lookup_compartment)

    args = make_args(
        subcommand="list-secrets",
        name_prefix=None,
        output_format="table",
        dry_run=False,
    )
    with pytest.raises(SystemExit) as exc:
        mv.cmd_list_secrets(args, log)
    assert exc.value.code == 5
