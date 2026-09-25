"""Tests for KMS master-encryption-key selection."""

from __future__ import annotations

import logging
from types import SimpleNamespace

import pytest


class _FakeKmsManagementClient:
    """Minimal client whose method is passed to ``common.list_all``."""

    def list_keys(self, **kwargs):  # noqa: ANN003, ANN201
        raise AssertionError("common.list_all should provide the test keys")


def _key(name: str, state: str = "ENABLED", key_id: str | None = None):
    """Build a minimal OCI key summary stand-in."""
    return SimpleNamespace(
        display_name=name,
        lifecycle_state=state,
        id=key_id or f"ocid1.key.oc1..{name}-{state}",
    )


def _resolve(common, monkeypatch, keys, *, mek_name=None):  # noqa: ANN001
    """Resolve a test key list through the public helper."""
    client = _FakeKmsManagementClient()
    monkeypatch.setattr(
        common,
        "oci",
        SimpleNamespace(
            key_management=SimpleNamespace(KmsManagementClient=object),
        ),
    )
    monkeypatch.setattr(common, "make_client", lambda *args, **kwargs: client)
    monkeypatch.setattr(common, "list_all", lambda *args, **kwargs: keys)
    return common.auto_pick_mek(
        {"region": "us-fake-1"},
        "ocid1.compartment.oc1..test",
        "https://kms.example.test",
        "vault_automation",
        logging.getLogger("test_mek_selection"),
        mek_name=mek_name,
    )


def test_legacy_selection_uses_the_only_enabled_key(common, monkeypatch):
    """The five-argument helper contract remains compatible."""
    key = _key("only-key")
    result = _resolve(common, monkeypatch, [key])
    assert result == (key.id, "only-key")


def test_legacy_selection_rejects_multiple_enabled_keys(common, monkeypatch, caplog):
    """Unnamed selection retains the prior fail-closed ambiguity behavior."""
    with caplog.at_level(logging.ERROR):
        with pytest.raises(SystemExit) as exc:
            _resolve(common, monkeypatch, [_key("one"), _key("two")])

    assert exc.value.code == 6
    assert "auto-pick is ambiguous" in caplog.text


def test_named_selection_uses_default_among_multiple_enabled_keys(common, monkeypatch):
    """The automation MEK is selected even when the unseal key remains enabled."""
    automation = _key("mek_automation")
    result = _resolve(
        common,
        monkeypatch,
        [_key("k8s_01_openbao_unseal"), automation],
        mek_name="mek_automation",
    )
    assert result == (automation.id, "mek_automation")


def test_named_selection_uses_explicit_override(common, monkeypatch):
    """A caller can intentionally select a different enabled key by name."""
    alternate = _key("application_mek")
    result = _resolve(
        common,
        monkeypatch,
        [_key("mek_automation"), alternate],
        mek_name="application_mek",
    )
    assert result == (alternate.id, "application_mek")


def test_named_selection_rejects_missing_key(common, monkeypatch, caplog):
    """A differently named enabled key is never used as a fallback."""
    with caplog.at_level(logging.ERROR):
        with pytest.raises(SystemExit) as exc:
            _resolve(
                common,
                monkeypatch,
                [_key("k8s_01_openbao_unseal")],
                mek_name="mek_automation",
            )

    assert exc.value.code == 6
    assert "has no key named 'mek_automation'" in caplog.text


def test_named_selection_is_case_sensitive(common, monkeypatch):
    """OCI key display-name selection does not silently normalize case."""
    with pytest.raises(SystemExit) as exc:
        _resolve(
            common,
            monkeypatch,
            [_key("mek_automation")],
            mek_name="MEK_AUTOMATION",
        )

    assert exc.value.code == 6


@pytest.mark.parametrize("state", ["DISABLED", "CREATING"])
def test_named_selection_rejects_non_enabled_key(common, monkeypatch, caplog, state):
    """A matching key must be enabled before it can encrypt a new secret."""
    with caplog.at_level(logging.ERROR):
        with pytest.raises(SystemExit) as exc:
            _resolve(
                common,
                monkeypatch,
                [_key("mek_automation", state)],
                mek_name="mek_automation",
            )

    assert exc.value.code == 6
    assert f"lifecycle state(s): {state}" in caplog.text


def test_named_selection_rejects_duplicate_enabled_names(common, monkeypatch, caplog):
    """OCI display-name duplicates cannot silently select an arbitrary key."""
    with caplog.at_level(logging.ERROR):
        with pytest.raises(SystemExit) as exc:
            _resolve(
                common,
                monkeypatch,
                [
                    _key("mek_automation", key_id="ocid1.key.oc1..one"),
                    _key("mek_automation", key_id="ocid1.key.oc1..two"),
                ],
                mek_name="mek_automation",
            )

    assert exc.value.code == 6
    assert "2 ENABLED keys named 'mek_automation'" in caplog.text


def test_named_selection_ignores_disabled_duplicate(common, monkeypatch):
    """One enabled match remains valid when an identically named key is disabled."""
    enabled = _key("mek_automation", key_id="ocid1.key.oc1..enabled")
    result = _resolve(
        common,
        monkeypatch,
        [_key("mek_automation", "DISABLED"), enabled],
        mek_name="mek_automation",
    )
    assert result == (enabled.id, "mek_automation")


def test_named_selection_uses_all_keys_returned_by_list_all(common, monkeypatch):
    """Selection considers the complete paginated result supplied by list_all."""
    automation = _key("mek_automation")
    result = _resolve(
        common,
        monkeypatch,
        [_key("k8s_01_openbao_unseal"), automation],
        mek_name="mek_automation",
    )
    assert result == (automation.id, "mek_automation")
