"""Shared fixtures for the gywadmin_oci vault tests."""
from __future__ import annotations

import argparse
import logging
from typing import Any

import pytest


@pytest.fixture(scope="session")
def common():
    """The shared library module (``gywadmin_oci.common``)."""
    import gywadmin_oci.common as common

    return common


@pytest.fixture(scope="session")
def mv(common):  # noqa: ARG001 — common ensures the package is importable first
    """The ``gywadmin_oci.manage_vault`` module."""
    import gywadmin_oci.manage_vault as manage_vault

    return manage_vault


class FakeSecretSummary:
    """Stand-in for an ``oci.vault.models.SecretSummary``."""

    def __init__(
        self,
        name: str,
        lifecycle_state: str = "ACTIVE",
        secret_id: str | None = None,
    ) -> None:
        self.secret_name = name
        self.id = secret_id or f"ocid1.secret.oc1..fake_{name}"
        self.lifecycle_state = lifecycle_state


@pytest.fixture
def fake_secret_summary():
    """Factory for :class:`FakeSecretSummary` objects."""
    return FakeSecretSummary


@pytest.fixture
def mock_oci(monkeypatch, common):
    """Stub all side-effecting OCI helpers in ``gywadmin_oci.common``.

    Tests that drive ``cmd_add_secret`` / ``cmd_delete_secret`` reach the
    validation logic without making real OCI calls.  Returns a dict with
    spies so tests can assert on interactions.
    """
    spies: dict[str, Any] = {}

    def _stub_require_dependencies(*a, **kw):  # noqa: ANN002,ANN003
        return None

    def _stub_load_oci_config(*a, **kw):  # noqa: ANN002,ANN003
        return {"region": "us-fake-1"}

    def _stub_verify_oci_authenticated(*a, **kw):  # noqa: ANN002,ANN003
        return "ocid1.tenancy.oc1..fake"

    def _stub_lookup_compartment(*a, **kw):  # noqa: ANN002,ANN003
        return "ocid1.compartment.oc1..fake"

    def _stub_lookup_vault(*a, **kw):  # noqa: ANN002,ANN003
        return "ocid1.vault.oc1..fake", "https://fake-vault-endpoint"

    def _stub_list_all(*a, **kw):  # noqa: ANN002,ANN003
        # Default: one ACTIVE secret matching the requested name.
        name = kw.get("name") or "test-secret"
        return [FakeSecretSummary(name, "ACTIVE")]

    monkeypatch.setattr(common, "require_dependencies", _stub_require_dependencies)
    monkeypatch.setattr(common, "load_oci_config", _stub_load_oci_config)
    monkeypatch.setattr(common, "verify_oci_authenticated", _stub_verify_oci_authenticated)
    monkeypatch.setattr(common, "lookup_compartment", _stub_lookup_compartment)
    monkeypatch.setattr(common, "lookup_vault", _stub_lookup_vault)
    monkeypatch.setattr(common, "list_all", _stub_list_all)

    # Stub OCI client constructors so module-level attribute access works.
    # The ``oci`` package uses a custom ``__getattr__`` on the top-level module
    # to lazily load submodules; ``import oci.identity`` does NOT work because
    # there is no ``oci/identity.py`` on disk.  We must trigger the lazy load
    # via attribute access first, which registers the submodule in
    # ``sys.modules`` and makes it patchable.
    import oci  # type: ignore[import]

    # Trigger lazy loading of each submodule.  We use getattr() rather than
    # bare attribute access to avoid pyflakes "assigned but never used" warnings
    # on the intermediate references.
    getattr(oci, "identity")
    getattr(oci, "key_management")
    getattr(oci, "vault")

    class _MockClient:
        """Minimal stub for any OCI service client.

        Provides no-op stubs for every method that ``cmd_delete_secret`` or
        ``cmd_add_secret`` accesses on a client instance.  The real work is
        intercepted at the ``common.*`` helper level (stubbed above), so these
        methods are never actually called — but the attribute access that
        happens when building the argument list for ``common.list_all`` must
        not raise ``AttributeError``.
        """

        def __init__(self, *a, **kw) -> None:  # noqa: ANN002,ANN003
            pass

        def list_secrets(self, *a, **kw):  # noqa: ANN002,ANN003,ANN201
            """Never called; common.list_all is stubbed above."""

        def get_secret(self, *a, **kw):  # noqa: ANN002,ANN003,ANN201
            """Never called in the stubbed path."""

        def create_secret(self, *a, **kw):  # noqa: ANN002,ANN003,ANN201
            """Never called in the stubbed path."""

        def update_secret(self, *a, **kw):  # noqa: ANN002,ANN003,ANN201
            """Never called in the stubbed path."""

        def schedule_secret_deletion(self, *a, **kw):  # noqa: ANN002,ANN003,ANN201
            """Never called in the stubbed path."""

        def list_vaults(self, *a, **kw):  # noqa: ANN002,ANN003,ANN201
            """Never called; common.lookup_vault is stubbed above."""

        def list_compartments(self, *a, **kw):  # noqa: ANN002,ANN003,ANN201
            """Never called; common.lookup_compartment is stubbed above."""

    monkeypatch.setattr(oci.identity, "IdentityClient", _MockClient, raising=False)
    monkeypatch.setattr(oci.key_management, "KmsVaultClient", _MockClient, raising=False)
    monkeypatch.setattr(oci.vault, "VaultsClient", _MockClient, raising=False)

    # Spy on prompt_destructive_confirm so tests can detect whether it was called.
    confirm_calls: list[dict[str, Any]] = []

    def _spy_confirm(*a, **kw):  # noqa: ANN002,ANN003
        confirm_calls.append({"args": a, "kwargs": kw})
        # Behave as if the user confirmed (--yes path).
        return None

    monkeypatch.setattr(common, "prompt_destructive_confirm", _spy_confirm)
    spies["confirm_calls"] = confirm_calls

    return spies


@pytest.fixture
def make_args():
    """Factory: build an ``argparse.Namespace`` with all fields that
    ``cmd_delete_secret`` / ``cmd_add_secret`` expect.
    """

    def _make(**overrides):  # noqa: ANN001,ANN202
        defaults = {
            "secret_name": "test-secret",
            "secret_value": "test-value",
            "dry_run": True,
            "oci_config_file": "fake",
            "oci_profile": "DEFAULT",
            "region": None,
            "vault_compartment_name": "cpm_automation",
            "vault_name": "vault_automation",
            "days": 0,
            "time_of_deletion": None,
            "yes": True,
            "wait_seconds": 1,
            "interval_seconds": 1,
            "verbose": 0,
        }
        defaults.update(overrides)
        return argparse.Namespace(**defaults)

    return _make


@pytest.fixture
def log():
    """A logger configured for capture during tests."""
    logger = logging.getLogger("test")
    logger.setLevel(logging.DEBUG)
    return logger
