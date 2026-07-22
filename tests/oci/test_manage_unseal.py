"""Tests for gywadmin_oci.manage_unseal.

Coverage areas
--------------
A. Cluster-name normalisation (valid and invalid inputs).
B. Name derivation (exact resource-name convention for k8s_01).
C. Unencrypted API key generation and OCI fingerprint computation.
D. CLI parsing: required ``--cluster-name`` flag, subcommand wiring.
E. Policy statement exactness.
F. Idempotent ``create`` skip vs forced ``rotate``.
G. Dry-run makes no mutations.
H. API key cap handling (exit 5 without flag; deletion with flag).
I. Invalid cluster-name exit-6 gate.
J. Check create complete (idempotency logic).
K. Private key never logged.
L. fingerprint_from_private_pem helper (common.py).
M. Strengthened _check_create_complete (private key validation).
N. Cap safety: protected fingerprint never deleted.
O. Summary-file compartment.name used for policy scope.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
from typing import Any
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Module fixtures
# ---------------------------------------------------------------------------
@pytest.fixture(scope="session")
def mu():
    """The ``gywadmin_oci.manage_unseal`` module."""
    import gywadmin_oci.manage_unseal as manage_unseal

    return manage_unseal


@pytest.fixture(scope="session")
def common_mod():
    """The ``gywadmin_oci.common`` module."""
    import gywadmin_oci.common as common

    return common


# ---------------------------------------------------------------------------
# A. Cluster-name normalisation
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "raw, expected",
    [
        ("k8s-01", "k8s_01"),
        ("K8S-01", "k8s_01"),
        ("  k8s-01  ", "k8s_01"),
        ("k8s--01", "k8s_01"),
        ("k8s___01", "k8s_01"),
        ("-k8s-01-", "k8s_01"),
        ("prod", "prod"),
        ("a" * 40, "a" * 40),  # exactly 40 chars — allowed
        ("abc_def_ghi", "abc_def_ghi"),
    ],
)
def test_normalize_cluster_name_valid(mu, raw, expected):
    """Valid inputs are normalised to the expected identifier."""
    assert mu.normalize_cluster_name(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",  # empty after strip
        "   ",  # whitespace-only → empty after strip
        "-",  # collapses to empty after underscore conversion
        "___",  # all underscores/dashes → collapses to empty
        "1cluster",  # starts with digit (stays invalid)
        "9" + "a" * 39,  # starts with digit, max-length irrelevant
        "a" * 41,  # too long (41 chars after normalisation)
        "abc def",  # internal space → does not match ^[a-z][a-z0-9_]*$
        "abc!def",  # special character → does not match pattern
    ],
)
def test_normalize_cluster_name_invalid(mu, raw):
    """Invalid inputs raise ``ValueError``."""
    with pytest.raises(ValueError):
        mu.normalize_cluster_name(raw)


def test_normalize_cluster_name_underscore_prefix_becomes_valid(mu):
    """Leading underscores are stripped; if what remains is valid, it's accepted."""
    # _k8s_01 → strip leading _ → k8s_01 (valid)
    assert mu.normalize_cluster_name("_k8s_01") == "k8s_01"


def test_normalize_cluster_name_logs_mapping_when_changed(mu):
    """Raw-to-normalised mapping is logged at INFO when the value changes.

    The logging happens inside the subcommand handlers (cmd_create, etc.),
    not inside normalize_cluster_name itself; verify the function returns the
    expected value here.
    """
    result = mu.normalize_cluster_name("k8s-01")
    assert result == "k8s_01"


def test_normalize_cluster_name_max_length_exactly_40(mu):
    """A normalised name of exactly 40 characters is accepted."""
    name = "a" * 40
    assert mu.normalize_cluster_name(name) == name


def test_normalize_cluster_name_too_long_41(mu):
    """A normalised name of 41 characters is rejected."""
    with pytest.raises(ValueError, match="40"):
        mu.normalize_cluster_name("a" * 41)


# ---------------------------------------------------------------------------
# B. Name derivation
# ---------------------------------------------------------------------------
def test_derive_names_k8s_01(mu):
    """Exact resource-name convention for the canonical example cluster 'k8s_01'."""
    names = mu.derive_names("k8s_01")
    assert names.cluster_id == "k8s_01"
    assert names.kms_key == "k8s_01_openbao_unseal"
    assert names.user == "sa_k8s_01_openbao_unseal"
    assert names.group == "grp_k8s_01_openbao_unseal"
    assert names.policy == "policy_k8s_01_openbao_unseal"
    assert names.secret_credential == "k8s_01_openbao_unseal_credential"


def test_derive_names_raw_input_normalised_first(mu):
    """Inputs normalising to the same ID target the same resources."""
    names_a = mu.derive_names(mu.normalize_cluster_name("k8s-01"))
    names_b = mu.derive_names(mu.normalize_cluster_name("K8S-01"))
    names_c = mu.derive_names(mu.normalize_cluster_name("  k8s-01  "))
    assert names_a == names_b == names_c


def test_derive_names_prefix_pattern(mu):
    """All names follow the expected prefix/suffix convention."""
    names = mu.derive_names("prod")
    base = "prod_openbao_unseal"
    assert names.kms_key == base
    assert names.user == f"sa_{base}"
    assert names.group == f"grp_{base}"
    assert names.policy == f"policy_{base}"
    assert names.secret_credential == f"{base}_credential"


# ---------------------------------------------------------------------------
# C. Unencrypted API key generation and fingerprint
# ---------------------------------------------------------------------------
def test_generate_unencrypted_api_key_returns_required_keys(common_mod):
    """``generate_unencrypted_rsa_api_key`` returns all four expected keys."""
    keypair = common_mod.generate_unencrypted_rsa_api_key(2048)  # 2048 for speed
    assert "private_pem" in keypair
    assert "public_pem" in keypair
    assert "public_der" in keypair
    assert "fingerprint" in keypair


def test_generate_unencrypted_api_key_pem_is_unencrypted(common_mod):
    """Private PEM must NOT contain 'ENCRYPTED' (i.e. no passphrase)."""
    keypair = common_mod.generate_unencrypted_rsa_api_key(2048)
    assert "ENCRYPTED" not in keypair["private_pem"], (
        "Private key PEM unexpectedly contains 'ENCRYPTED'; "
        "manage-unseal requires NoEncryption()."
    )
    assert "BEGIN PRIVATE KEY" in keypair["private_pem"]


def test_generate_unencrypted_api_key_private_not_logged(common_mod, caplog):
    """Private key material must not appear in any log record."""
    with caplog.at_level(logging.DEBUG):
        keypair = common_mod.generate_unencrypted_rsa_api_key(2048)

    priv = keypair["private_pem"]
    for record in caplog.records:
        assert priv not in record.getMessage(), (
            f"Private key leaked into log: {record.getMessage()[:60]!r}"
        )


def test_compute_oci_fingerprint_format(common_mod):
    """Fingerprint is 16 colon-separated lowercase hex pairs (32 nibbles total)."""
    keypair = common_mod.generate_unencrypted_rsa_api_key(2048)
    fp = keypair["fingerprint"]
    parts = fp.split(":")
    assert len(parts) == 16, f"Expected 16 parts, got {len(parts)}: {fp!r}"
    for part in parts:
        assert len(part) == 2, f"Part {part!r} is not 2 hex chars"
        assert all(c in "0123456789abcdef" for c in part), (
            f"Non-hex character in part {part!r}"
        )


def test_compute_oci_fingerprint_matches_md5(common_mod):
    """Fingerprint must equal the colon-separated MD5 of the DER public key."""
    keypair = common_mod.generate_unencrypted_rsa_api_key(2048)
    der = keypair["public_der"]
    expected_digest = hashlib.md5(der).hexdigest()
    expected_fp = ":".join(expected_digest[i : i + 2] for i in range(0, 32, 2))
    assert keypair["fingerprint"] == expected_fp


# ---------------------------------------------------------------------------
# D. CLI parsing
# ---------------------------------------------------------------------------
def test_cli_create_requires_cluster_name(mu):
    """``create`` without ``--cluster-name`` exits with code 2 (argparse error)."""
    with pytest.raises(SystemExit) as exc:
        mu.parse_args(["create"])
    assert exc.value.code == 2


def test_cli_rotate_requires_cluster_name(mu):
    """``rotate`` without ``--cluster-name`` exits with code 2."""
    with pytest.raises(SystemExit) as exc:
        mu.parse_args(["rotate"])
    assert exc.value.code == 2


def test_cli_show_requires_cluster_name(mu):
    """``show`` without ``--cluster-name`` exits with code 2."""
    with pytest.raises(SystemExit) as exc:
        mu.parse_args(["show"])
    assert exc.value.code == 2


def test_cli_create_parses_cluster_name(mu):
    """``create --cluster-name k8s-01`` parses without error."""
    args = mu.parse_args(["create", "--cluster-name", "k8s-01"])
    assert args.cluster_name == "k8s-01"
    assert args.subcommand == "create"


def test_cli_rotate_parses_cluster_name(mu):
    """``rotate --cluster-name k8s-01`` parses without error."""
    args = mu.parse_args(["rotate", "--cluster-name", "k8s-01"])
    assert args.cluster_name == "k8s-01"
    assert args.subcommand == "rotate"


def test_cli_show_parses_cluster_name(mu):
    """``show --cluster-name k8s-01`` parses without error."""
    args = mu.parse_args(["show", "--cluster-name", "k8s-01"])
    assert args.cluster_name == "k8s-01"
    assert args.subcommand == "show"


def test_cli_defaults(mu):
    """Default flag values match documented defaults."""
    args = mu.parse_args(["create", "--cluster-name", "c"])
    assert args.compartment == mu.DEFAULT_COMPARTMENT
    assert args.vault_name == mu.DEFAULT_VAULT_NAME
    assert args.mek_name == mu.DEFAULT_MEK_NAME
    assert args.oci_profile == mu.DEFAULT_OCI_PROFILE
    assert args.dry_run is False
    assert args.delete_old_api_key is False
    assert args.wait_seconds == mu.DEFAULT_WAIT_SECONDS
    assert args.interval_seconds == mu.DEFAULT_INTERVAL_SECONDS
    assert args.summary_file is None
    assert args.region is None


def test_cli_delete_old_api_key_flag_create(mu):
    """``--delete-old-api-key`` is accepted on ``create``."""
    args = mu.parse_args(["create", "--cluster-name", "c", "--delete-old-api-key"])
    assert args.delete_old_api_key is True


def test_cli_delete_old_api_key_flag_rotate(mu):
    """``--delete-old-api-key`` is accepted on ``rotate``."""
    args = mu.parse_args(["rotate", "--cluster-name", "c", "--delete-old-api-key"])
    assert args.delete_old_api_key is True


def test_cli_dry_run_flag(mu):
    """``--dry-run`` is accepted on all subcommands."""
    for subcmd in ("create", "rotate", "show"):
        args = mu.parse_args([subcmd, "--cluster-name", "c", "--dry-run"])
        assert args.dry_run is True, f"dry_run not True for subcommand {subcmd!r}"


def test_cli_summary_file_resolves_to_path(mu, tmp_path):
    """``-f`` yields a resolved ``pathlib.Path``."""
    dummy = tmp_path / "summary.json"
    dummy.touch()
    args = mu.parse_args(["create", "--cluster-name", "c", "-f", str(dummy)])
    from pathlib import Path

    assert isinstance(args.summary_file, Path)
    assert args.summary_file.name == "summary.json"


# ---------------------------------------------------------------------------
# E. Policy statement exactness
# ---------------------------------------------------------------------------
def test_policy_statement_format(mu):
    """Policy statement contains group, compartment name, and key OCID."""
    stmt = mu._unseal_policy_statement(
        "grp_k8s_01_openbao_unseal",
        "cpm_automation",
        "ocid1.key.oc1..aaaaaa",
    )
    assert "Allow group grp_k8s_01_openbao_unseal" in stmt
    assert "use keys" in stmt
    assert "compartment cpm_automation" in stmt
    assert "target.key.id = 'ocid1.key.oc1..aaaaaa'" in stmt
    # Must NOT grant broader permissions.
    assert "manage" not in stmt.lower()
    assert "secret" not in stmt.lower()
    assert "vault" not in stmt.lower()
    assert "bucket" not in stmt.lower()


def test_policy_statement_exact_text(mu):
    """Policy statement must exactly match the specified format."""
    stmt = mu._unseal_policy_statement(
        "grp_k8s_01_openbao_unseal",
        "cpm_automation",
        "ocid1.key.oc1..fake",
    )
    expected = (
        "Allow group grp_k8s_01_openbao_unseal to use keys in compartment "
        "cpm_automation where target.key.id = 'ocid1.key.oc1..fake'"
    )
    assert stmt == expected


def test_ensure_unseal_policy_creates_with_one_statement(mu):
    """``_ensure_unseal_policy`` calls ``create_policy`` with exactly one statement."""
    identity_client = MagicMock()
    identity_client.list_policies.return_value = MagicMock(data=[])
    created_policy = MagicMock()
    created_policy.id = "ocid1.policy.oc1..new"
    identity_client.create_policy.return_value = MagicMock(data=created_policy)

    log = logging.getLogger("test_policy")

    # Stub list_all (no existing policy) and wait_for_state (new policy becomes ACTIVE).
    with (
        patch.object(mu.common, "list_all", return_value=[]),
        patch.object(mu.common, "wait_for_state", return_value=created_policy),
    ):
        policy_ocid = mu._ensure_unseal_policy(
            identity_client,
            "ocid1.tenancy.oc1..fake",
            "policy_k8s_01_openbao_unseal",
            "grp_k8s_01_openbao_unseal",
            "cpm_automation",
            "ocid1.key.oc1..fake",
            dry_run=False,
            log=log,
        )

    assert policy_ocid == "ocid1.policy.oc1..new"
    identity_client.create_policy.assert_called_once()
    call_kwargs = identity_client.create_policy.call_args[0][0]
    stmts = call_kwargs.statements
    assert len(stmts) == 1, f"Expected 1 statement, got {len(stmts)}: {stmts}"
    assert "use keys" in stmts[0]
    assert "target.key.id" in stmts[0]


def test_ensure_unseal_policy_updates_to_exactly_one_if_wrong(mu):
    """If the policy has wrong statements, it is updated to exactly the one correct statement."""
    fake_policy = MagicMock()
    fake_policy.name = "policy_k8s_01_openbao_unseal"
    fake_policy.id = "ocid1.policy.oc1..existing"
    fake_policy.lifecycle_state = "ACTIVE"
    fake_policy.statements = ["Allow group X to manage all-resources in tenancy"]
    fake_policy.description = "old description"

    identity_client = MagicMock()
    log = logging.getLogger("test_policy_update")

    # wait_for_state is called after the update; return the (now-ACTIVE) policy model.
    with (
        patch.object(mu.common, "list_all", return_value=[fake_policy]),
        patch.object(mu.common, "wait_for_state", return_value=fake_policy),
    ):
        mu._ensure_unseal_policy(
            identity_client,
            "ocid1.tenancy.oc1..fake",
            "policy_k8s_01_openbao_unseal",
            "grp_k8s_01_openbao_unseal",
            "cpm_automation",
            "ocid1.key.oc1..fake",
            dry_run=False,
            log=log,
        )

    identity_client.update_policy.assert_called_once()
    update_details = identity_client.update_policy.call_args[0][1]
    assert len(update_details.statements) == 1
    assert "use keys" in update_details.statements[0]
    assert "target.key.id = 'ocid1.key.oc1..fake'" in update_details.statements[0]


def test_ensure_unseal_policy_noop_when_correct(mu):
    """No mutation when the policy already has exactly the one correct statement."""
    key_ocid = "ocid1.key.oc1..fake"
    expected_stmt = mu._unseal_policy_statement(
        "grp_k8s_01_openbao_unseal", "cpm_automation", key_ocid
    )
    fake_policy = MagicMock()
    fake_policy.name = "policy_k8s_01_openbao_unseal"
    fake_policy.id = "ocid1.policy.oc1..existing"
    fake_policy.lifecycle_state = "ACTIVE"
    fake_policy.statements = [expected_stmt]

    identity_client = MagicMock()
    log = logging.getLogger("test_policy_noop")

    with patch.object(mu.common, "list_all", return_value=[fake_policy]):
        result = mu._ensure_unseal_policy(
            identity_client,
            "ocid1.tenancy.oc1..fake",
            "policy_k8s_01_openbao_unseal",
            "grp_k8s_01_openbao_unseal",
            "cpm_automation",
            key_ocid,
            dry_run=False,
            log=log,
        )

    assert result == "ocid1.policy.oc1..existing"
    identity_client.create_policy.assert_not_called()
    identity_client.update_policy.assert_not_called()


# ---------------------------------------------------------------------------
# F. Idempotent create skip vs forced rotate
# ---------------------------------------------------------------------------
def _make_unseal_args(**overrides: Any) -> argparse.Namespace:
    """Build a minimal ``argparse.Namespace`` for manage-unseal subcommands."""
    defaults = {
        "cluster_name": "k8s-01",
        "compartment": "cpm_automation",
        "vault_name": "vault_automation",
        "mek_name": "mek_automation",
        "oci_config_file": "~/.oci/config",
        "oci_profile": "DEFAULT",
        "region": None,
        "summary_file": None,
        "verbose": 0,
        "dry_run": True,
        "wait_seconds": 1,
        "interval_seconds": 1,
        "delete_old_api_key": False,
    }
    defaults.update(overrides)
    # Resolve Path so _resolve_infra doesn't fail on type check.
    from pathlib import Path

    defaults["oci_config_file"] = Path(defaults["oci_config_file"]).expanduser()
    return argparse.Namespace(**defaults)


@pytest.fixture
def mock_unseal_oci(monkeypatch, mu):
    """Patch all OCI side-effects in manage_unseal so unit tests run without OCI."""
    import gywadmin_oci.common as common

    # Stub OCI dependency checks and authentication.
    monkeypatch.setattr(common, "require_dependencies", lambda *a, **kw: None)
    monkeypatch.setattr(common, "load_oci_config", lambda **kw: {"region": "us-fake-1"})
    monkeypatch.setattr(
        common,
        "verify_oci_authenticated",
        lambda *a, **kw: "ocid1.tenancy.oc1..fake",
    )
    monkeypatch.setattr(
        common, "lookup_compartment", lambda *a, **kw: "ocid1.compartment.oc1..fake"
    )
    monkeypatch.setattr(
        common,
        "lookup_vault",
        lambda *a, **kw: ("ocid1.vault.oc1..fake", "https://vault-mgmt.fake"),
    )
    monkeypatch.setattr(common, "list_all", lambda *a, **kw: [])

    # Stub OCI client constructors.
    import oci  # type: ignore[import]

    getattr(oci, "identity")
    getattr(oci, "key_management")
    getattr(oci, "vault")
    getattr(oci, "secrets")

    class _MockClient:
        def __init__(self, *a, **kw) -> None:
            pass

        def list_keys(self, **kw):  # noqa: ANN201
            pass  # common.list_all is stubbed

        def get_key(self, *a, **kw):  # noqa: ANN201
            pass  # returns None; cmd_show guards with kms_key_ocid is not None

        def list_secrets(self, **kw):  # noqa: ANN201
            pass

        def get_secret(self, *a, **kw):  # noqa: ANN201
            pass

        def create_secret(self, *a, **kw):  # noqa: ANN201
            pass

        def update_secret(self, *a, **kw):  # noqa: ANN201
            pass

        def list_users(self, **kw):  # noqa: ANN201
            pass

        def list_groups(self, **kw):  # noqa: ANN201
            pass

        def list_policies(self, **kw):  # noqa: ANN201
            pass

        def list_api_keys(self, **kw):  # noqa: ANN201
            pass

        def list_user_group_memberships(self, **kw):  # noqa: ANN201
            pass

        def upload_api_key(self, *a, **kw):  # noqa: ANN201
            pass

        def delete_api_key(self, **kw):  # noqa: ANN201
            pass

        def create_user(self, *a, **kw):  # noqa: ANN201
            pass

        def create_group(self, *a, **kw):  # noqa: ANN201
            pass

        def add_user_to_group(self, *a, **kw):  # noqa: ANN201
            pass

        def create_policy(self, *a, **kw):  # noqa: ANN201
            pass

        def update_policy(self, *a, **kw):  # noqa: ANN201
            pass

        def get_secret_bundle(self, **kw):  # noqa: ANN201
            pass

    for attr in ("IdentityClient",):
        monkeypatch.setattr(oci.identity, attr, _MockClient, raising=False)
    for attr in ("KmsVaultClient", "KmsManagementClient"):
        monkeypatch.setattr(oci.key_management, attr, _MockClient, raising=False)
    for attr in ("VaultsClient",):
        monkeypatch.setattr(oci.vault, attr, _MockClient, raising=False)
    for attr in ("SecretsClient",):
        monkeypatch.setattr(oci.secrets, attr, _MockClient, raising=False)

    # Stub _require_mek so it returns a fake OCID without hitting OCI.
    monkeypatch.setattr(
        mu,
        "_require_mek",
        lambda *a, **kw: "ocid1.key.oc1..mek_fake",
    )
    # Stub _ensure_unseal_kms_key to return a fake key OCID.
    monkeypatch.setattr(
        mu,
        "_ensure_unseal_kms_key",
        lambda *a, **kw: "ocid1.key.oc1..unseal_fake",
    )
    # Stub _ensure_unseal_user.
    monkeypatch.setattr(
        mu,
        "_ensure_unseal_user",
        lambda *a, **kw: "ocid1.user.oc1..unseal_fake",
    )
    # Stub _ensure_unseal_group.
    monkeypatch.setattr(
        mu,
        "_ensure_unseal_group",
        lambda *a, **kw: "ocid1.group.oc1..unseal_fake",
    )
    # Stub membership and policy (no-ops for now).
    monkeypatch.setattr(mu, "_ensure_unseal_membership", lambda *a, **kw: None)
    monkeypatch.setattr(
        mu,
        "_ensure_unseal_policy",
        lambda *a, **kw: "ocid1.policy.oc1..unseal_fake",
    )
    # Stub lookup_existing_secret to return None (no secrets by default).
    monkeypatch.setattr(common, "lookup_existing_secret", lambda *a, **kw: None)

    return {"monkeypatch": monkeypatch, "mu": mu, "common": common}


def test_create_idempotent_noop_when_complete(mu, mock_unseal_oci, monkeypatch):
    """``create`` exits 0 without mutations when idempotency check passes."""
    monkeypatch.setattr(mu, "_check_create_complete", lambda *a, **kw: True)

    log = logging.getLogger("test_create_idempotent")
    args = _make_unseal_args(dry_run=False)
    rc = mu.cmd_create(args, log)

    assert rc == 0


def test_create_not_complete_enters_provision_path(mu, mock_unseal_oci, monkeypatch):
    """When idempotency check fails and dry_run=True, the [DRY-RUN] path is taken."""
    completion_results = iter((False, True))
    monkeypatch.setattr(
        mu,
        "_check_create_complete",
        lambda *a, **kw: next(completion_results),
    )

    log = logging.getLogger("test_create_provision")
    args = _make_unseal_args(dry_run=True)
    rc = mu.cmd_create(args, log)

    assert rc == 0  # dry-run always returns 0


def test_rotate_skips_idempotency_check(mu, mock_unseal_oci, monkeypatch, caplog):
    """``rotate`` does NOT call ``_check_create_complete`` — it always rotates."""
    check_called = []
    monkeypatch.setattr(
        mu,
        "_check_create_complete",
        lambda *a, **kw: check_called.append(True) or False,
    )
    # Stub _read_secret_value (for old fingerprint lookup) to return None.
    monkeypatch.setattr(mu, "_read_secret_value", lambda *a, **kw: None)
    # Stub _handle_api_key_cap.
    monkeypatch.setattr(mu, "_handle_api_key_cap", lambda *a, **kw: None)

    log = logging.getLogger("test_rotate_no_idempotency")
    args = _make_unseal_args(dry_run=True)
    rc = mu.cmd_rotate(args, log)

    assert rc == 0
    assert check_called == [], (
        "_check_create_complete must not be called from cmd_rotate"
    )


# ---------------------------------------------------------------------------
# G. Dry-run makes no mutations
# ---------------------------------------------------------------------------
def test_create_dry_run_no_api_key_generation(mu, mock_unseal_oci, monkeypatch):
    """Dry-run ``create`` must not generate or upload an API key."""
    generate_calls: list = []
    monkeypatch.setattr(
        mu.common,
        "generate_unencrypted_rsa_api_key",
        lambda *a, **kw: generate_calls.append(True),
    )
    monkeypatch.setattr(mu, "_check_create_complete", lambda *a, **kw: False)

    log = logging.getLogger("test_create_dry_api_key")
    args = _make_unseal_args(dry_run=True)
    rc = mu.cmd_create(args, log)

    assert rc == 0
    assert generate_calls == [], (
        "generate_unencrypted_rsa_api_key must not be called in dry-run"
    )


def test_create_dry_run_no_secret_upsert(mu, mock_unseal_oci, monkeypatch):
    """Dry-run ``create`` must not call ``_upsert_vault_secret``."""
    upsert_calls: list = []
    monkeypatch.setattr(
        mu,
        "_upsert_vault_secret",
        lambda *a, **kw: upsert_calls.append(True),
    )
    monkeypatch.setattr(mu, "_check_create_complete", lambda *a, **kw: False)

    log = logging.getLogger("test_create_dry_secret")
    args = _make_unseal_args(dry_run=True)
    rc = mu.cmd_create(args, log)

    assert rc == 0
    assert upsert_calls == [], "_upsert_vault_secret must not be called in dry-run"


def test_rotate_dry_run_no_api_key_upload(mu, mock_unseal_oci, monkeypatch):
    """Dry-run ``rotate`` must not call ``_generate_and_upload_api_key``."""
    upload_calls: list = []
    monkeypatch.setattr(
        mu,
        "_generate_and_upload_api_key",
        lambda *a, **kw: upload_calls.append(True),
    )
    monkeypatch.setattr(mu, "_read_secret_value", lambda *a, **kw: None)
    monkeypatch.setattr(mu, "_handle_api_key_cap", lambda *a, **kw: None)

    log = logging.getLogger("test_rotate_dry_upload")
    args = _make_unseal_args(dry_run=True)
    rc = mu.cmd_rotate(args, log)

    assert rc == 0
    assert upload_calls == [], (
        "_generate_and_upload_api_key must not be called in dry-run"
    )


def test_rotate_dry_run_no_secret_upsert(mu, mock_unseal_oci, monkeypatch):
    """Dry-run ``rotate`` must not call ``_upsert_vault_secret``."""
    upsert_calls: list = []
    monkeypatch.setattr(
        mu,
        "_upsert_vault_secret",
        lambda *a, **kw: upsert_calls.append(True),
    )
    monkeypatch.setattr(mu, "_read_secret_value", lambda *a, **kw: None)
    monkeypatch.setattr(mu, "_handle_api_key_cap", lambda *a, **kw: None)

    log = logging.getLogger("test_rotate_dry_secret")
    args = _make_unseal_args(dry_run=True)
    rc = mu.cmd_rotate(args, log)

    assert rc == 0
    assert upsert_calls == [], "_upsert_vault_secret must not be called in dry-run"


def test_dry_run_log_lines_contain_dry_run_prefix(
    mu, mock_unseal_oci, monkeypatch, caplog
):
    """Dry-run actions emit at least one log line containing '[DRY-RUN]'."""
    monkeypatch.setattr(mu, "_check_create_complete", lambda *a, **kw: False)
    # Re-enable actual _ensure_unseal_kms_key (dry_run path logs [DRY-RUN]).
    monkeypatch.setattr(
        mu,
        "_ensure_unseal_kms_key",
        lambda *a, **kw: mu.common.dry_run_ocid("key"),
    )

    log = logging.getLogger("test_dry_run_lines")
    args = _make_unseal_args(dry_run=True)

    with caplog.at_level(logging.INFO):
        mu.cmd_create(args, log)

    dry_run_lines = [r for r in caplog.records if "[DRY-RUN]" in r.getMessage()]
    assert dry_run_lines, "Expected at least one [DRY-RUN] log line from dry-run create"


# ---------------------------------------------------------------------------
# H. API key cap handling
# ---------------------------------------------------------------------------
def _fake_key(fingerprint: str, time_created: str) -> Any:
    k = MagicMock()
    k.fingerprint = fingerprint
    k.time_created = time_created
    return k


def test_handle_api_key_cap_exit5_at_three_without_flag(mu):
    """Exit 5 when user has 3 API keys and --delete-old-api-key is False."""
    identity_client = MagicMock()
    log = logging.getLogger("test_cap_exit5")

    three_keys = [
        _fake_key("aa:bb:cc", "2024-01-01"),
        _fake_key("dd:ee:ff", "2024-02-01"),
        _fake_key("11:22:33", "2024-03-01"),
    ]

    with patch.object(mu.common, "list_all", return_value=three_keys):
        with pytest.raises(SystemExit) as exc:
            mu._handle_api_key_cap(
                identity_client,
                "ocid1.user.oc1..fake",
                delete_old_api_key=False,
                dry_run=False,
                log=log,
            )
    assert exc.value.code == mu._EXIT_RESOURCE_NOT_FOUND  # == 5


def test_handle_api_key_cap_deletes_oldest_with_flag(mu):
    """With --delete-old-api-key, the oldest key is deleted to make room."""
    identity_client = MagicMock()
    log = logging.getLogger("test_cap_delete")

    three_keys = [
        _fake_key("old:fp:aa", "2024-01-01"),  # oldest
        _fake_key("mid:fp:bb", "2024-06-01"),
        _fake_key("new:fp:cc", "2024-12-01"),
    ]

    with patch.object(mu.common, "list_all", return_value=three_keys):
        mu._handle_api_key_cap(
            identity_client,
            "ocid1.user.oc1..fake",
            delete_old_api_key=True,
            dry_run=False,
            log=log,
        )

    identity_client.delete_api_key.assert_called_once_with(
        user_id="ocid1.user.oc1..fake",
        fingerprint="old:fp:aa",
    )


def test_handle_api_key_cap_noop_below_three(mu):
    """No deletion when user has fewer than 3 API keys."""
    identity_client = MagicMock()
    log = logging.getLogger("test_cap_noop")

    two_keys = [_fake_key("aa:bb", "2024-01-01"), _fake_key("cc:dd", "2024-02-01")]

    with patch.object(mu.common, "list_all", return_value=two_keys):
        mu._handle_api_key_cap(
            identity_client,
            "ocid1.user.oc1..fake",
            delete_old_api_key=False,
            dry_run=False,
            log=log,
        )

    identity_client.delete_api_key.assert_not_called()


def test_handle_api_key_cap_dry_run_does_not_delete(mu):
    """With dry_run=True, the key is NOT deleted even when at cap with the flag."""
    identity_client = MagicMock()
    log = logging.getLogger("test_cap_dry_delete")

    three_keys = [
        _fake_key("old:fp:aa", "2024-01-01"),
        _fake_key("mid:fp:bb", "2024-06-01"),
        _fake_key("new:fp:cc", "2024-12-01"),
    ]

    with patch.object(mu.common, "list_all", return_value=three_keys):
        mu._handle_api_key_cap(
            identity_client,
            "ocid1.user.oc1..fake",
            delete_old_api_key=True,
            dry_run=True,
            log=log,
        )

    identity_client.delete_api_key.assert_not_called()


# ---------------------------------------------------------------------------
# I. Invalid cluster-name exit-6 gate
# ---------------------------------------------------------------------------
def test_cmd_create_invalid_cluster_name_exit6(mu, mock_unseal_oci):
    """``cmd_create`` with an invalid cluster name raises SystemExit(6)."""
    log = logging.getLogger("test_invalid_name_create")
    args = _make_unseal_args(cluster_name="1invalid-starts-with-digit", dry_run=True)
    with pytest.raises(SystemExit) as exc:
        mu.cmd_create(args, log)
    assert exc.value.code == mu._EXIT_INVALID_CLUSTER_NAME  # == 6


def test_cmd_rotate_invalid_cluster_name_exit6(mu, mock_unseal_oci):
    """``cmd_rotate`` with an invalid cluster name raises SystemExit(6)."""
    log = logging.getLogger("test_invalid_name_rotate")
    args = _make_unseal_args(cluster_name="1invalid", dry_run=True)
    with pytest.raises(SystemExit) as exc:
        mu.cmd_rotate(args, log)
    assert exc.value.code == mu._EXIT_INVALID_CLUSTER_NAME


def test_cmd_show_invalid_cluster_name_exit6(mu, mock_unseal_oci):
    """``cmd_show`` with an invalid cluster name raises SystemExit(6)."""
    log = logging.getLogger("test_invalid_name_show")
    args = _make_unseal_args(cluster_name="1invalid", dry_run=True)
    with pytest.raises(SystemExit) as exc:
        mu.cmd_show(args, log)
    assert exc.value.code == mu._EXIT_INVALID_CLUSTER_NAME


# ---------------------------------------------------------------------------
# J. Check create complete (idempotency logic)
# ---------------------------------------------------------------------------
def test_check_create_complete_false_when_credential_secret_missing(mu):
    """``_check_create_complete`` returns False when the credential secret is absent."""
    log = logging.getLogger("test_idem_missing")

    with patch.object(mu.common, "lookup_existing_secret", return_value=None):
        result = mu._check_create_complete(
            MagicMock(),  # vaults_client
            MagicMock(),  # secrets_client
            MagicMock(),  # identity_client
            "ocid1.compartment.oc1..fake",
            "ocid1.vault.oc1..fake",
            mu.derive_names("k8s_01"),
            "ocid1.user.oc1..fake",
            log,
        )
    assert result is False


def test_check_create_complete_false_when_credential_secret_is_not_active(mu):
    """A present but CREATING credential secret cannot make provisioning complete."""
    creating_secret = MagicMock()
    creating_secret.id = "ocid1.secret.oc1..creating"
    creating_secret.lifecycle_state = "CREATING"

    with patch.object(
        mu.common, "lookup_existing_secret", return_value=creating_secret
    ):
        result = mu._check_create_complete(
            MagicMock(),
            MagicMock(),
            MagicMock(),
            "ocid1.compartment.oc1..fake",
            "ocid1.vault.oc1..fake",
            mu.derive_names("k8s_01"),
            "ocid1.user.oc1..fake",
            logging.getLogger("test_idem_secret_creating"),
        )

    assert result is False


def test_check_create_complete_false_when_fingerprint_not_in_api_keys(mu, common_mod):
    """``_check_create_complete`` returns False when stored fingerprint has no matching key."""
    log = logging.getLogger("test_idem_fp_mismatch")

    # Generate a real keypair so the private-key check passes.
    keypair = common_mod.generate_unencrypted_rsa_api_key(2048)
    real_fp = keypair["fingerprint"]
    real_pem = keypair["private_pem"]

    fake_secret = MagicMock()
    fake_secret.id = "ocid1.secret.oc1..fake"
    fake_secret.lifecycle_state = "ACTIVE"

    def _fake_lookup(vaults_c, comp_id, vault_id, name, log_arg):  # noqa: ANN001
        return fake_secret

    # _read_secret_value returns the one JSON credential payload.
    def _fake_read(vaults_c, secrets_c, comp_id, vault_id, name, log_arg):  # noqa: ANN001
        return json.dumps(
            {
                "private_key": real_pem,
                "fingerprint": real_fp,
                "user_ocid": "ocid1.user.oc1..fake",
            }
        )

    # API keys on the user do NOT contain the matching fingerprint.
    no_matching_key = MagicMock()
    no_matching_key.fingerprint = "xx:yy:zz:zz:xx:yy:zz:zz:xx:yy:zz:zz:xx:yy:zz:zz"

    with (
        patch.object(mu.common, "lookup_existing_secret", side_effect=_fake_lookup),
        patch.object(mu, "_read_secret_value", side_effect=_fake_read),
        patch.object(mu.common, "list_all", return_value=[no_matching_key]),
    ):
        result = mu._check_create_complete(
            MagicMock(),
            MagicMock(),
            MagicMock(),
            "ocid1.compartment.oc1..fake",
            "ocid1.vault.oc1..fake",
            mu.derive_names("k8s_01"),
            "ocid1.user.oc1..fake",
            log,
        )
    assert result is False


def test_check_create_complete_true_when_all_match(mu, common_mod):
    """``_check_create_complete`` returns True when all conditions hold."""
    log = logging.getLogger("test_idem_complete")
    user_ocid = "ocid1.user.oc1..real"

    # Generate a real keypair: private_key + fingerprint must be self-consistent.
    keypair = common_mod.generate_unencrypted_rsa_api_key(2048)
    registered_fp = keypair["fingerprint"]
    real_pem = keypair["private_pem"]

    fake_secret = MagicMock()
    fake_secret.id = "ocid1.secret.oc1..fake"
    fake_secret.lifecycle_state = "ACTIVE"

    def _fake_read(vaults_c, secrets_c, comp_id, vault_id, name, log_arg):  # noqa: ANN001
        return json.dumps(
            {
                "private_key": real_pem,
                "fingerprint": registered_fp,
                "user_ocid": user_ocid,
            }
        )

    matching_key = MagicMock()
    matching_key.fingerprint = registered_fp

    with (
        patch.object(mu.common, "lookup_existing_secret", return_value=fake_secret),
        patch.object(mu, "_read_secret_value", side_effect=_fake_read),
        patch.object(mu.common, "list_all", return_value=[matching_key]),
    ):
        result = mu._check_create_complete(
            MagicMock(),
            MagicMock(),
            MagicMock(),
            "ocid1.compartment.oc1..fake",
            "ocid1.vault.oc1..fake",
            mu.derive_names("k8s_01"),
            user_ocid,
            log,
        )
    assert result is True


@pytest.mark.parametrize(
    "raw_value",
    [
        "not-json",
        "[]",
        json.dumps({"fingerprint": "aa:bb", "user_ocid": "ocid1.user.oc1..fake"}),
        json.dumps(
            {
                "private_key": "key",
                "fingerprint": "",
                "user_ocid": "ocid1.user.oc1..fake",
            }
        ),
    ],
)
def test_check_create_complete_false_for_invalid_credential_json(mu, raw_value):
    """The consolidated credential must be a JSON object with all string fields."""
    active_secret = MagicMock()
    active_secret.id = "ocid1.secret.oc1..credential"
    active_secret.lifecycle_state = "ACTIVE"

    with (
        patch.object(mu.common, "lookup_existing_secret", return_value=active_secret),
        patch.object(mu, "_read_secret_value", return_value=raw_value),
    ):
        result = mu._check_create_complete(
            MagicMock(),
            MagicMock(),
            MagicMock(),
            "ocid1.compartment.oc1..fake",
            "ocid1.vault.oc1..fake",
            mu.derive_names("k8s_01"),
            "ocid1.user.oc1..fake",
            logging.getLogger("test_invalid_credential_json"),
        )

    assert result is False


# ---------------------------------------------------------------------------
# K. Private key never logged
# ---------------------------------------------------------------------------
def test_private_key_not_in_log_during_generate(mu, caplog):
    """The private key PEM must not appear in any log record during generation."""
    captured_private_pem: list[str] = []

    def _fake_generate(bits: int) -> dict:  # noqa: ANN001
        keypair = {
            "private_pem": "-----BEGIN PRIVATE KEY-----\nSECRETDATA\n-----END PRIVATE KEY-----\n",
            "public_pem": "-----BEGIN PUBLIC KEY-----\nPUBLIC\n-----END PUBLIC KEY-----\n",
            "public_der": b"\x00" * 16,
            "fingerprint": "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99",
        }
        captured_private_pem.append(keypair["private_pem"])
        return keypair

    identity_client = MagicMock()
    log = logging.getLogger("test_no_priv_log")

    with (
        patch.object(
            mu.common, "generate_unencrypted_rsa_api_key", side_effect=_fake_generate
        ),
        caplog.at_level(logging.DEBUG),
    ):
        mu._generate_and_upload_api_key(
            identity_client, "ocid1.user.oc1..fake", "sa_k8s_01_openbao_unseal", log
        )

    private_pem = captured_private_pem[0] if captured_private_pem else ""
    for record in caplog.records:
        assert private_pem not in record.getMessage(), (
            f"Private key leaked into log record: {record.getMessage()[:80]!r}"
        )
        assert "SECRETDATA" not in record.getMessage()


# ---------------------------------------------------------------------------
# L. fingerprint_from_private_pem helper (common.py)
# ---------------------------------------------------------------------------
def test_fingerprint_from_private_pem_valid_rsa_matches(common_mod):
    """A valid unencrypted RSA key produces the expected fingerprint."""
    keypair = common_mod.generate_unencrypted_rsa_api_key(2048)
    fp = common_mod.fingerprint_from_private_pem(keypair["private_pem"])
    assert fp == keypair["fingerprint"], (
        "fingerprint_from_private_pem must produce the same fingerprint as "
        "generate_unencrypted_rsa_api_key for the same key"
    )


def test_fingerprint_from_private_pem_encrypted_raises(common_mod):
    """An encrypted (passphrase-protected) private key raises ValueError."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    encrypted_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(b"secret"),
    ).decode("utf-8")

    with pytest.raises(ValueError, match="encrypted"):
        common_mod.fingerprint_from_private_pem(encrypted_pem)


def test_fingerprint_from_private_pem_malformed_raises(common_mod):
    """Malformed / non-PEM input raises ValueError."""
    with pytest.raises(ValueError):
        common_mod.fingerprint_from_private_pem("this is not a pem at all")


def test_fingerprint_from_private_pem_ec_key_raises(common_mod):
    """An EC private key (non-RSA) raises ValueError."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    ec_key = ec.generate_private_key(ec.SECP256R1())
    ec_pem = ec_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    with pytest.raises(ValueError, match="not RSA"):
        common_mod.fingerprint_from_private_pem(ec_pem)


def test_fingerprint_from_private_pem_never_logs_key(common_mod, caplog):
    """No log record must contain any part of the private key PEM."""
    keypair = common_mod.generate_unencrypted_rsa_api_key(2048)
    with caplog.at_level(logging.DEBUG):
        common_mod.fingerprint_from_private_pem(keypair["private_pem"])

    for record in caplog.records:
        assert keypair["private_pem"] not in record.getMessage()


# ---------------------------------------------------------------------------
# M. Strengthened _check_create_complete (private key validation)
# ---------------------------------------------------------------------------
def test_check_create_complete_false_when_private_key_malformed(mu, common_mod):
    """Returns False when the JSON credential contains a malformed PEM."""
    log = logging.getLogger("test_idem_pk_malformed")
    user_ocid = "ocid1.user.oc1..real"
    keypair = common_mod.generate_unencrypted_rsa_api_key(2048)
    registered_fp = keypair["fingerprint"]

    fake_secret = MagicMock()
    fake_secret.id = "ocid1.secret.oc1..fake"
    fake_secret.lifecycle_state = "ACTIVE"

    def _fake_read(vaults_c, secrets_c, comp_id, vault_id, name, log_arg):  # noqa: ANN001
        return json.dumps(
            {
                "private_key": "not a valid pem at all",
                "fingerprint": registered_fp,
                "user_ocid": user_ocid,
            }
        )

    matching_key = MagicMock()
    matching_key.fingerprint = registered_fp

    with (
        patch.object(mu.common, "lookup_existing_secret", return_value=fake_secret),
        patch.object(mu, "_read_secret_value", side_effect=_fake_read),
        patch.object(mu.common, "list_all", return_value=[matching_key]),
    ):
        result = mu._check_create_complete(
            MagicMock(),
            MagicMock(),
            MagicMock(),
            "ocid1.compartment.oc1..fake",
            "ocid1.vault.oc1..fake",
            mu.derive_names("k8s_01"),
            user_ocid,
            log,
        )
    assert result is False


def test_check_create_complete_false_when_private_key_fingerprint_mismatches(
    mu, common_mod
):
    """Returns False when the private key derives a different fingerprint than stored."""
    log = logging.getLogger("test_idem_pk_fp_mismatch")
    user_ocid = "ocid1.user.oc1..real"

    # Two independent keypairs: key_a's PEM but key_b's fingerprint stored.
    key_a = common_mod.generate_unencrypted_rsa_api_key(2048)
    key_b = common_mod.generate_unencrypted_rsa_api_key(2048)
    assert key_a["fingerprint"] != key_b["fingerprint"], "fingerprints must differ"

    fake_secret = MagicMock()
    fake_secret.id = "ocid1.secret.oc1..fake"
    fake_secret.lifecycle_state = "ACTIVE"

    def _fake_read(vaults_c, secrets_c, comp_id, vault_id, name, log_arg):  # noqa: ANN001
        return json.dumps(
            {
                "private_key": key_a["private_pem"],
                "fingerprint": key_b["fingerprint"],
                "user_ocid": user_ocid,
            }
        )

    any_key = MagicMock()
    any_key.fingerprint = key_b["fingerprint"]

    with (
        patch.object(mu.common, "lookup_existing_secret", return_value=fake_secret),
        patch.object(mu, "_read_secret_value", side_effect=_fake_read),
        patch.object(mu.common, "list_all", return_value=[any_key]),
    ):
        result = mu._check_create_complete(
            MagicMock(),
            MagicMock(),
            MagicMock(),
            "ocid1.compartment.oc1..fake",
            "ocid1.vault.oc1..fake",
            mu.derive_names("k8s_01"),
            user_ocid,
            log,
        )
    assert result is False


# ---------------------------------------------------------------------------
# N. Cap safety: protected fingerprint never deleted
# ---------------------------------------------------------------------------
def test_handle_api_key_cap_never_deletes_protected_fingerprint(mu):
    """The oldest key is skipped if it is protected; the next-oldest is deleted."""
    identity_client = MagicMock()
    log = logging.getLogger("test_cap_protected")

    three_keys = [
        _fake_key("protected:fp", "2024-01-01"),  # oldest = protected → must not delete
        _fake_key("spare:fp:bb", "2024-06-01"),  # next-oldest → should be deleted
        _fake_key("newest:fp:cc", "2024-12-01"),
    ]

    with patch.object(mu.common, "list_all", return_value=three_keys):
        mu._handle_api_key_cap(
            identity_client,
            "ocid1.user.oc1..fake",
            delete_old_api_key=True,
            protected_fingerprint="protected:fp",
            dry_run=False,
            log=log,
        )

    identity_client.delete_api_key.assert_called_once_with(
        user_id="ocid1.user.oc1..fake",
        fingerprint="spare:fp:bb",
    )


def test_handle_api_key_cap_exit5_when_no_safe_candidate(mu):
    """Exit 5 when every existing key fingerprint matches the protected fingerprint."""
    identity_client = MagicMock()
    log = logging.getLogger("test_cap_no_safe")

    # Artificial: all three keys share the protected fingerprint
    # (can't occur with real OCI fingerprints, but covers defensive code path).
    three_keys = [
        _fake_key("only:fp", "2024-01-01"),
        _fake_key("only:fp", "2024-06-01"),
        _fake_key("only:fp", "2024-12-01"),
    ]

    with patch.object(mu.common, "list_all", return_value=three_keys):
        with pytest.raises(SystemExit) as exc:
            mu._handle_api_key_cap(
                identity_client,
                "ocid1.user.oc1..fake",
                delete_old_api_key=True,
                protected_fingerprint="only:fp",
                dry_run=False,
                log=log,
            )
    assert exc.value.code == mu._EXIT_RESOURCE_NOT_FOUND  # == 5
    identity_client.delete_api_key.assert_not_called()


def test_handle_api_key_cap_no_protected_deletes_oldest(mu):
    """Without a protected fingerprint, behaviour is unchanged: oldest deleted."""
    identity_client = MagicMock()
    log = logging.getLogger("test_cap_no_protected")

    three_keys = [
        _fake_key("old:fp:aa", "2024-01-01"),
        _fake_key("mid:fp:bb", "2024-06-01"),
        _fake_key("new:fp:cc", "2024-12-01"),
    ]

    with patch.object(mu.common, "list_all", return_value=three_keys):
        mu._handle_api_key_cap(
            identity_client,
            "ocid1.user.oc1..fake",
            delete_old_api_key=True,
            protected_fingerprint=None,
            dry_run=False,
            log=log,
        )

    identity_client.delete_api_key.assert_called_once_with(
        user_id="ocid1.user.oc1..fake",
        fingerprint="old:fp:aa",
    )


def test_create_protects_registered_fingerprint_when_repairing(
    mu, mock_unseal_oci, monkeypatch
):
    """A repair run must not evict the fingerprint still registered in Vault.

    The idempotency check returns False first (provisioning is incomplete) so
    the repair path is taken.  After writing the new secrets the post-write
    validation returns True (now complete).  The cap handler must receive the
    currently-registered (protected) fingerprint so it is never evicted.
    """
    protected_fingerprint = "aa:bb:cc:dd"
    cap_kwargs: dict[str, Any] = {}

    # First call (idempotency check): incomplete → repair path taken.
    # Second call (post-write validation): complete → success.
    _check_results = iter([False, True])
    monkeypatch.setattr(
        mu,
        "_check_create_complete",
        lambda *a, **kw: next(_check_results),
    )
    monkeypatch.setattr(
        mu,
        "_read_credential_payload",
        lambda *a, **kw: {
            "private_key": "private",
            "fingerprint": protected_fingerprint,
            "user_ocid": "ocid1.user.oc1..unseal_fake",
        },
    )
    monkeypatch.setattr(
        mu,
        "_handle_api_key_cap",
        lambda *a, **kw: cap_kwargs.update(kw),
    )
    monkeypatch.setattr(
        mu,
        "_generate_and_upload_api_key",
        lambda *a, **kw: {
            "private_pem": "private",
            "fingerprint": "new:fingerprint",
        },
    )
    monkeypatch.setattr(mu, "_upsert_vault_secret", lambda *a, **kw: "secret")
    args = _make_unseal_args(dry_run=False, delete_old_api_key=True)
    assert mu.cmd_create(args, logging.getLogger("test_create_protected")) == 0
    assert cap_kwargs.get("protected_fingerprint") == protected_fingerprint


def test_create_consolidates_valid_legacy_credentials_without_new_api_key(
    mu, mock_unseal_oci, monkeypatch
):
    """A valid legacy triplet is copied to JSON without changing the API key."""
    user_ocid = "ocid1.user.oc1..unseal_fake"
    legacy = {
        "private_key": "legacy-private-key",
        "fingerprint": "aa:bb:cc:dd",
        "user_ocid": user_ocid,
    }
    check_results = iter([False, True])
    upsert_kwargs: dict[str, Any] = {}

    monkeypatch.setattr(
        mu, "_check_create_complete", lambda *a, **kw: next(check_results)
    )
    monkeypatch.setattr(mu, "_read_legacy_credential_payload", lambda *a, **kw: legacy)
    monkeypatch.setattr(mu, "_credential_payload_is_valid", lambda *a, **kw: True)
    monkeypatch.setattr(
        mu, "_require_legacy_credential_secrets_use_mek", lambda *a, **kw: None
    )
    monkeypatch.setattr(
        mu,
        "_upsert_vault_secret",
        lambda *a, **kw: upsert_kwargs.update(kw) or "ocid1.secret.oc1..credential",
    )
    monkeypatch.setattr(
        mu,
        "_generate_and_upload_api_key",
        lambda *a, **kw: pytest.fail("legacy consolidation must not create an API key"),
    )

    assert (
        mu.cmd_create(
            _make_unseal_args(dry_run=False),
            logging.getLogger("test_legacy_consolidation"),
        )
        == 0
    )
    assert upsert_kwargs["secret_name"] == "k8s_01_openbao_unseal_credential"
    assert json.loads(upsert_kwargs["secret_value_bytes"].decode("utf-8")) == legacy


# ---------------------------------------------------------------------------
# O. Summary-file compartment.name used for policy scope
# ---------------------------------------------------------------------------
def test_load_summary_for_discovery_returns_compartment_name(mu, tmp_path):
    """``_load_summary_for_discovery`` returns ``compartment.name`` from summary."""
    summary = {
        "compartment": {
            "ocid": "ocid1.compartment.oc1..summary",
            "name": "my_summary_compartment",
        },
        "vault": {
            "ocid": "ocid1.vault.oc1..summary",
            "management_endpoint": "https://vault-mgmt.summary.fake",
        },
    }
    summary_path = tmp_path / "summary.json"
    summary_path.write_text(json.dumps(summary))

    log = logging.getLogger("test_summary_cname")
    result = mu._load_summary_for_discovery(summary_path, log)

    assert result["compartment_name"] == "my_summary_compartment"
    assert result["compartment_ocid"] == "ocid1.compartment.oc1..summary"
    assert result["vault_ocid"] == "ocid1.vault.oc1..summary"
    assert result["management_endpoint"] == "https://vault-mgmt.summary.fake"


def test_load_summary_for_discovery_exits3_when_compartment_name_missing(mu, tmp_path):
    """Exit 3 when ``compartment.name`` is absent from the summary."""
    summary = {
        "compartment": {"ocid": "ocid1.compartment.oc1..fake"},  # no "name" key
        "vault": {
            "ocid": "ocid1.vault.oc1..fake",
            "management_endpoint": "https://vault-mgmt.fake",
        },
    }
    summary_path = tmp_path / "summary.json"
    summary_path.write_text(json.dumps(summary))

    log = logging.getLogger("test_summary_cname_missing")
    with pytest.raises(SystemExit) as exc:
        mu._load_summary_for_discovery(summary_path, log)
    assert exc.value.code == 3


def test_load_summary_for_discovery_exits3_when_compartment_name_empty(mu, tmp_path):
    """Exit 3 when ``compartment.name`` is present but empty."""
    summary = {
        "compartment": {"ocid": "ocid1.compartment.oc1..fake", "name": ""},
        "vault": {
            "ocid": "ocid1.vault.oc1..fake",
            "management_endpoint": "https://vault-mgmt.fake",
        },
    }
    summary_path = tmp_path / "summary.json"
    summary_path.write_text(json.dumps(summary))

    log = logging.getLogger("test_summary_cname_empty")
    with pytest.raises(SystemExit) as exc:
        mu._load_summary_for_discovery(summary_path, log)
    assert exc.value.code == 3


# ---------------------------------------------------------------------------
# P. IAM propagation: CREATING resources must be waited upon
# ---------------------------------------------------------------------------
def _make_mock_user(ocid: str, name: str, lifecycle_state: str) -> MagicMock:
    u = MagicMock()
    u.id = ocid
    u.name = name
    u.lifecycle_state = lifecycle_state
    return u


def _make_mock_group(ocid: str, name: str, lifecycle_state: str) -> MagicMock:
    g = MagicMock()
    g.id = ocid
    g.name = name
    g.lifecycle_state = lifecycle_state
    return g


def _make_mock_policy(ocid: str, name: str, lifecycle_state: str) -> MagicMock:
    p = MagicMock()
    p.id = ocid
    p.name = name
    p.lifecycle_state = lifecycle_state
    return p


def test_ensure_unseal_user_waits_when_creating(mu):
    """When an existing user is CREATING, ``_ensure_unseal_user`` polls for ACTIVE."""
    user_ocid = "ocid1.user.oc1..creating"
    user_name = "sa_k8s_01_openbao_unseal"
    creating_user = _make_mock_user(user_ocid, user_name, "CREATING")
    active_user = _make_mock_user(user_ocid, user_name, "ACTIVE")

    identity_client = MagicMock()
    log = logging.getLogger("test_user_creating")

    with (
        patch.object(mu.common, "list_all", return_value=[creating_user]),
        patch.object(
            mu.common, "wait_for_state", return_value=active_user
        ) as mock_wait,
    ):
        result = mu._ensure_unseal_user(
            identity_client,
            "ocid1.tenancy.oc1..fake",
            user_name,
            dry_run=False,
            wait_seconds=60,
            interval_seconds=5,
            log=log,
        )

    assert result == user_ocid
    mock_wait.assert_called_once()
    # Verify that get_user was used (via the lambda passed to wait_for_state).
    call_args = mock_wait.call_args
    assert call_args.kwargs.get("max_wait") == 60
    assert call_args.kwargs.get("interval") == 5


def test_ensure_unseal_user_waits_after_creation(mu):
    """A newly created user is polled for ACTIVE before the OCID is returned."""
    user_ocid = "ocid1.user.oc1..fresh"
    user_name = "sa_k8s_01_openbao_unseal"
    active_user = _make_mock_user(user_ocid, user_name, "ACTIVE")

    identity_client = MagicMock()
    resp_mock = MagicMock()
    resp_mock.data.id = user_ocid
    identity_client.create_user.return_value = resp_mock

    log = logging.getLogger("test_user_creation_wait")

    with (
        patch.object(mu.common, "list_all", return_value=[]),
        patch.object(
            mu.common, "wait_for_state", return_value=active_user
        ) as mock_wait,
    ):
        result = mu._ensure_unseal_user(
            identity_client,
            "ocid1.tenancy.oc1..fake",
            user_name,
            dry_run=False,
            wait_seconds=60,
            interval_seconds=5,
            log=log,
        )

    assert result == user_ocid
    identity_client.create_user.assert_called_once()
    mock_wait.assert_called_once()


def test_ensure_unseal_group_waits_when_creating(mu):
    """When an existing group is CREATING, ``_ensure_unseal_group`` polls for ACTIVE."""
    group_ocid = "ocid1.group.oc1..creating"
    group_name = "grp_k8s_01_openbao_unseal"
    creating_group = _make_mock_group(group_ocid, group_name, "CREATING")
    active_group = _make_mock_group(group_ocid, group_name, "ACTIVE")

    identity_client = MagicMock()
    log = logging.getLogger("test_group_creating")

    with (
        patch.object(mu.common, "list_all", return_value=[creating_group]),
        patch.object(
            mu.common, "wait_for_state", return_value=active_group
        ) as mock_wait,
    ):
        result = mu._ensure_unseal_group(
            identity_client,
            "ocid1.tenancy.oc1..fake",
            group_name,
            dry_run=False,
            wait_seconds=60,
            interval_seconds=5,
            log=log,
        )

    assert result == group_ocid
    mock_wait.assert_called_once()


def test_ensure_unseal_membership_waits_when_creating(mu):
    """When an existing membership is CREATING, it is polled for ACTIVE."""
    membership_ocid = "ocid1.membership.oc1..creating"
    creating_membership = MagicMock()
    creating_membership.id = membership_ocid
    creating_membership.lifecycle_state = "CREATING"

    active_membership = MagicMock()
    active_membership.id = membership_ocid
    active_membership.lifecycle_state = "ACTIVE"

    identity_client = MagicMock()
    log = logging.getLogger("test_membership_creating")

    with (
        patch.object(mu.common, "list_all", return_value=[creating_membership]),
        patch.object(
            mu.common, "wait_for_state", return_value=active_membership
        ) as mock_wait,
    ):
        mu._ensure_unseal_membership(
            identity_client,
            "ocid1.tenancy.oc1..fake",
            "ocid1.user.oc1..fake",
            "ocid1.group.oc1..fake",
            dry_run=False,
            wait_seconds=60,
            interval_seconds=5,
            log=log,
        )

    mock_wait.assert_called_once()
    call_args = mock_wait.call_args
    assert call_args.kwargs.get("max_wait") == 60


def test_ensure_unseal_membership_waits_after_creation(mu):
    """A newly created membership is polled for ACTIVE before returning."""
    membership_ocid = "ocid1.membership.oc1..fresh"
    active_membership = MagicMock()
    active_membership.id = membership_ocid
    active_membership.lifecycle_state = "ACTIVE"

    identity_client = MagicMock()
    add_resp = MagicMock()
    add_resp.data.id = membership_ocid
    identity_client.add_user_to_group.return_value = add_resp

    log = logging.getLogger("test_membership_creation_wait")

    with (
        patch.object(mu.common, "list_all", return_value=[]),
        patch.object(
            mu.common, "wait_for_state", return_value=active_membership
        ) as mock_wait,
    ):
        mu._ensure_unseal_membership(
            identity_client,
            "ocid1.tenancy.oc1..fake",
            "ocid1.user.oc1..fake",
            "ocid1.group.oc1..fake",
            dry_run=False,
            wait_seconds=60,
            interval_seconds=5,
            log=log,
        )

    identity_client.add_user_to_group.assert_called_once()
    mock_wait.assert_called_once()


def test_ensure_unseal_policy_waits_when_creating(mu):
    """When an existing policy is CREATING, ``_ensure_unseal_policy`` polls for ACTIVE."""
    key_ocid = "ocid1.key.oc1..fake"
    expected_stmt = mu._unseal_policy_statement(
        "grp_k8s_01_openbao_unseal", "cpm_automation", key_ocid
    )
    policy_ocid = "ocid1.policy.oc1..creating"
    creating_policy = _make_mock_policy(
        policy_ocid, "policy_k8s_01_openbao_unseal", "CREATING"
    )

    active_policy = _make_mock_policy(
        policy_ocid, "policy_k8s_01_openbao_unseal", "ACTIVE"
    )
    active_policy.statements = [expected_stmt]
    active_policy.description = "desc"

    identity_client = MagicMock()
    log = logging.getLogger("test_policy_creating")

    with (
        patch.object(mu.common, "list_all", return_value=[creating_policy]),
        patch.object(
            mu.common, "wait_for_state", return_value=active_policy
        ) as mock_wait,
    ):
        result = mu._ensure_unseal_policy(
            identity_client,
            "ocid1.tenancy.oc1..fake",
            "policy_k8s_01_openbao_unseal",
            "grp_k8s_01_openbao_unseal",
            "cpm_automation",
            key_ocid,
            dry_run=False,
            wait_seconds=60,
            interval_seconds=5,
            log=log,
        )

    assert result == policy_ocid
    mock_wait.assert_called_once()
    # No mutation: the policy statement is correct so no update_policy call.
    identity_client.update_policy.assert_not_called()


def test_ensure_unseal_policy_waits_after_update(mu):
    """After updating a policy with wrong statements, ``_ensure_unseal_policy`` waits for ACTIVE."""
    key_ocid = "ocid1.key.oc1..fake"
    policy_ocid = "ocid1.policy.oc1..existing"
    wrong_policy = _make_mock_policy(
        policy_ocid, "policy_k8s_01_openbao_unseal", "ACTIVE"
    )
    wrong_policy.statements = ["Allow group X to manage all-resources in tenancy"]
    wrong_policy.description = "old"

    identity_client = MagicMock()
    log = logging.getLogger("test_policy_update_wait")

    with (
        patch.object(mu.common, "list_all", return_value=[wrong_policy]),
        patch.object(
            mu.common, "wait_for_state", return_value=wrong_policy
        ) as mock_wait,
    ):
        result = mu._ensure_unseal_policy(
            identity_client,
            "ocid1.tenancy.oc1..fake",
            "policy_k8s_01_openbao_unseal",
            "grp_k8s_01_openbao_unseal",
            "cpm_automation",
            key_ocid,
            dry_run=False,
            wait_seconds=60,
            interval_seconds=5,
            log=log,
        )

    assert result == policy_ocid
    identity_client.update_policy.assert_called_once()
    mock_wait.assert_called_once()


def test_ensure_unseal_user_creating_allowed_in_dry_run(mu):
    """CREATING user is polled even in dry-run mode (polling is read-only)."""
    user_ocid = "ocid1.user.oc1..creating"
    user_name = "sa_k8s_01_openbao_unseal"
    creating_user = _make_mock_user(user_ocid, user_name, "CREATING")
    active_user = _make_mock_user(user_ocid, user_name, "ACTIVE")

    identity_client = MagicMock()
    log = logging.getLogger("test_user_creating_dry")

    with (
        patch.object(mu.common, "list_all", return_value=[creating_user]),
        patch.object(
            mu.common, "wait_for_state", return_value=active_user
        ) as mock_wait,
    ):
        result = mu._ensure_unseal_user(
            identity_client,
            "ocid1.tenancy.oc1..fake",
            user_name,
            dry_run=True,  # dry-run: mutations skipped, but polling is OK
            wait_seconds=60,
            interval_seconds=5,
            log=log,
        )

    assert result == user_ocid
    # Even in dry-run, a CREATING resource must be polled.
    mock_wait.assert_called_once()


# ---------------------------------------------------------------------------
# Q. CLI polling validation: --wait-seconds / --interval-seconds
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("bad_value", ["0", "-1", "-100"])
def test_cli_wait_seconds_rejects_nonpositive(mu, bad_value):
    """``--wait-seconds`` with zero or negative value exits with code 2."""
    with pytest.raises(SystemExit) as exc:
        mu.parse_args(["create", "--cluster-name", "c", "--wait-seconds", bad_value])
    assert exc.value.code == 2


@pytest.mark.parametrize("good_value,expected", [("1", 1), ("30", 30), ("600", 600)])
def test_cli_wait_seconds_accepts_positive(mu, good_value, expected):
    """``--wait-seconds`` with a positive integer is parsed correctly."""
    args = mu.parse_args(
        ["create", "--cluster-name", "c", "--wait-seconds", good_value]
    )
    assert args.wait_seconds == expected


@pytest.mark.parametrize("bad_value", ["0", "-1", "-100"])
def test_cli_interval_seconds_rejects_nonpositive(mu, bad_value):
    """``--interval-seconds`` with zero or negative value exits with code 2."""
    with pytest.raises(SystemExit) as exc:
        mu.parse_args(
            ["create", "--cluster-name", "c", "--interval-seconds", bad_value]
        )
    assert exc.value.code == 2


@pytest.mark.parametrize("good_value,expected", [("1", 1), ("10", 10), ("60", 60)])
def test_cli_interval_seconds_accepts_positive(mu, good_value, expected):
    """``--interval-seconds`` with a positive integer is parsed correctly."""
    args = mu.parse_args(
        ["create", "--cluster-name", "c", "--interval-seconds", good_value]
    )
    assert args.interval_seconds == expected


# ---------------------------------------------------------------------------
# R. Strict summary discovery fields: truthy non-string values must exit 3
# ---------------------------------------------------------------------------
_VALID_SUMMARY_BASE = {
    "compartment": {
        "ocid": "ocid1.compartment.oc1..c",
        "name": "cpm_automation",
    },
    "vault": {
        "ocid": "ocid1.vault.oc1..v",
        "management_endpoint": "https://vault-mgmt.fake",
    },
}


def _summary_with_field(path: list, value: Any) -> dict:
    """Return a copy of ``_VALID_SUMMARY_BASE`` with one field replaced."""
    import copy

    data = copy.deepcopy(_VALID_SUMMARY_BASE)
    node = data
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = value
    return data


@pytest.mark.parametrize(
    "field_path,bad_value",
    [
        # compartment.ocid: truthy non-string
        (["compartment", "ocid"], 1),
        (["compartment", "ocid"], True),
        (["compartment", "ocid"], ["nonempty-list"]),
        (["compartment", "ocid"], {"key": "value"}),
        # compartment.name: truthy non-string
        (["compartment", "name"], 42),
        (["compartment", "name"], True),
        # vault.ocid: truthy non-string
        (["vault", "ocid"], 1),
        (["vault", "ocid"], True),
        # vault.management_endpoint: truthy non-string
        (["vault", "management_endpoint"], 1),
        (["vault", "management_endpoint"], ["https://fake"]),
    ],
)
def test_load_summary_exits3_for_truthy_non_string_field(
    mu, tmp_path, field_path, bad_value
):
    """Exit 3 when any discovery field is truthy but not a string.

    JSON serialises Python booleans (``true``/``false``) and integers; when
    loaded back these become Python ``bool``/``int``.  A non-empty list or dict
    would be truthy but is not a string.  All must trigger exit 3.
    """
    bad_summary = _summary_with_field(field_path, bad_value)
    summary_path = tmp_path / "summary.json"
    summary_path.write_text(json.dumps(bad_summary))

    log = logging.getLogger("test_truthy_nonstring")
    with pytest.raises(SystemExit) as exc:
        mu._load_summary_for_discovery(summary_path, log)
    assert exc.value.code == 3


# ---------------------------------------------------------------------------
# S. KMS key shape validation
# ---------------------------------------------------------------------------
def _make_key_shape_resp(
    algorithm: Any, length: Any, protection_mode: Any
) -> MagicMock:
    """Return a mock ``get_key`` response with the specified shape attributes."""
    key_shape = MagicMock()
    key_shape.algorithm = algorithm
    key_shape.length = length
    key_data = MagicMock()
    key_data.key_shape = key_shape
    key_data.protection_mode = protection_mode
    key_data.id = "ocid1.key.oc1..shape_test"
    key_data.lifecycle_state = "ENABLED"
    resp = MagicMock()
    resp.data = key_data
    return resp


def _make_mgmt_mock(get_key_resp: MagicMock) -> MagicMock:
    """Return a mock KmsManagementClient whose ``get_key`` returns *get_key_resp*."""
    mgmt = MagicMock()
    mgmt.get_key.return_value = get_key_resp
    return mgmt


def _make_key_summary_mock(key_id: str, display_name: str, state: str) -> MagicMock:
    """Return a mock KeySummary (as returned by list_keys)."""
    k = MagicMock()
    k.id = key_id
    k.display_name = display_name
    k.lifecycle_state = state
    return k


# --- Direct tests of _validate_unseal_key_shape ---


def test_validate_unseal_key_shape_accepts_aes_256_software(mu):
    """AES / length=32 / SOFTWARE passes without raising."""
    resp = _make_key_shape_resp("AES", 32, "SOFTWARE")
    mgmt = _make_mgmt_mock(resp)
    log = logging.getLogger("test_shape_ok")
    mu._validate_unseal_key_shape(
        mgmt, "ocid1.key.oc1..fake", "k8s_01_openbao_unseal", log
    )
    mgmt.get_key.assert_called_once_with("ocid1.key.oc1..fake")


def test_validate_unseal_key_shape_rejects_wrong_algorithm(mu):
    """Non-AES algorithm (RSA) raises SystemExit(1)."""
    resp = _make_key_shape_resp("RSA", 32, "SOFTWARE")
    mgmt = _make_mgmt_mock(resp)
    log = logging.getLogger("test_shape_rsa")
    with pytest.raises(SystemExit) as exc:
        mu._validate_unseal_key_shape(
            mgmt, "ocid1.key.oc1..fake", "k8s_01_openbao_unseal", log
        )
    assert exc.value.code == 1


def test_validate_unseal_key_shape_rejects_aes_128(mu):
    """AES with length=16 (AES-128) is rejected; only length=32 (AES-256) is accepted."""
    resp = _make_key_shape_resp("AES", 16, "SOFTWARE")
    mgmt = _make_mgmt_mock(resp)
    log = logging.getLogger("test_shape_aes128")
    with pytest.raises(SystemExit) as exc:
        mu._validate_unseal_key_shape(
            mgmt, "ocid1.key.oc1..fake", "k8s_01_openbao_unseal", log
        )
    assert exc.value.code == 1


def test_validate_unseal_key_shape_rejects_hsm_protection_mode(mu):
    """HSM protection mode is rejected; only SOFTWARE is accepted."""
    resp = _make_key_shape_resp("AES", 32, "HSM")
    mgmt = _make_mgmt_mock(resp)
    log = logging.getLogger("test_shape_hsm")
    with pytest.raises(SystemExit) as exc:
        mu._validate_unseal_key_shape(
            mgmt, "ocid1.key.oc1..fake", "k8s_01_openbao_unseal", log
        )
    assert exc.value.code == 1


def test_validate_unseal_key_shape_rejects_none_key_shape(mu):
    """``key_shape=None`` (field unavailable) raises SystemExit(1)."""
    key_data = MagicMock()
    key_data.key_shape = None
    key_data.protection_mode = "SOFTWARE"
    resp = MagicMock()
    resp.data = key_data
    mgmt = MagicMock()
    mgmt.get_key.return_value = resp
    log = logging.getLogger("test_shape_none")
    with pytest.raises(SystemExit) as exc:
        mu._validate_unseal_key_shape(
            mgmt, "ocid1.key.oc1..fake", "k8s_01_openbao_unseal", log
        )
    assert exc.value.code == 1


def test_validate_unseal_key_shape_error_message_contains_key_name_and_observed(
    mu, caplog
):
    """The error log must name the key and include the observed non-sensitive values."""
    resp = _make_key_shape_resp("RSA", 4096, "HSM")
    mgmt = _make_mgmt_mock(resp)
    log = logging.getLogger("test_shape_msg")
    with caplog.at_level(logging.ERROR), pytest.raises(SystemExit):
        mu._validate_unseal_key_shape(
            mgmt, "ocid1.key.oc1..fake", "mycluster_openbao_unseal", log
        )
    error_text = " ".join(
        r.getMessage() for r in caplog.records if r.levelno >= logging.ERROR
    )
    assert "mycluster_openbao_unseal" in error_text
    assert "ocid1.key.oc1..fake" in error_text
    assert "RSA" in error_text
    assert "HSM" in error_text


# --- _ensure_unseal_kms_key with existing ENABLED key ---


def test_ensure_unseal_kms_key_accepts_existing_enabled_correct_shape(mu):
    """Returns the key OCID when existing ENABLED key has AES/32/SOFTWARE shape."""
    key_id = "ocid1.key.oc1..shape_ok"
    key_summary = _make_key_summary_mock(key_id, "k8s_01_openbao_unseal", "ENABLED")
    get_key_resp = _make_key_shape_resp("AES", 32, "SOFTWARE")
    mgmt_mock = _make_mgmt_mock(get_key_resp)

    log = logging.getLogger("test_ensure_existing_ok")
    with (
        patch.object(mu.common, "make_client", return_value=mgmt_mock),
        patch.object(mu.common, "list_all", return_value=[key_summary]),
    ):
        result = mu._ensure_unseal_kms_key(
            {"region": "us-fake-1"},
            "ocid1.compartment.oc1..fake",
            "https://vault-mgmt.fake",
            "k8s_01_openbao_unseal",
            dry_run=False,
            wait_seconds=10,
            interval_seconds=1,
            log=log,
        )

    assert result == key_id
    mgmt_mock.get_key.assert_called_with(key_id)
    # Must not attempt to create a new key
    mgmt_mock.create_key.assert_not_called()


def test_ensure_unseal_kms_key_rejects_existing_enabled_wrong_algorithm(mu):
    """Raises SystemExit(1) when existing ENABLED key has algorithm != AES.

    No new key is created; the mismatch is a hard failure.
    """
    key_id = "ocid1.key.oc1..bad_algo"
    key_summary = _make_key_summary_mock(key_id, "k8s_01_openbao_unseal", "ENABLED")
    get_key_resp = _make_key_shape_resp("RSA", 32, "SOFTWARE")
    mgmt_mock = _make_mgmt_mock(get_key_resp)

    log = logging.getLogger("test_ensure_existing_bad_algo")
    with (
        patch.object(mu.common, "make_client", return_value=mgmt_mock),
        patch.object(mu.common, "list_all", return_value=[key_summary]),
    ):
        with pytest.raises(SystemExit) as exc:
            mu._ensure_unseal_kms_key(
                {"region": "us-fake-1"},
                "ocid1.compartment.oc1..fake",
                "https://vault-mgmt.fake",
                "k8s_01_openbao_unseal",
                dry_run=False,
                wait_seconds=10,
                interval_seconds=1,
                log=log,
            )

    assert exc.value.code == 1
    mgmt_mock.create_key.assert_not_called()


def test_ensure_unseal_kms_key_rejects_existing_enabled_hsm_protection(mu):
    """Raises SystemExit(1) when existing ENABLED key has protection_mode == HSM."""
    key_id = "ocid1.key.oc1..bad_hsm"
    key_summary = _make_key_summary_mock(key_id, "k8s_01_openbao_unseal", "ENABLED")
    get_key_resp = _make_key_shape_resp("AES", 32, "HSM")
    mgmt_mock = _make_mgmt_mock(get_key_resp)

    log = logging.getLogger("test_ensure_existing_hsm")
    with (
        patch.object(mu.common, "make_client", return_value=mgmt_mock),
        patch.object(mu.common, "list_all", return_value=[key_summary]),
    ):
        with pytest.raises(SystemExit) as exc:
            mu._ensure_unseal_kms_key(
                {"region": "us-fake-1"},
                "ocid1.compartment.oc1..fake",
                "https://vault-mgmt.fake",
                "k8s_01_openbao_unseal",
                dry_run=False,
                wait_seconds=10,
                interval_seconds=1,
                log=log,
            )

    assert exc.value.code == 1
    mgmt_mock.create_key.assert_not_called()


# --- _ensure_unseal_kms_key with newly created key ---


def test_ensure_unseal_kms_key_validates_newly_created_key_correct_shape(mu):
    """Validates shape after creating a new key; returns key OCID on success."""
    key_id = "ocid1.key.oc1..new_valid"
    get_key_resp = _make_key_shape_resp("AES", 32, "SOFTWARE")
    get_key_resp.data.id = key_id

    mgmt_mock = MagicMock()
    mgmt_mock.get_key.return_value = get_key_resp
    create_resp = MagicMock()
    create_resp.data.id = key_id
    mgmt_mock.create_key.return_value = create_resp

    log = logging.getLogger("test_ensure_new_valid")
    with (
        patch.object(mu.common, "make_client", return_value=mgmt_mock),
        patch.object(mu.common, "list_all", return_value=[]),
        patch.object(mu.common, "wait_for_state", return_value=get_key_resp.data),
    ):
        result = mu._ensure_unseal_kms_key(
            {"region": "us-fake-1"},
            "ocid1.compartment.oc1..fake",
            "https://vault-mgmt.fake",
            "k8s_01_openbao_unseal",
            dry_run=False,
            wait_seconds=10,
            interval_seconds=1,
            log=log,
        )

    assert result == key_id
    mgmt_mock.create_key.assert_called_once()


def test_ensure_unseal_kms_key_rejects_newly_created_key_wrong_shape(mu):
    """Raises SystemExit(1) after creating a key when the server reports wrong shape.

    Covers the defensive case of unexpected server-side shape divergence.
    """
    key_id = "ocid1.key.oc1..new_bad"
    # Server confirms creation but reports AES-128 (length=16) instead of AES-256.
    get_key_resp = _make_key_shape_resp("AES", 16, "SOFTWARE")
    get_key_resp.data.id = key_id

    mgmt_mock = MagicMock()
    mgmt_mock.get_key.return_value = get_key_resp
    create_resp = MagicMock()
    create_resp.data.id = key_id
    mgmt_mock.create_key.return_value = create_resp

    log = logging.getLogger("test_ensure_new_bad")
    with (
        patch.object(mu.common, "make_client", return_value=mgmt_mock),
        patch.object(mu.common, "list_all", return_value=[]),
        patch.object(mu.common, "wait_for_state", return_value=get_key_resp.data),
    ):
        with pytest.raises(SystemExit) as exc:
            mu._ensure_unseal_kms_key(
                {"region": "us-fake-1"},
                "ocid1.compartment.oc1..fake",
                "https://vault-mgmt.fake",
                "k8s_01_openbao_unseal",
                dry_run=False,
                wait_seconds=10,
                interval_seconds=1,
                log=log,
            )

    assert exc.value.code == 1


# --- cmd_show shape reporting ---


def test_cmd_show_reports_kms_key_shape_fields(
    mu, mock_unseal_oci, monkeypatch, capsys
):
    """cmd_show includes algorithm/key_length/protection_mode/matches_expected_shape."""
    import oci as _oci

    key_id = "ocid1.key.oc1..show_shape"
    key_summary = _make_key_summary_mock(key_id, "k8s_01_openbao_unseal", "ENABLED")
    get_key_resp = _make_key_shape_resp("AES", 32, "SOFTWARE")

    def _list_all_for_show(fn, **kwargs):
        if getattr(fn, "__name__", "") == "list_keys":
            return [key_summary]
        return []

    monkeypatch.setattr(mu.common, "list_all", _list_all_for_show)
    monkeypatch.setattr(
        _oci.key_management.KmsManagementClient,
        "get_key",
        lambda self, key_id: get_key_resp,
    )

    log = logging.getLogger("test_show_shape_fields")
    args = _make_unseal_args()
    rc = mu.cmd_show(args, log)

    assert rc == 0
    output = json.loads(capsys.readouterr().out)
    kms = output["kms_key"]
    assert kms["algorithm"] == "AES"
    assert kms["key_length"] == 32
    assert kms["protection_mode"] == "SOFTWARE"
    assert kms["matches_expected_shape"] is True


def test_cmd_show_matches_expected_shape_false_for_wrong_shape(
    mu, mock_unseal_oci, monkeypatch, capsys
):
    """matches_expected_shape is False and provisioning_complete is False for wrong shape."""
    import oci as _oci

    key_id = "ocid1.key.oc1..show_wrong"
    key_summary = _make_key_summary_mock(key_id, "k8s_01_openbao_unseal", "ENABLED")
    # HSM protection — wrong shape
    get_key_resp = _make_key_shape_resp("AES", 32, "HSM")

    def _list_all_for_show(fn, **kwargs):
        if getattr(fn, "__name__", "") == "list_keys":
            return [key_summary]
        return []

    monkeypatch.setattr(mu.common, "list_all", _list_all_for_show)
    monkeypatch.setattr(
        _oci.key_management.KmsManagementClient,
        "get_key",
        lambda self, key_id: get_key_resp,
    )

    log = logging.getLogger("test_show_shape_wrong")
    args = _make_unseal_args()
    rc = mu.cmd_show(args, log)

    assert rc == 0
    output = json.loads(capsys.readouterr().out)
    assert output["kms_key"]["matches_expected_shape"] is False
    # provisioning_complete requires matches_expected_shape=True
    assert output["provisioning_complete"] is False


# ---------------------------------------------------------------------------
# T. Consolidated credential secret must use the configured MEK
# ---------------------------------------------------------------------------
def _secret_with_key(key_id: str) -> MagicMock:
    secret = MagicMock()
    secret.id = "ocid1.secret.oc1..existing"
    secret.key_id = key_id
    secret.lifecycle_state = "ACTIVE"
    return secret


def test_credential_secret_with_wrong_mek_fails_before_credential_generation(
    mu, mock_unseal_oci, monkeypatch
):
    """A mismatched credential secret key fails closed before API-key generation."""
    wrong_secret = _secret_with_key("ocid1.key.oc1..not_the_mek")
    monkeypatch.setattr(
        mu.common,
        "lookup_existing_secret",
        lambda *a, **kw: wrong_secret,
    )
    monkeypatch.setattr(
        mu,
        "_generate_and_upload_api_key",
        lambda *a, **kw: pytest.fail("must not generate a credential"),
    )

    with pytest.raises(SystemExit) as exc:
        mu.cmd_create(
            _make_unseal_args(dry_run=False),
            logging.getLogger("test_contract_wrong_mek"),
        )

    assert exc.value.code == 1


def test_upsert_refuses_to_overwrite_secret_using_wrong_mek(mu):
    """The update path independently refuses a secret encrypted by another key."""
    vaults_client = MagicMock()
    wrong_secret = _secret_with_key("ocid1.key.oc1..not_the_mek")

    with patch.object(mu.common, "lookup_existing_secret", return_value=wrong_secret):
        with pytest.raises(SystemExit) as exc:
            mu._upsert_vault_secret(
                vaults_client,
                compartment_ocid="ocid1.compartment.oc1..fake",
                vault_ocid="ocid1.vault.oc1..fake",
                mek_ocid="ocid1.key.oc1..mek",
                secret_name="k8s_01_openbao_unseal_credential",
                secret_value_bytes=b'{"private_key":"private-key"}',
                wait_seconds=1,
                interval_seconds=1,
                log=logging.getLogger("test_upsert_wrong_mek"),
            )

    assert exc.value.code == 1
    vaults_client.update_secret.assert_not_called()
