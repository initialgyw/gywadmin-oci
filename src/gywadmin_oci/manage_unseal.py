#!/usr/bin/env python3
"""manage-unseal — provision and rotate OpenBao KMS auto-unseal credentials.

Three subcommands manage the per-cluster lifecycle of the OCI resources that
allow an OpenBao instance to auto-unseal using OCI KMS:

``create``
    Provision the per-cluster AES-256 SOFTWARE KMS unseal key, IAM user,
    group, user-group membership, and an exactly-scoped IAM policy.  Then
    issue an unencrypted RSA-4096 API key for the unseal user and store the
    private key, fingerprint, and user OCID as three separate Vault secrets
    (encrypted under the shared MEK).  **Idempotent**: if all three secrets
    already exist and the fingerprint matches a current OCI API key, the
    command is a no-op (exit 0).

``rotate``
    Always generate fresh key material regardless of existing state and
    push new versions of the three Vault secrets.  IAM infrastructure is
    verified/ensured first, exactly as ``create`` does.

``show``
    Read-only JSON status report: derived resource names, discovered
    OCIDs/lifecycle states, fingerprint (never private key), secret
    presence, and overall ``provisioning_complete`` flag.

Exit codes
----------

| Code | Meaning |
|------|---------|
| 0    | Success (or clean dry-run, or idempotent no-op). |
| 1    | Generic OCI / polling failure. |
| 2    | Required Python deps missing (``oci``, ``cryptography``). |
| 3    | OCI config file missing or invalid; ``--summary-file`` structurally invalid. |
| 4    | OCI authentication preflight failed. |
| 5    | Resource not found; or API key cap (3 keys) without ``--delete-old-api-key``. |
| 6    | Invalid ``--cluster-name`` (normalization / validation failure). |

Authentication
--------------

``manage-unseal`` **always** authenticates using the admin OCI config
(``--oci-config-file``).  The optional ``--summary-file`` / ``-f`` flag is
**only** for resource-OCID discovery (compartment OCID, vault OCID, vault
management endpoint) and never for authentication.  Providing a structurally
invalid summary file is a hard failure (exit 3); there is no silent fallback.

Cluster-name normalisation
--------------------------

The raw ``--cluster-name`` value is normalised deterministically before any
resource name is derived::

    1. Trim surrounding whitespace.
    2. Lowercase.
    3. Replace every ``-`` with ``_``.
    4. Collapse consecutive ``_`` into one.
    5. Strip leading and trailing ``_``.
    6. Validate: must match ``^[a-z][a-z0-9_]*$``, max 40 characters.

Multiple raw inputs that normalise to the same ID intentionally target the
same OCI resources.  The mapping is logged at INFO when normalisation changes
the input.

Resource-name convention (example: cluster ``k8s-01`` → id ``k8s_01``)
-----------------------------------------------------------------------

* KMS key            ``k8s_01_openbao_unseal``
* IAM user           ``sa_k8s_01_openbao_unseal``
* IAM group          ``grp_k8s_01_openbao_unseal``
* IAM policy         ``policy_k8s_01_openbao_unseal``
* Vault secret       ``k8s_01_openbao_unseal_private_key``
* Vault secret       ``k8s_01_openbao_unseal_fingerprint``
* Vault secret       ``k8s_01_openbao_unseal_user_ocid``

Least-privilege policy
-----------------------

The derived IAM policy contains **exactly one** statement::

    Allow group grp_<id>_openbao_unseal to use keys in compartment <cpm>
      where target.key.id = '<key_ocid>'

No secret, bucket, vault, or broad key access is granted to the unseal group.
"""

from __future__ import annotations

import argparse
import base64
import json
import logging
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import gywadmin_oci.common as common

oci = common.oci  # type: ignore[assignment]
ServiceError = common.ServiceError  # type: ignore[assignment,misc]

# ---------------------------------------------------------------------------
# Constants / defaults
# ---------------------------------------------------------------------------
DEFAULT_COMPARTMENT = "cpm_automation"
DEFAULT_VAULT_NAME = "vault_automation"
DEFAULT_MEK_NAME = "mek_automation"
DEFAULT_OCI_CONFIG = "~/.oci/config"
DEFAULT_OCI_PROFILE = "DEFAULT"
DEFAULT_WAIT_SECONDS = 600
DEFAULT_INTERVAL_SECONDS = 10

RSA_KEY_BITS = 4096

LOGGER_NAME = "manage-unseal"

# Dedicated exit codes (in addition to 0-4 shared with other commands).
_EXIT_RESOURCE_NOT_FOUND = 5  # also API key cap exceeded
_EXIT_INVALID_CLUSTER_NAME = 6


# ---------------------------------------------------------------------------
# Argparse helpers
# ---------------------------------------------------------------------------
def _positive_int(value: str) -> int:
    """Argparse ``type`` converter that accepts only strictly positive integers.

    Rejects zero and negative values with an :class:`argparse.ArgumentTypeError`
    so argparse surfaces the problem as exit code ``2`` before any OCI calls
    are made.

    Args:
        value: Raw CLI string value to validate.

    Returns:
        The parsed integer when it is strictly positive (``> 0``).

    Raises:
        argparse.ArgumentTypeError: When ``value`` cannot be parsed as an
            integer or the resulting integer is ``<= 0``.
    """
    try:
        ivalue = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{value!r} is not a valid integer")
    if ivalue <= 0:
        raise argparse.ArgumentTypeError(f"{value!r} must be a positive integer (> 0)")
    return ivalue


# ---------------------------------------------------------------------------
# Cluster-name normalisation
# ---------------------------------------------------------------------------
_VALID_NORMALIZED_RE = re.compile(r"^[a-z][a-z0-9_]*$")


def normalize_cluster_name(raw: str) -> str:
    """Normalise a raw ``--cluster-name`` value to a stable resource-name prefix.

    Steps applied in order:

    1. Trim surrounding whitespace.
    2. Lowercase.
    3. Replace every ``-`` with ``_``.
    4. Collapse consecutive ``_`` into one.
    5. Strip leading and trailing ``_``.
    6. Validate: must match ``^[a-z][a-z0-9_]*$``, max 40 characters.

    Args:
        raw: The raw command-line value for ``--cluster-name``.

    Returns:
        The normalised identifier string.

    Raises:
        ValueError: With a descriptive message when the result fails
            validation (empty, too long, or illegal characters).
    """
    normalized = raw.strip().lower()
    normalized = normalized.replace("-", "_")
    normalized = re.sub(r"_+", "_", normalized)
    normalized = normalized.strip("_")

    if not normalized:
        raise ValueError(
            f"--cluster-name {raw!r} normalises to an empty string. "
            "Provide a non-empty name."
        )
    if len(normalized) > 40:
        raise ValueError(
            f"Normalised cluster name {normalized!r} is {len(normalized)} characters "
            "(max 40). Shorten the cluster name."
        )
    if not _VALID_NORMALIZED_RE.match(normalized):
        raise ValueError(
            f"Normalised cluster name {normalized!r} does not match "
            r"^[a-z][a-z0-9_]*$. "
            "It must start with a lowercase letter and contain only lowercase "
            "letters, digits, and underscores."
        )
    return normalized


# ---------------------------------------------------------------------------
# Name derivation
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class UnsealNames:
    """All OCI resource names derived from a normalised cluster ID.

    Every field is a plain string ready for use as an OCI display name,
    IAM resource name, or Vault secret name.
    """

    cluster_id: str
    kms_key: str
    user: str
    group: str
    policy: str
    secret_private_key: str
    secret_fingerprint: str
    secret_user_ocid: str


def derive_names(cluster_id: str) -> UnsealNames:
    """Derive all resource names from a normalised cluster ID.

    For ``cluster_id = "k8s_01"``::

        kms_key            k8s_01_openbao_unseal
        user               sa_k8s_01_openbao_unseal
        group              grp_k8s_01_openbao_unseal
        policy             policy_k8s_01_openbao_unseal
        secret_private_key k8s_01_openbao_unseal_private_key
        secret_fingerprint k8s_01_openbao_unseal_fingerprint
        secret_user_ocid   k8s_01_openbao_unseal_user_ocid

    Args:
        cluster_id: Already-normalised cluster identifier from
            :func:`normalize_cluster_name`.

    Returns:
        :class:`UnsealNames` dataclass with all derived names populated.
    """
    base = f"{cluster_id}_openbao_unseal"
    return UnsealNames(
        cluster_id=cluster_id,
        kms_key=base,
        user=f"sa_{base}",
        group=f"grp_{base}",
        policy=f"policy_{base}",
        secret_private_key=f"{base}_private_key",
        secret_fingerprint=f"{base}_fingerprint",
        secret_user_ocid=f"{base}_user_ocid",
    )


# ---------------------------------------------------------------------------
# CLI parsing
# ---------------------------------------------------------------------------
def _build_common_parser() -> argparse.ArgumentParser:
    """Build the shared parent parser for all ``manage-unseal`` subcommands.

    Returns:
        An ``ArgumentParser`` with ``add_help=False`` suitable for use as a
        ``parents=[...]`` entry in subparsers.
    """
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument(
        "--cluster-name",
        required=True,
        metavar="NAME",
        help=(
            "Logical name of the cluster (e.g. 'k8s-01'). "
            "Normalised deterministically before use: whitespace trimmed, "
            "lowercased, hyphens replaced by underscores, consecutive underscores "
            "collapsed, leading/trailing underscores stripped. "
            "Max 40 characters after normalisation."
        ),
    )
    p.add_argument(
        "--compartment",
        default=DEFAULT_COMPARTMENT,
        help=(
            "Name of the compartment containing the vault "
            "(looked up at tenancy root). (default: %(default)s)"
        ),
    )
    p.add_argument(
        "--vault-name",
        default=DEFAULT_VAULT_NAME,
        help="Display name of the target KMS Vault. (default: %(default)s)",
    )
    p.add_argument(
        "--mek-name",
        default=DEFAULT_MEK_NAME,
        help=(
            "Display name of the master encryption key used to encrypt the "
            "three Vault secrets. (default: %(default)s)"
        ),
    )
    p.add_argument(
        "--oci-config-file",
        default=DEFAULT_OCI_CONFIG,
        help="Path to the OCI CLI config file. (default: %(default)s)",
    )
    p.add_argument(
        "--oci-profile",
        default=DEFAULT_OCI_PROFILE,
        help="Profile within the OCI CLI config file. (default: %(default)s)",
    )
    p.add_argument(
        "--summary-file",
        "-f",
        default=None,
        metavar="PATH",
        help=(
            "Path to an initialize-oci-summary.json. When provided, compartment "
            "name/OCID and vault OCID/endpoint are read for resource discovery "
            "only. Authentication always uses --oci-config-file. "
            "Structurally invalid summaries hard-fail (exit 3)."
        ),
    )
    p.add_argument(
        "--region",
        default=None,
        help="Override the OCI region in the config (e.g. us-ashburn-1).",
    )
    p.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help=(
            "Increase verbosity. Repeat to increase: "
            "-v=INFO, -vv=DEBUG, -vvv=TRACE (with urllib3 DEBUG)."
        ),
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Make no mutations; emit [DRY-RUN] actions to log output.",
    )
    p.add_argument(
        "--wait-seconds",
        type=_positive_int,
        default=DEFAULT_WAIT_SECONDS,
        help=(
            "Maximum seconds to wait for a resource to reach its target state. "
            "Must be a positive integer. (default: %(default)s)"
        ),
    )
    p.add_argument(
        "--interval-seconds",
        type=_positive_int,
        default=DEFAULT_INTERVAL_SECONDS,
        help=(
            "Polling interval in seconds while waiting. "
            "Must be a positive integer. (default: %(default)s)"
        ),
    )
    return p


def _add_delete_old_api_key(sp: argparse.ArgumentParser) -> None:
    """Add the ``--delete-old-api-key`` flag to a subparser."""
    sp.add_argument(
        "--delete-old-api-key",
        action="store_true",
        default=False,
        help=(
            "If the unseal user already has 3 API keys (OCI maximum), delete "
            "the oldest non-active spare key to make room for the new key. "
            "The currently registered (active) fingerprint is always protected "
            "from automatic deletion. This flag does NOT delete the prior "
            "active credential after rotation — consumers must roll over to the "
            "new secret before a retired key is removed manually."
        ),
    )


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    """Parse command-line arguments for ``manage-unseal``.

    Args:
        argv: Optional explicit argv list (useful for testing).

    Returns:
        Parsed ``argparse.Namespace``.
    """
    common_parser = _build_common_parser()

    parser = argparse.ArgumentParser(
        prog="manage-unseal",
        description=(
            "Manage OpenBao KMS auto-unseal credentials. "
            "Run 'manage-unseal <subcommand> --help' for per-subcommand usage."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    # ---- create ------------------------------------------------------------
    sp_create = subparsers.add_parser(
        "create",
        parents=[common_parser],
        help=(
            "Provision unseal KMS key, IAM user/group/policy, and store "
            "API-key credentials as Vault secrets. Idempotent."
        ),
        description=(
            "Provision all per-cluster unseal resources and credentials. "
            "Creates an AES-256 SOFTWARE KMS unseal key, an IAM user, group, "
            "membership, and an exactly-scoped IAM policy. Then issues an "
            "unencrypted RSA-4096 API key and stores the private key, "
            "fingerprint, and user OCID as three Vault secrets (encrypted "
            "under --mek-name). Idempotent: if all three secrets exist and the "
            "fingerprint matches a live API key, the command exits 0 without "
            "any mutations."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    _add_delete_old_api_key(sp_create)

    # ---- rotate ------------------------------------------------------------
    sp_rotate = subparsers.add_parser(
        "rotate",
        parents=[common_parser],
        help="Rotate credentials: generate fresh API key and update Vault secrets.",
        description=(
            "Always generate fresh RSA-4096 API key material and push new "
            "versions of the three Vault secrets. IAM infrastructure is "
            "verified/ensured first (same as create). API-key cap: exit 5 if "
            "the user already has 3 keys and --delete-old-api-key is not set. "
            "With --delete-old-api-key: make room by removing the oldest "
            "non-active spare key (the currently registered fingerprint is "
            "protected). The prior active API key is NOT deleted automatically "
            "after rotation; consumers must roll over to the new secret first."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    _add_delete_old_api_key(sp_rotate)

    # ---- show --------------------------------------------------------------
    subparsers.add_parser(  # noqa: F841
        "show",
        parents=[common_parser],
        help="Read-only JSON status report: names, OCIDs, fingerprint, secret presence.",
        description=(
            "Emit a JSON object to stdout containing derived resource names, "
            "discovered OCIDs and lifecycle states, the registered API key "
            "fingerprint (not the private key), secret presence, and an overall "
            "``provisioning_complete`` flag. Read-only; --dry-run is inherited "
            "but is a no-op for this subcommand."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    ns = parser.parse_args(argv)
    ns.oci_config_file = Path(ns.oci_config_file).expanduser().resolve()
    if ns.summary_file is not None:
        ns.summary_file = Path(ns.summary_file).expanduser().resolve()
    return ns


# ---------------------------------------------------------------------------
# Summary-file discovery (OCID lookup only; never authentication)
# ---------------------------------------------------------------------------
def _load_summary_for_discovery(
    summary_path: Path,
    log: logging.Logger,
) -> Dict[str, str]:
    """Load compartment/vault OCIDs from a summary for resource discovery only.

    Reads the ``compartment.ocid``, ``vault.ocid``, and
    ``vault.management_endpoint`` fields from an ``initialize-oci-summary.json``
    file.  Authentication credentials in the summary are **not** used; this
    function exists solely to skip OCI API lookup calls when the caller already
    knows the OCIDs.

    Args:
        summary_path: Path to the ``initialize-oci-summary.json``.
        log: Active logger.

    Returns:
        Dict with keys ``"compartment_ocid"``, ``"compartment_name"``,
        ``"vault_ocid"``, and ``"management_endpoint"``.

    Raises:
        SystemExit: With code ``3`` if the file is missing/unreadable, has
            invalid JSON, or is missing any of the four required fields.
    """
    common.validate_summary_file(summary_path, log=log)
    data = common.load_summary(summary_path, log=log)

    try:
        compartment_ocid: str = data["compartment"]["ocid"]
        compartment_name: str = data["compartment"]["name"]
        vault_ocid: str = data["vault"]["ocid"]
        management_endpoint: str = data["vault"]["management_endpoint"]
    except (KeyError, TypeError) as exc:
        log.error(
            "Summary file %s is missing required discovery fields "
            "(compartment.ocid, compartment.name, vault.ocid, "
            "vault.management_endpoint): %s",
            summary_path,
            exc,
        )
        raise SystemExit(3) from exc

    for field_name, val in [
        ("compartment.ocid", compartment_ocid),
        ("compartment.name", compartment_name),
        ("vault.ocid", vault_ocid),
        ("vault.management_endpoint", management_endpoint),
    ]:
        if not isinstance(val, str) or not val.strip():
            log.error(
                "Summary file %s has an invalid or empty required discovery field: "
                "%s (expected a nonempty string, got %s)",
                summary_path,
                field_name,
                type(val).__name__,
            )
            raise SystemExit(3)

    log.info(
        "Loaded resource discovery from summary %s (compartment=%s [%s], vault=%s)",
        summary_path,
        compartment_name,
        compartment_ocid,
        vault_ocid,
    )
    return {
        "compartment_ocid": compartment_ocid,
        "compartment_name": compartment_name,
        "vault_ocid": vault_ocid,
        "management_endpoint": management_endpoint,
    }


# ---------------------------------------------------------------------------
# Shared-infra resolution
# ---------------------------------------------------------------------------
def _resolve_infra(
    args: argparse.Namespace,
    config: Dict[str, Any],
    tenancy_ocid: str,
    identity_client: Any,
    kms_vault_client: Any,
    log: logging.Logger,
) -> Tuple[str, str, str, str]:
    """Resolve ``(compartment_ocid, vault_ocid, management_endpoint, compartment_name)``.

    Reads from the summary file when ``args.summary_file`` is set; otherwise
    performs live OCI API lookups.  Authentication is always from the admin
    config (``args.oci_config_file``), never from the summary.

    The returned ``compartment_name`` is the **authoritative** display name of
    the compartment: taken from ``compartment.name`` in the summary file when
    ``--summary-file`` is given, or from ``args.compartment`` for live lookups.
    This name is used for the IAM policy statement — never a default or unrelated
    argument value.

    Args:
        args: Parsed CLI arguments.
        config: Validated OCI config dict (admin credentials).
        tenancy_ocid: Tenancy OCID from the authentication preflight.
        identity_client: Authenticated ``IdentityClient``.
        kms_vault_client: Authenticated ``KmsVaultClient``.
        log: Active logger.

    Returns:
        ``(compartment_ocid, vault_ocid, management_endpoint, compartment_name)``
        tuple.

    Raises:
        SystemExit: Propagated from lookup helpers (exit 5 if not found,
            exit 3 if summary is invalid or missing ``compartment.name``).
    """
    if args.summary_file is not None:
        ocids = _load_summary_for_discovery(args.summary_file, log)
        return (
            ocids["compartment_ocid"],
            ocids["vault_ocid"],
            ocids["management_endpoint"],
            ocids["compartment_name"],
        )

    compartment_ocid = common.lookup_compartment(
        identity_client, tenancy_ocid, args.compartment, log
    )
    vault_ocid, management_endpoint = common.lookup_vault(
        kms_vault_client, compartment_ocid, args.vault_name, log
    )
    return compartment_ocid, vault_ocid, management_endpoint, args.compartment


# ---------------------------------------------------------------------------
# KMS key helpers
# ---------------------------------------------------------------------------
def _lookup_kms_key_by_name(
    config: Dict[str, Any],
    compartment_ocid: str,
    management_endpoint: str,
    key_name: str,
    log: logging.Logger,
) -> Optional[Any]:
    """Find an ENABLED KMS key by display name; return the model or ``None``.

    Args:
        config: Validated OCI config dict.
        compartment_ocid: OCID of the parent compartment.
        management_endpoint: Vault management endpoint URL.
        key_name: KMS key display name to search for.
        log: Active logger.

    Returns:
        The first matching ``KeySummary`` model whose lifecycle state is
        ``ENABLED``, or ``None`` if no match is found.
    """
    mgmt = common.make_client(
        oci.key_management.KmsManagementClient,
        config,
        service_endpoint=management_endpoint,
    )
    for k in common.list_all(mgmt.list_keys, compartment_id=compartment_ocid):
        if k.display_name == key_name and k.lifecycle_state == "ENABLED":
            log.debug("KMS key '%s' -> %s", key_name, k.id)
            return k
    return None


def _require_mek(
    config: Dict[str, Any],
    compartment_ocid: str,
    management_endpoint: str,
    mek_name: str,
    log: logging.Logger,
) -> str:
    """Look up the MEK by name and return its OCID; exit 5 if not found.

    Args:
        config: Validated OCI config dict.
        compartment_ocid: OCID of the parent compartment.
        management_endpoint: Vault management endpoint URL.
        mek_name: MEK display name.
        log: Active logger.

    Returns:
        MEK OCID.

    Raises:
        SystemExit: With code ``5`` if the MEK is not found.
    """
    k = _lookup_kms_key_by_name(
        config, compartment_ocid, management_endpoint, mek_name, log
    )
    if k is None:
        log.error(
            "MEK '%s' not found in vault. Run 'initialize-oci' to create it first.",
            mek_name,
        )
        raise SystemExit(_EXIT_RESOURCE_NOT_FOUND)
    log.debug("MEK '%s' -> %s", mek_name, k.id)
    return k.id


def _validate_unseal_key_shape(
    mgmt: Any,
    key_id: str,
    key_name: str,
    log: logging.Logger,
) -> None:
    """Fetch the full key model and assert the AES-256 SOFTWARE contract.

    Calls ``KmsManagementClient.get_key(key_id)`` to retrieve the
    authoritative (server-side) key model and validates all three shape
    properties:

    * ``key_shape.algorithm == "AES"``
    * ``key_shape.length == 32``  (32 bytes = 256 bits)
    * ``protection_mode == "SOFTWARE"``

    On success, emits a DEBUG line and returns normally.

    On any mismatch or unavailable field, emits an ERROR that names the key,
    its OCID, and the observed (non-sensitive) property values, then raises
    ``SystemExit(1)`` **without** creating or mutating any resource.

    Args:
        mgmt: Authenticated ``KmsManagementClient``.
        key_id: OCID of the KMS key to validate.
        key_name: Display name of the KMS key (used in error messages only).
        log: Active logger.

    Raises:
        SystemExit: With code ``1`` when any shape property does not match
            the AES-256 SOFTWARE contract.
    """
    key_data = mgmt.get_key(key_id).data
    key_shape = getattr(key_data, "key_shape", None)
    algorithm = getattr(key_shape, "algorithm", None) if key_shape is not None else None
    length = getattr(key_shape, "length", None) if key_shape is not None else None
    protection_mode = getattr(key_data, "protection_mode", None)

    if algorithm == "AES" and length == 32 and protection_mode == "SOFTWARE":
        log.debug(
            "KMS unseal key '%s' [%s] shape verified: "
            "algorithm=%s, key_length=%s, protection_mode=%s",
            key_name,
            key_id,
            algorithm,
            length,
            protection_mode,
        )
        return

    log.error(
        "KMS unseal key '%s' [%s] does not match the required AES-256 SOFTWARE "
        "shape. Observed: algorithm=%r, key_length=%r, protection_mode=%r. "
        "Expected: algorithm='AES', key_length=32, protection_mode='SOFTWARE'. "
        "Do not attempt to replace this key automatically — inspect it in OCI "
        "and resolve the mismatch manually.",
        key_name,
        key_id,
        algorithm,
        length,
        protection_mode,
    )
    raise SystemExit(1)


def _ensure_unseal_kms_key(
    config: Dict[str, Any],
    compartment_ocid: str,
    management_endpoint: str,
    key_name: str,
    *,
    dry_run: bool,
    wait_seconds: int,
    interval_seconds: int,
    log: logging.Logger,
) -> str:
    """Ensure the per-cluster AES-256 SOFTWARE KMS unseal key is ENABLED.

    Creates the key if it does not exist.  Waits for it to become ENABLED
    if it was already being created.

    Args:
        config: Validated OCI config dict.
        compartment_ocid: OCID of the parent compartment.
        management_endpoint: Vault management endpoint URL.
        key_name: Derived KMS key display name (e.g. ``k8s_01_openbao_unseal``).
        dry_run: When ``True``, log what would happen and return a placeholder.
        wait_seconds: Max polling time.
        interval_seconds: Polling interval.
        log: Active logger.

    Returns:
        OCID of the KMS key (or a dry-run placeholder OCID).
    """
    mgmt = common.make_client(
        oci.key_management.KmsManagementClient,
        config,
        service_endpoint=management_endpoint,
    )

    existing = [
        k
        for k in common.list_all(mgmt.list_keys, compartment_id=compartment_ocid)
        if k.display_name == key_name
        and k.lifecycle_state
        in {"ENABLED", "CREATING", "ENABLING", "DISABLED", "DISABLING"}
    ]

    if existing:
        key = existing[0]
        log.info(
            "KMS unseal key '%s' exists [%s, state=%s]",
            key_name,
            key.id,
            key.lifecycle_state,
        )
        if key.lifecycle_state == "DISABLING":
            log.error(
                "KMS unseal key '%s' [%s] is currently DISABLING. "
                "Wait for it to reach DISABLED, then re-run to re-enable it.",
                key_name,
                key.id,
            )
            raise SystemExit(1)
        if key.lifecycle_state == "DISABLED":
            if dry_run:
                log.info(
                    "[DRY-RUN] KMS unseal key '%s' is DISABLED [%s]; "
                    "would re-enable it",
                    key_name,
                    key.id,
                )
                return key.id
            log.warning(
                "KMS unseal key '%s' is DISABLED [%s]; re-enabling",
                key_name,
                key.id,
            )
            mgmt.enable_key(key.id)
            common.wait_for_state(
                lambda: mgmt.get_key(key.id),
                ["ENABLED"],
                label=f"KMS key {key_name} (re-enable)",
                log=log,
                max_wait=wait_seconds,
                interval=interval_seconds,
            )
            log.info("KMS unseal key '%s' re-enabled [%s]", key_name, key.id)
            _validate_unseal_key_shape(mgmt, key.id, key_name, log)
            return key.id
        if key.lifecycle_state != "ENABLED":
            common.wait_for_state(
                lambda: mgmt.get_key(key.id),
                ["ENABLED"],
                label=f"KMS key {key_name}",
                log=log,
                max_wait=wait_seconds,
                interval=interval_seconds,
            )
        _validate_unseal_key_shape(mgmt, key.id, key_name, log)
        return key.id

    if dry_run:
        log.info(
            "[DRY-RUN] would create AES-256 SOFTWARE KMS unseal key '%s'",
            key_name,
        )
        return common.dry_run_ocid("key")

    log.info("Creating AES-256 SOFTWARE KMS unseal key '%s'", key_name)
    details = oci.key_management.models.CreateKeyDetails(
        compartment_id=compartment_ocid,
        display_name=key_name,
        key_shape=oci.key_management.models.KeyShape(algorithm="AES", length=32),
        protection_mode="SOFTWARE",
    )
    resp = mgmt.create_key(details)
    key = common.wait_for_state(
        lambda: mgmt.get_key(resp.data.id),
        ["ENABLED"],
        label=f"KMS key {key_name}",
        log=log,
        max_wait=wait_seconds,
        interval=interval_seconds,
    )
    log.info("KMS unseal key '%s' enabled [%s]", key_name, key.id)
    _validate_unseal_key_shape(mgmt, key.id, key_name, log)
    return key.id


# ---------------------------------------------------------------------------
# IAM helpers
# ---------------------------------------------------------------------------
def _ensure_unseal_user(
    identity_client: Any,
    tenancy_ocid: str,
    user_name: str,
    *,
    dry_run: bool,
    wait_seconds: int = DEFAULT_WAIT_SECONDS,
    interval_seconds: int = DEFAULT_INTERVAL_SECONDS,
    log: logging.Logger,
) -> str:
    """Create or look up the unseal IAM user; return the user OCID.

    Waits for the user to reach ACTIVE before returning, whether the user was
    already in a CREATING state when discovered or was just created.  Polling
    is read-only and therefore permitted even in dry-run mode.

    Args:
        identity_client: Authenticated ``IdentityClient``.
        tenancy_ocid: Tenancy OCID.
        user_name: Derived IAM user name.
        dry_run: When ``True``, skip mutations; CREATING resources are still
            polled since polling is read-only.
        wait_seconds: Maximum seconds to wait for ACTIVE.
        interval_seconds: Polling interval in seconds.
        log: Active logger.

    Returns:
        User OCID (or dry-run placeholder).
    """
    existing = [
        u
        for u in common.list_all(
            identity_client.list_users,
            compartment_id=tenancy_ocid,
            name=user_name,
        )
        if u.name == user_name and u.lifecycle_state in {"ACTIVE", "CREATING"}
    ]
    if existing:
        user = existing[0]
        log.info(
            "IAM user '%s' exists [%s, state=%s]",
            user_name,
            user.id,
            user.lifecycle_state,
        )
        if user.lifecycle_state != "ACTIVE":
            # CREATING → wait for ACTIVE. Polling is read-only; permitted in dry-run.
            user_id = user.id
            common.wait_for_state(
                lambda: identity_client.get_user(user_id),
                ["ACTIVE"],
                label=f"IAM user {user_name}",
                log=log,
                max_wait=wait_seconds,
                interval=interval_seconds,
            )
        return user.id

    if dry_run:
        log.info("[DRY-RUN] would create IAM user '%s'", user_name)
        return common.dry_run_ocid("user")

    log.info("Creating IAM user '%s'", user_name)
    details = oci.identity.models.CreateUserDetails(
        compartment_id=tenancy_ocid,
        name=user_name,
        description="OpenBao unseal service account managed by manage-unseal.",
    )
    resp = identity_client.create_user(details)
    new_user_id = resp.data.id
    log.info("IAM user '%s' created [%s]; waiting for ACTIVE", user_name, new_user_id)
    user = common.wait_for_state(
        lambda: identity_client.get_user(new_user_id),
        ["ACTIVE"],
        label=f"IAM user {user_name}",
        log=log,
        max_wait=wait_seconds,
        interval=interval_seconds,
    )
    log.info("IAM user '%s' active [%s]", user_name, user.id)
    return user.id


def _ensure_unseal_group(
    identity_client: Any,
    tenancy_ocid: str,
    group_name: str,
    *,
    dry_run: bool,
    wait_seconds: int = DEFAULT_WAIT_SECONDS,
    interval_seconds: int = DEFAULT_INTERVAL_SECONDS,
    log: logging.Logger,
) -> str:
    """Create or look up the unseal IAM group; return the group OCID.

    Waits for the group to reach ACTIVE before returning, whether the group
    was already in a CREATING state or was just created.  Polling is read-only
    and therefore permitted even in dry-run mode.

    Args:
        identity_client: Authenticated ``IdentityClient``.
        tenancy_ocid: Tenancy OCID.
        group_name: Derived IAM group name.
        dry_run: When ``True``, skip mutations; CREATING resources are still
            polled since polling is read-only.
        wait_seconds: Maximum seconds to wait for ACTIVE.
        interval_seconds: Polling interval in seconds.
        log: Active logger.

    Returns:
        Group OCID (or dry-run placeholder).
    """
    existing = [
        g
        for g in common.list_all(
            identity_client.list_groups,
            compartment_id=tenancy_ocid,
            name=group_name,
        )
        if g.name == group_name and g.lifecycle_state in {"ACTIVE", "CREATING"}
    ]
    if existing:
        group = existing[0]
        log.info(
            "IAM group '%s' exists [%s, state=%s]",
            group_name,
            group.id,
            group.lifecycle_state,
        )
        if group.lifecycle_state != "ACTIVE":
            # CREATING → wait for ACTIVE. Polling is read-only; permitted in dry-run.
            group_id = group.id
            common.wait_for_state(
                lambda: identity_client.get_group(group_id),
                ["ACTIVE"],
                label=f"IAM group {group_name}",
                log=log,
                max_wait=wait_seconds,
                interval=interval_seconds,
            )
        return group.id

    if dry_run:
        log.info("[DRY-RUN] would create IAM group '%s'", group_name)
        return common.dry_run_ocid("group")

    log.info("Creating IAM group '%s'", group_name)
    details = oci.identity.models.CreateGroupDetails(
        compartment_id=tenancy_ocid,
        name=group_name,
        description="OpenBao unseal group managed by manage-unseal.",
    )
    resp = identity_client.create_group(details)
    new_group_id = resp.data.id
    log.info(
        "IAM group '%s' created [%s]; waiting for ACTIVE", group_name, new_group_id
    )
    group = common.wait_for_state(
        lambda: identity_client.get_group(new_group_id),
        ["ACTIVE"],
        label=f"IAM group {group_name}",
        log=log,
        max_wait=wait_seconds,
        interval=interval_seconds,
    )
    log.info("IAM group '%s' active [%s]", group_name, group.id)
    return group.id


def _ensure_unseal_membership(
    identity_client: Any,
    tenancy_ocid: str,
    user_ocid: str,
    group_ocid: str,
    *,
    dry_run: bool,
    wait_seconds: int = DEFAULT_WAIT_SECONDS,
    interval_seconds: int = DEFAULT_INTERVAL_SECONDS,
    log: logging.Logger,
) -> None:
    """Ensure the unseal user is a member of the unseal group.

    Skips the API call if both OCIDs are dry-run placeholders.  When an
    existing membership is in the CREATING state, polls until ACTIVE before
    returning.  A freshly created membership is also polled until ACTIVE.

    Args:
        identity_client: Authenticated ``IdentityClient``.
        tenancy_ocid: Tenancy OCID.
        user_ocid: User OCID (may be a dry-run placeholder).
        group_ocid: Group OCID (may be a dry-run placeholder).
        dry_run: When ``True``, skip mutations; CREATING memberships are still
            polled since polling is read-only.
        wait_seconds: Maximum seconds to wait for ACTIVE.
        interval_seconds: Polling interval in seconds.
        log: Active logger.
    """
    if common.is_dry_run_ocid(user_ocid) or common.is_dry_run_ocid(group_ocid):
        if dry_run:
            log.info(
                "[DRY-RUN] would add user %s to group %s",
                user_ocid,
                group_ocid,
            )
        return

    memberships = common.list_all(
        identity_client.list_user_group_memberships,
        compartment_id=tenancy_ocid,
        user_id=user_ocid,
        group_id=group_ocid,
    )
    if memberships:
        membership = memberships[0]
        membership_state = getattr(membership, "lifecycle_state", "ACTIVE")
        if membership_state not in {"ACTIVE"}:
            # CREATING membership → wait for ACTIVE.
            # Polling is read-only; permitted in dry-run.
            membership_id = membership.id
            log.info(
                "Membership user %s / group %s exists [state=%s]; waiting for ACTIVE",
                user_ocid,
                group_ocid,
                membership_state,
            )
            common.wait_for_state(
                lambda: identity_client.get_user_group_membership(membership_id),
                ["ACTIVE"],
                label=f"membership user={user_ocid} group={group_ocid}",
                log=log,
                max_wait=wait_seconds,
                interval=interval_seconds,
            )
        else:
            log.info("User %s already in group %s", user_ocid, group_ocid)
        return

    if dry_run:
        log.info(
            "[DRY-RUN] would add user %s to group %s",
            user_ocid,
            group_ocid,
        )
        return

    log.info("Adding user %s to group %s", user_ocid, group_ocid)
    resp = identity_client.add_user_to_group(
        oci.identity.models.AddUserToGroupDetails(
            user_id=user_ocid,
            group_id=group_ocid,
        )
    )
    membership_id = resp.data.id
    log.info("Membership created [%s]; waiting for ACTIVE", membership_id)
    common.wait_for_state(
        lambda: identity_client.get_user_group_membership(membership_id),
        ["ACTIVE"],
        label=f"membership user={user_ocid} group={group_ocid}",
        log=log,
        max_wait=wait_seconds,
        interval=interval_seconds,
    )


# ---------------------------------------------------------------------------
# Policy helpers
# ---------------------------------------------------------------------------
def _unseal_policy_statement(
    group_name: str,
    compartment_name: str,
    key_ocid: str,
) -> str:
    """Build the exactly-scoped unseal IAM policy statement.

    The statement grants only ``use keys`` permission, scoped to the specific
    per-cluster KMS key OCID.  No secret, bucket, vault, or broad key access
    is included.

    Args:
        group_name: Derived IAM group name.
        compartment_name: Compartment display name (not OCID).
        key_ocid: OCID of the per-cluster KMS unseal key.

    Returns:
        The full OCI IAM policy statement string.
    """
    return (
        f"Allow group {group_name} to use keys in compartment {compartment_name} "
        f"where target.key.id = '{key_ocid}'"
    )


def _ensure_unseal_policy(
    identity_client: Any,
    tenancy_ocid: str,
    policy_name: str,
    group_name: str,
    compartment_name: str,
    key_ocid: str,
    *,
    dry_run: bool,
    wait_seconds: int = DEFAULT_WAIT_SECONDS,
    interval_seconds: int = DEFAULT_INTERVAL_SECONDS,
    log: logging.Logger,
) -> str:
    """Ensure the unseal policy exists with **exactly** one scoped statement.

    If the policy already exists but has a different set of statements, it is
    updated to contain exactly the single correct statement (enforcing
    least-privilege idempotently).

    Waits for the policy to reach ACTIVE in all mutation paths (new creation,
    update to fix statements, or resolution of a pre-existing CREATING state).

    Args:
        identity_client: Authenticated ``IdentityClient``.
        tenancy_ocid: Tenancy OCID (policies are created at the tenancy root).
        policy_name: Derived policy name.
        group_name: Derived IAM group name.
        compartment_name: Compartment display name (not OCID).
        key_ocid: Per-cluster KMS key OCID.
        dry_run: When ``True``, log what would happen without mutating;
            CREATING policies are still polled since polling is read-only.
        wait_seconds: Maximum seconds to wait for ACTIVE.
        interval_seconds: Polling interval in seconds.
        log: Active logger.

    Returns:
        Policy OCID (or dry-run placeholder).
    """
    if common.is_dry_run_ocid(key_ocid):
        # Key is a placeholder; include it in the [DRY-RUN] message but skip
        # any real policy lookup/creation since the OCID is not real.
        expected_stmt = _unseal_policy_statement(group_name, compartment_name, key_ocid)
        log.info(
            "[DRY-RUN] would create/update policy '%s' with statement: %s",
            policy_name,
            expected_stmt,
        )
        return common.dry_run_ocid("policy")

    expected_stmt = _unseal_policy_statement(group_name, compartment_name, key_ocid)
    expected_norm = " ".join(expected_stmt.split()).lower()

    existing = [
        p
        for p in common.list_all(
            identity_client.list_policies,
            compartment_id=tenancy_ocid,
        )
        if p.name == policy_name and p.lifecycle_state in {"ACTIVE", "CREATING"}
    ]

    if existing:
        policy = existing[0]
        if policy.lifecycle_state != "ACTIVE":
            # CREATING → wait for ACTIVE. Polling is read-only; permitted in dry-run.
            policy_id = policy.id
            log.info(
                "Policy '%s' is CREATING [%s]; waiting for ACTIVE",
                policy_name,
                policy_id,
            )
            policy = common.wait_for_state(
                lambda: identity_client.get_policy(policy_id),
                ["ACTIVE"],
                label=f"IAM policy {policy_name}",
                log=log,
                max_wait=wait_seconds,
                interval=interval_seconds,
            )

        stmts = list(policy.statements or [])
        norm_stmts = [" ".join(s.split()).lower() for s in stmts]

        if len(norm_stmts) == 1 and norm_stmts[0] == expected_norm:
            log.info(
                "Policy '%s' exists with the correct statement [%s]",
                policy_name,
                policy.id,
            )
            return policy.id

        log.warning(
            "Policy '%s' has %d statement(s) but expected exactly 1 (correctly scoped). "
            "Updating to enforce least privilege.",
            policy_name,
            len(stmts),
        )
        if dry_run:
            log.info(
                "[DRY-RUN] would update policy '%s' to exactly: %s",
                policy_name,
                expected_stmt,
            )
            return policy.id

        identity_client.update_policy(
            policy.id,
            oci.identity.models.UpdatePolicyDetails(
                statements=[expected_stmt],
                description=(
                    policy.description
                    or f"OpenBao unseal policy: {group_name} may use the cluster unseal key only."
                ),
            ),
        )
        log.info(
            "Policy '%s' updated with exactly the one scoped statement [%s]; "
            "waiting for ACTIVE",
            policy_name,
            policy.id,
        )
        policy_id = policy.id
        common.wait_for_state(
            lambda: identity_client.get_policy(policy_id),
            ["ACTIVE"],
            label=f"IAM policy {policy_name} (post-update)",
            log=log,
            max_wait=wait_seconds,
            interval=interval_seconds,
        )
        return policy.id

    if dry_run:
        log.info(
            "[DRY-RUN] would create policy '%s' with statement: %s",
            policy_name,
            expected_stmt,
        )
        return common.dry_run_ocid("policy")

    log.info("Creating policy '%s' with exactly-scoped statement", policy_name)
    details = oci.identity.models.CreatePolicyDetails(
        compartment_id=tenancy_ocid,
        name=policy_name,
        description=(
            f"OpenBao unseal policy: allows {group_name} to use the "
            f"cluster unseal key only."
        ),
        statements=[expected_stmt],
    )
    resp = identity_client.create_policy(details)
    new_policy_id = resp.data.id
    log.info("Policy '%s' created [%s]; waiting for ACTIVE", policy_name, new_policy_id)
    policy = common.wait_for_state(
        lambda: identity_client.get_policy(new_policy_id),
        ["ACTIVE"],
        label=f"IAM policy {policy_name}",
        log=log,
        max_wait=wait_seconds,
        interval=interval_seconds,
    )
    log.info("Policy '%s' active [%s]", policy_name, policy.id)
    return policy.id


# ---------------------------------------------------------------------------
# Vault secret helpers
# ---------------------------------------------------------------------------
def _require_secret_uses_mek(
    secret: Optional[Any],
    *,
    secret_name: str,
    mek_ocid: str,
    log: logging.Logger,
) -> None:
    """Fail closed when an existing credential secret is not encrypted by the MEK."""
    if secret is None:
        return

    actual_key_ocid = getattr(secret, "key_id", None)
    if actual_key_ocid == mek_ocid:
        return

    log.error(
        "Vault secret '%s' [%s] is encrypted with key %s, not the required MEK %s. "
        "Refusing to overwrite or accept it.",
        secret_name,
        getattr(secret, "id", "<unknown>"),
        actual_key_ocid or "<unknown>",
        mek_ocid,
    )
    raise SystemExit(1)


def _require_contract_secrets_use_mek(
    vaults_client: Any,
    *,
    compartment_ocid: str,
    vault_ocid: str,
    names: UnsealNames,
    mek_ocid: str,
    log: logging.Logger,
) -> None:
    """Verify every existing credential-contract secret uses the selected MEK."""
    for secret_name in (
        names.secret_private_key,
        names.secret_fingerprint,
        names.secret_user_ocid,
    ):
        existing = common.lookup_existing_secret(
            vaults_client,
            compartment_ocid,
            vault_ocid,
            secret_name,
            log,
        )
        _require_secret_uses_mek(
            existing,
            secret_name=secret_name,
            mek_ocid=mek_ocid,
            log=log,
        )


def _upsert_vault_secret(
    vaults_client: Any,
    *,
    compartment_ocid: str,
    vault_ocid: str,
    mek_ocid: str,
    secret_name: str,
    secret_value_bytes: bytes,
    wait_seconds: int,
    interval_seconds: int,
    log: logging.Logger,
) -> str:
    """Create or update a Vault secret; return its OCID.

    The ``secret_value_bytes`` are base64-encoded before storage (OCI Vault
    requires base64 content).  They are **never logged**.

    Args:
        vaults_client: Authenticated ``oci.vault.VaultsClient``.
        compartment_ocid: Compartment OCID.
        vault_ocid: Vault OCID.
        mek_ocid: MEK OCID used to encrypt the secret.
        secret_name: Secret display name.
        secret_value_bytes: Raw secret bytes (private key PEM, fingerprint
            string, or user OCID string, all UTF-8).
        wait_seconds: Max polling time for the secret to reach ACTIVE.
        interval_seconds: Polling interval.
        log: Active logger.

    Returns:
        OCID of the created or updated secret.
    """
    b64 = base64.b64encode(secret_value_bytes).decode("ascii")
    existing = common.lookup_existing_secret(
        vaults_client, compartment_ocid, vault_ocid, secret_name, log
    )
    _require_secret_uses_mek(
        existing,
        secret_name=secret_name,
        mek_ocid=mek_ocid,
        log=log,
    )

    if existing is None:
        content = oci.vault.models.Base64SecretContentDetails(
            content_type="BASE64",
            content=b64,
            stage="CURRENT",
        )
        details = oci.vault.models.CreateSecretDetails(
            compartment_id=compartment_ocid,
            vault_id=vault_ocid,
            key_id=mek_ocid,
            secret_name=secret_name,
            secret_content=content,
        )
        log.info("Creating Vault secret '%s'", secret_name)
        resp = vaults_client.create_secret(details)
        secret = common.wait_for_state(
            lambda: vaults_client.get_secret(resp.data.id),
            ["ACTIVE"],
            label=f"secret {secret_name}",
            log=log,
            max_wait=wait_seconds,
            interval=interval_seconds,
        )
        log.info("Vault secret '%s' created [%s]", secret_name, secret.id)
        return secret.id

    # Update existing secret.
    if existing.lifecycle_state != "ACTIVE":
        common.wait_for_state(
            lambda: vaults_client.get_secret(existing.id),
            ["ACTIVE"],
            label=f"secret {secret_name}",
            log=log,
            max_wait=wait_seconds,
            interval=interval_seconds,
        )
    content = oci.vault.models.Base64SecretContentDetails(
        content_type="BASE64",
        content=b64,
        stage="CURRENT",
    )
    details = oci.vault.models.UpdateSecretDetails(secret_content=content)
    log.info("Updating Vault secret '%s' [%s]", secret_name, existing.id)
    vaults_client.update_secret(existing.id, details)
    secret = common.wait_for_state(
        lambda: vaults_client.get_secret(existing.id),
        ["ACTIVE"],
        label=f"secret {secret_name}",
        log=log,
        max_wait=wait_seconds,
        interval=interval_seconds,
    )
    log.info("Vault secret '%s' updated [%s]", secret_name, secret.id)
    return secret.id


def _read_secret_value(
    vaults_client: Any,
    secrets_client: Any,
    compartment_ocid: str,
    vault_ocid: str,
    secret_name: str,
    log: logging.Logger,
) -> Optional[str]:
    """Read the LATEST stage value of a Vault secret; return ``None`` on any failure.

    Args:
        vaults_client: Authenticated ``oci.vault.VaultsClient``.
        secrets_client: Authenticated ``oci.secrets.SecretsClient``.
        compartment_ocid: Compartment OCID.
        vault_ocid: Vault OCID.
        secret_name: Secret display name.
        log: Active logger.

    Returns:
        Decoded UTF-8 string (stripped of whitespace), or ``None`` if the
        secret does not exist or cannot be read.
    """
    try:
        existing = common.lookup_existing_secret(
            vaults_client, compartment_ocid, vault_ocid, secret_name, log
        )
        if existing is None:
            return None
        bundle = secrets_client.get_secret_bundle(
            secret_id=existing.id, stage="LATEST"
        ).data
        raw_b64 = getattr(
            getattr(bundle, "secret_bundle_content", None), "content", None
        )
        if raw_b64 is None:
            return None
        return base64.b64decode(raw_b64).decode("utf-8").strip()
    except Exception as exc:
        log.debug("Could not read secret '%s': %s", secret_name, exc)
        return None


# ---------------------------------------------------------------------------
# Idempotency check (create)
# ---------------------------------------------------------------------------
def _check_create_complete(
    vaults_client: Any,
    secrets_client: Any,
    identity_client: Any,
    compartment_ocid: str,
    vault_ocid: str,
    names: UnsealNames,
    user_ocid: str,
    log: logging.Logger,
) -> bool:
    """Return ``True`` only when ``create`` is fully provisioned and valid.

    All five conditions must hold simultaneously:

    1. All three secrets (``private_key``, ``fingerprint``, ``user_ocid``)
       exist and are ACTIVE.
    2. The private-key secret contains a valid **unencrypted RSA** key.
    3. The OCI fingerprint derived from that private key matches the value
       stored in the fingerprint secret.
    4. The stored fingerprint corresponds to a live API key on the unseal user.
    5. The stored user OCID matches the actual (derived) user OCID.

    Private key material is **never** logged.

    Args:
        vaults_client: Authenticated ``oci.vault.VaultsClient``.
        secrets_client: Authenticated ``oci.secrets.SecretsClient``.
        identity_client: Authenticated ``IdentityClient``.
        compartment_ocid: Compartment OCID.
        vault_ocid: Vault OCID.
        names: Derived resource names.
        user_ocid: Actual user OCID (must not be a dry-run placeholder).
        log: Active logger.

    Returns:
        ``True`` if provisioning is complete and valid; ``False`` otherwise.
    """
    # Check all three secrets exist.
    s_fp = common.lookup_existing_secret(
        vaults_client, compartment_ocid, vault_ocid, names.secret_fingerprint, log
    )
    s_pk = common.lookup_existing_secret(
        vaults_client, compartment_ocid, vault_ocid, names.secret_private_key, log
    )
    s_uid = common.lookup_existing_secret(
        vaults_client, compartment_ocid, vault_ocid, names.secret_user_ocid, log
    )

    secret_states = tuple(
        getattr(secret, "lifecycle_state", None) for secret in (s_fp, s_pk, s_uid)
    )
    if not all(
        secret is not None and state == "ACTIVE"
        for secret, state in zip((s_fp, s_pk, s_uid), secret_states)
    ):
        log.debug(
            "Not all 3 secrets are ACTIVE (fingerprint=%s, private_key=%s, "
            "user_ocid=%s; states=%s); create is not complete.",
            bool(s_fp),
            bool(s_pk),
            bool(s_uid),
            secret_states,
        )
        return False

    # Read fingerprint secret value.
    fp_value = _read_secret_value(
        vaults_client,
        secrets_client,
        compartment_ocid,
        vault_ocid,
        names.secret_fingerprint,
        log,
    )
    if not fp_value:
        log.debug("Cannot read fingerprint secret; create is not complete.")
        return False

    # Read private-key secret value and validate it is an unencrypted RSA key
    # whose derived fingerprint matches the stored fingerprint.
    # The raw PEM is intentionally not logged.
    pk_value = _read_secret_value(
        vaults_client,
        secrets_client,
        compartment_ocid,
        vault_ocid,
        names.secret_private_key,
        log,
    )
    if not pk_value:
        log.debug("Cannot read private_key secret; create is not complete.")
        return False
    try:
        derived_fp = common.fingerprint_from_private_pem(pk_value)
    except (ValueError, RuntimeError):
        log.debug(
            "Private key secret is invalid (encrypted / non-RSA / malformed); "
            "create is not complete."
        )
        return False
    if derived_fp != fp_value:
        log.debug(
            "Private key fingerprint does not match stored fingerprint; "
            "create is not complete."
        )
        return False

    # Read user_ocid secret value.
    uid_value = _read_secret_value(
        vaults_client,
        secrets_client,
        compartment_ocid,
        vault_ocid,
        names.secret_user_ocid,
        log,
    )
    if not uid_value:
        log.debug("Cannot read user_ocid secret; create is not complete.")
        return False

    # Stored fingerprint must match a live API key on the user.
    existing_keys = common.list_all(identity_client.list_api_keys, user_id=user_ocid)
    active_fps = {k.fingerprint for k in existing_keys}
    if fp_value not in active_fps:
        log.debug(
            "Fingerprint from secret not found in user's live API keys; create is not complete."
        )
        return False

    # Stored user OCID must match the actual user OCID.
    if uid_value != user_ocid:
        log.debug(
            "user_ocid secret value does not match actual user OCID; create is not complete."
        )
        return False

    return True


# ---------------------------------------------------------------------------
# API key cap management
# ---------------------------------------------------------------------------
def _handle_api_key_cap(
    identity_client: Any,
    user_ocid: str,
    *,
    delete_old_api_key: bool,
    protected_fingerprint: Optional[str] = None,
    dry_run: bool,
    log: logging.Logger,
) -> None:
    """Check the API key cap; optionally make room by removing an expendable spare.

    Does nothing if the user has fewer than 3 API keys.  When
    ``delete_old_api_key=True`` the oldest key **that is not the currently
    registered (protected) fingerprint** is removed.  If no safe candidate
    exists (all remaining keys carry the protected fingerprint), exit 5
    without any deletion.

    Args:
        identity_client: Authenticated ``IdentityClient``.
        user_ocid: User OCID (must not be a dry-run placeholder).
        delete_old_api_key: When ``True``, delete the oldest non-protected key
            to make room.
        protected_fingerprint: Fingerprint of the currently registered/active
            API key that must **never** be deleted automatically.  ``None``
            means no key is protected.
        dry_run: When ``True``, only log what would happen without mutating.
        log: Active logger.

    Raises:
        SystemExit: With code ``5`` if at/over cap and ``delete_old_api_key``
            is ``False``, or if ``delete_old_api_key`` is ``True`` but no
            safe (non-protected) candidate exists for deletion.
    """
    existing_keys = common.list_all(identity_client.list_api_keys, user_id=user_ocid)
    if len(existing_keys) < 3:
        return  # Room available; nothing to do.

    if not delete_old_api_key:
        log.error(
            "User already has %d API keys (OCI maximum is 3). "
            "Remove one manually or pass --delete-old-api-key.",
            len(existing_keys),
        )
        raise SystemExit(_EXIT_RESOURCE_NOT_FOUND)

    # Select deletion candidates: exclude the currently registered fingerprint.
    candidates = [k for k in existing_keys if k.fingerprint != protected_fingerprint]
    if not candidates:
        log.error(
            "Cannot safely make room at the 3-key cap: every existing API key "
            "fingerprint matches the protected active credential (%s). "
            "Manually remove an unused spare key before retrying.",
            protected_fingerprint,
        )
        raise SystemExit(_EXIT_RESOURCE_NOT_FOUND)

    oldest_safe = sorted(candidates, key=lambda k: k.time_created)[0]
    if dry_run:
        log.info(
            "[DRY-RUN] would delete oldest non-protected API key %s "
            "(time_created=%s) to make room",
            oldest_safe.fingerprint,
            oldest_safe.time_created,
        )
        return

    log.info(
        "Deleting oldest non-protected API key %s (time_created=%s) to make room",
        oldest_safe.fingerprint,
        oldest_safe.time_created,
    )
    identity_client.delete_api_key(
        user_id=user_ocid, fingerprint=oldest_safe.fingerprint
    )


def _generate_and_upload_api_key(
    identity_client: Any,
    user_ocid: str,
    user_name: str,
    log: logging.Logger,
) -> Dict[str, Any]:
    """Generate an unencrypted RSA-4096 API key and upload the public half to OCI.

    The private key is **never** logged.

    Args:
        identity_client: Authenticated ``IdentityClient``.
        user_ocid: User OCID.
        user_name: IAM user name (for log messages only).
        log: Active logger.

    Returns:
        Keypair dict from :func:`~gywadmin_oci.common.generate_unencrypted_rsa_api_key`
        with keys ``"private_pem"``, ``"public_pem"``, ``"public_der"``,
        ``"fingerprint"``.
    """
    log.info(
        "Generating RSA-%d unencrypted API key for user '%s'",
        RSA_KEY_BITS,
        user_name,
    )
    keypair = common.generate_unencrypted_rsa_api_key(RSA_KEY_BITS)
    log.info(
        "Uploading public key to user '%s' [fingerprint=%s]",
        user_name,
        keypair["fingerprint"],
    )
    identity_client.upload_api_key(
        user_ocid,
        oci.identity.models.CreateApiKeyDetails(key=keypair["public_pem"]),
    )
    return keypair


# ---------------------------------------------------------------------------
# Subcommand implementations
# ---------------------------------------------------------------------------
def cmd_create(args: argparse.Namespace, log: logging.Logger) -> int:
    """Implement the ``create`` subcommand.

    Provisions all per-cluster unseal resources (KMS key, IAM user/group/
    membership/policy) and, when not already complete, issues a new API key
    and stores the three Vault secrets.

    Args:
        args: Parsed CLI arguments.
        log: Active logger.

    Returns:
        Process exit code (``0`` on success or no-op).
    """
    log.info("manage-unseal create starting (dry_run=%s)", args.dry_run)

    # Normalize cluster name (exit 6 on validation failure).
    try:
        cluster_id = normalize_cluster_name(args.cluster_name)
    except ValueError as exc:
        log.error("Invalid --cluster-name %r: %s", args.cluster_name, exc)
        raise SystemExit(_EXIT_INVALID_CLUSTER_NAME) from exc

    if cluster_id != args.cluster_name:
        log.info(
            "cluster_name normalized: %r -> %r",
            args.cluster_name,
            cluster_id,
        )

    names = derive_names(cluster_id)
    log.debug("Derived names: %s", asdict(names))

    common.require_dependencies(log, need_cryptography=True)

    config = common.load_oci_config(
        config_path=args.oci_config_file,
        profile=args.oci_profile,
        region_override=args.region,
        log=log,
    )
    tenancy_ocid = common.verify_oci_authenticated(config, log, level=logging.DEBUG)

    identity_client = common.make_client(oci.identity.IdentityClient, config)
    kms_vault_client = common.make_client(oci.key_management.KmsVaultClient, config)
    vaults_client = common.make_client(oci.vault.VaultsClient, config)

    try:
        compartment_ocid, vault_ocid, management_endpoint, compartment_name = (
            _resolve_infra(
                args, config, tenancy_ocid, identity_client, kms_vault_client, log
            )
        )

        mek_ocid = _require_mek(
            config, compartment_ocid, management_endpoint, args.mek_name, log
        )
        _require_contract_secrets_use_mek(
            vaults_client,
            compartment_ocid=compartment_ocid,
            vault_ocid=vault_ocid,
            names=names,
            mek_ocid=mek_ocid,
            log=log,
        )

        kms_key_ocid = _ensure_unseal_kms_key(
            config,
            compartment_ocid,
            management_endpoint,
            names.kms_key,
            dry_run=args.dry_run,
            wait_seconds=args.wait_seconds,
            interval_seconds=args.interval_seconds,
            log=log,
        )
        user_ocid = _ensure_unseal_user(
            identity_client,
            tenancy_ocid,
            names.user,
            dry_run=args.dry_run,
            wait_seconds=args.wait_seconds,
            interval_seconds=args.interval_seconds,
            log=log,
        )
        group_ocid = _ensure_unseal_group(
            identity_client,
            tenancy_ocid,
            names.group,
            dry_run=args.dry_run,
            wait_seconds=args.wait_seconds,
            interval_seconds=args.interval_seconds,
            log=log,
        )
        _ensure_unseal_membership(
            identity_client,
            tenancy_ocid,
            user_ocid,
            group_ocid,
            dry_run=args.dry_run,
            wait_seconds=args.wait_seconds,
            interval_seconds=args.interval_seconds,
            log=log,
        )
        _ensure_unseal_policy(
            identity_client,
            tenancy_ocid,
            names.policy,
            names.group,
            compartment_name,
            kms_key_ocid,
            dry_run=args.dry_run,
            wait_seconds=args.wait_seconds,
            interval_seconds=args.interval_seconds,
            log=log,
        )

        # Idempotency check and post-write validation both use secrets_client.
        secrets_client = common.make_client(oci.secrets.SecretsClient, config)

        # Idempotency check — read-only; works even in dry-run when user is real.
        if not common.is_dry_run_ocid(user_ocid):
            if _check_create_complete(
                vaults_client,
                secrets_client,
                identity_client,
                compartment_ocid,
                vault_ocid,
                names,
                user_ocid,
                log,
            ):
                log.info(
                    "manage-unseal create: all credentials are already provisioned "
                    "and valid. No changes needed. (idempotent no-op)"
                )
                return 0

        if args.dry_run:
            log.info(
                "[DRY-RUN] would generate RSA-%d API key for user '%s', upload "
                "to OCI, and store 3 Vault secrets "
                "(%s, %s, %s)",
                RSA_KEY_BITS,
                names.user,
                names.secret_private_key,
                names.secret_fingerprint,
                names.secret_user_ocid,
            )
            log.info("manage-unseal create complete (dry_run=True)")
            return 0

        # A partial/invalid credential set may still be deployed. Preserve its
        # registered fingerprint while making room for a repair credential.
        protected_fingerprint = _read_secret_value(
            vaults_client,
            secrets_client,
            compartment_ocid,
            vault_ocid,
            names.secret_fingerprint,
            log,
        )

        # Real run: cap check → generate → upload → store secrets.
        _handle_api_key_cap(
            identity_client,
            user_ocid,
            delete_old_api_key=args.delete_old_api_key,
            protected_fingerprint=protected_fingerprint,
            dry_run=False,
            log=log,
        )

        keypair = _generate_and_upload_api_key(
            identity_client, user_ocid, names.user, log
        )

        _upsert_vault_secret(
            vaults_client,
            compartment_ocid=compartment_ocid,
            vault_ocid=vault_ocid,
            mek_ocid=mek_ocid,
            secret_name=names.secret_private_key,
            secret_value_bytes=keypair["private_pem"].encode("utf-8"),
            wait_seconds=args.wait_seconds,
            interval_seconds=args.interval_seconds,
            log=log,
        )
        _upsert_vault_secret(
            vaults_client,
            compartment_ocid=compartment_ocid,
            vault_ocid=vault_ocid,
            mek_ocid=mek_ocid,
            secret_name=names.secret_fingerprint,
            secret_value_bytes=keypair["fingerprint"].encode("utf-8"),
            wait_seconds=args.wait_seconds,
            interval_seconds=args.interval_seconds,
            log=log,
        )
        _upsert_vault_secret(
            vaults_client,
            compartment_ocid=compartment_ocid,
            vault_ocid=vault_ocid,
            mek_ocid=mek_ocid,
            secret_name=names.secret_user_ocid,
            secret_value_bytes=user_ocid.encode("utf-8"),
            wait_seconds=args.wait_seconds,
            interval_seconds=args.interval_seconds,
            log=log,
        )

        # Post-write validation: confirm the stored credential set is internally
        # consistent before declaring success.  No prior key is deleted here.
        log.info("Validating stored credential set after write...")
        if not _check_create_complete(
            vaults_client,
            secrets_client,
            identity_client,
            compartment_ocid,
            vault_ocid,
            names,
            user_ocid,
            log,
        ):
            log.error(
                "Post-write validation failed: stored secrets do not form a "
                "consistent credential set. Inspect with 'manage-unseal show'. "
                "No prior key was deleted."
            )
            return 1

    except ServiceError as exc:
        log.error(
            "Aborting on OCI error (status=%s code=%s): %s",
            getattr(exc, "status", "?"),
            getattr(exc, "code", "?"),
            getattr(exc, "message", str(exc)),
        )
        return 1
    except (RuntimeError, TimeoutError, OSError) as exc:
        log.error("Aborting: %s", exc)
        return 1

    log.info("manage-unseal create complete.")
    return 0


def cmd_rotate(args: argparse.Namespace, log: logging.Logger) -> int:
    """Implement the ``rotate`` subcommand.

    Always generates fresh RSA-4096 API key material and pushes new versions
    of all three Vault secrets, regardless of existing state.

    Args:
        args: Parsed CLI arguments.
        log: Active logger.

    Returns:
        Process exit code (``0`` on success).
    """
    log.info("manage-unseal rotate starting (dry_run=%s)", args.dry_run)

    try:
        cluster_id = normalize_cluster_name(args.cluster_name)
    except ValueError as exc:
        log.error("Invalid --cluster-name %r: %s", args.cluster_name, exc)
        raise SystemExit(_EXIT_INVALID_CLUSTER_NAME) from exc

    if cluster_id != args.cluster_name:
        log.info(
            "cluster_name normalized: %r -> %r",
            args.cluster_name,
            cluster_id,
        )

    names = derive_names(cluster_id)
    log.debug("Derived names: %s", asdict(names))

    common.require_dependencies(log, need_cryptography=True)

    config = common.load_oci_config(
        config_path=args.oci_config_file,
        profile=args.oci_profile,
        region_override=args.region,
        log=log,
    )
    tenancy_ocid = common.verify_oci_authenticated(config, log, level=logging.DEBUG)

    identity_client = common.make_client(oci.identity.IdentityClient, config)
    kms_vault_client = common.make_client(oci.key_management.KmsVaultClient, config)
    vaults_client = common.make_client(oci.vault.VaultsClient, config)

    try:
        compartment_ocid, vault_ocid, management_endpoint, compartment_name = (
            _resolve_infra(
                args, config, tenancy_ocid, identity_client, kms_vault_client, log
            )
        )

        mek_ocid = _require_mek(
            config, compartment_ocid, management_endpoint, args.mek_name, log
        )
        _require_contract_secrets_use_mek(
            vaults_client,
            compartment_ocid=compartment_ocid,
            vault_ocid=vault_ocid,
            names=names,
            mek_ocid=mek_ocid,
            log=log,
        )

        kms_key_ocid = _ensure_unseal_kms_key(
            config,
            compartment_ocid,
            management_endpoint,
            names.kms_key,
            dry_run=args.dry_run,
            wait_seconds=args.wait_seconds,
            interval_seconds=args.interval_seconds,
            log=log,
        )
        user_ocid = _ensure_unseal_user(
            identity_client,
            tenancy_ocid,
            names.user,
            dry_run=args.dry_run,
            wait_seconds=args.wait_seconds,
            interval_seconds=args.interval_seconds,
            log=log,
        )
        group_ocid = _ensure_unseal_group(
            identity_client,
            tenancy_ocid,
            names.group,
            dry_run=args.dry_run,
            wait_seconds=args.wait_seconds,
            interval_seconds=args.interval_seconds,
            log=log,
        )
        _ensure_unseal_membership(
            identity_client,
            tenancy_ocid,
            user_ocid,
            group_ocid,
            dry_run=args.dry_run,
            wait_seconds=args.wait_seconds,
            interval_seconds=args.interval_seconds,
            log=log,
        )
        _ensure_unseal_policy(
            identity_client,
            tenancy_ocid,
            names.policy,
            names.group,
            compartment_name,
            kms_key_ocid,
            dry_run=args.dry_run,
            wait_seconds=args.wait_seconds,
            interval_seconds=args.interval_seconds,
            log=log,
        )

        # Read the current registered fingerprint to protect it during cap
        # management and to use for post-write validation.
        # The client is also reused for post-write validation below.
        secrets_client = common.make_client(oci.secrets.SecretsClient, config)
        old_fingerprint: Optional[str] = None
        if not common.is_dry_run_ocid(user_ocid):
            old_fingerprint = _read_secret_value(
                vaults_client,
                secrets_client,
                compartment_ocid,
                vault_ocid,
                names.secret_fingerprint,
                log,
            )
            log.debug(
                "Current registered fingerprint before rotate: %s",
                old_fingerprint or "<none>",
            )

            # API key cap check. The currently registered fingerprint is
            # protected — it must never be deleted automatically during cap
            # management because consumers may still depend on it.
            _handle_api_key_cap(
                identity_client,
                user_ocid,
                delete_old_api_key=args.delete_old_api_key,
                protected_fingerprint=old_fingerprint,
                dry_run=args.dry_run,
                log=log,
            )

        if args.dry_run:
            log.info(
                "[DRY-RUN] would generate fresh RSA-%d API key for user '%s', "
                "upload to OCI, and update 3 Vault secrets "
                "(%s, %s, %s)",
                RSA_KEY_BITS,
                names.user,
                names.secret_private_key,
                names.secret_fingerprint,
                names.secret_user_ocid,
            )
            log.info("manage-unseal rotate complete (dry_run=True)")
            return 0

        keypair = _generate_and_upload_api_key(
            identity_client, user_ocid, names.user, log
        )

        _upsert_vault_secret(
            vaults_client,
            compartment_ocid=compartment_ocid,
            vault_ocid=vault_ocid,
            mek_ocid=mek_ocid,
            secret_name=names.secret_private_key,
            secret_value_bytes=keypair["private_pem"].encode("utf-8"),
            wait_seconds=args.wait_seconds,
            interval_seconds=args.interval_seconds,
            log=log,
        )
        _upsert_vault_secret(
            vaults_client,
            compartment_ocid=compartment_ocid,
            vault_ocid=vault_ocid,
            mek_ocid=mek_ocid,
            secret_name=names.secret_fingerprint,
            secret_value_bytes=keypair["fingerprint"].encode("utf-8"),
            wait_seconds=args.wait_seconds,
            interval_seconds=args.interval_seconds,
            log=log,
        )
        _upsert_vault_secret(
            vaults_client,
            compartment_ocid=compartment_ocid,
            vault_ocid=vault_ocid,
            mek_ocid=mek_ocid,
            secret_name=names.secret_user_ocid,
            secret_value_bytes=user_ocid.encode("utf-8"),
            wait_seconds=args.wait_seconds,
            interval_seconds=args.interval_seconds,
            log=log,
        )

        # Post-write validation: confirm the stored credential set is internally
        # consistent before declaring success.  The prior active API key is
        # intentionally NOT deleted here — consumers must roll over to the new
        # secret before a retired key is removed manually.
        log.info("Validating stored credential set after rotate...")
        if not _check_create_complete(
            vaults_client,
            secrets_client,
            identity_client,
            compartment_ocid,
            vault_ocid,
            names,
            user_ocid,
            log,
        ):
            log.error(
                "Post-write validation failed: stored secrets do not form a "
                "consistent credential set after rotate. "
                "Inspect with 'manage-unseal show'. "
                "The prior API key was NOT deleted."
            )
            return 1

    except ServiceError as exc:
        log.error(
            "Aborting on OCI error (status=%s code=%s): %s",
            getattr(exc, "status", "?"),
            getattr(exc, "code", "?"),
            getattr(exc, "message", str(exc)),
        )
        return 1
    except (RuntimeError, TimeoutError, OSError) as exc:
        log.error("Aborting: %s", exc)
        return 1

    log.info("manage-unseal rotate complete.")
    return 0


def cmd_show(args: argparse.Namespace, log: logging.Logger) -> int:
    """Implement the ``show`` subcommand.

    Emits a JSON object to stdout with derived resource names, discovered
    OCIDs and lifecycle states, the registered API key fingerprint (not the
    private key), secret presence, and a ``provisioning_complete`` flag.
    Read-only; makes no mutations.

    Args:
        args: Parsed CLI arguments.
        log: Active logger.

    Returns:
        Process exit code (``0`` on success).
    """
    log.info("manage-unseal show starting")

    try:
        cluster_id = normalize_cluster_name(args.cluster_name)
    except ValueError as exc:
        log.error("Invalid --cluster-name %r: %s", args.cluster_name, exc)
        raise SystemExit(_EXIT_INVALID_CLUSTER_NAME) from exc

    if cluster_id != args.cluster_name:
        log.info(
            "cluster_name normalized: %r -> %r",
            args.cluster_name,
            cluster_id,
        )

    names = derive_names(cluster_id)

    common.require_dependencies(log, need_cryptography=True)

    config = common.load_oci_config(
        config_path=args.oci_config_file,
        profile=args.oci_profile,
        region_override=args.region,
        log=log,
    )
    tenancy_ocid = common.verify_oci_authenticated(config, log, level=logging.DEBUG)

    identity_client = common.make_client(oci.identity.IdentityClient, config)
    kms_vault_client = common.make_client(oci.key_management.KmsVaultClient, config)
    vaults_client = common.make_client(oci.vault.VaultsClient, config)
    secrets_client = common.make_client(oci.secrets.SecretsClient, config)

    try:
        compartment_ocid, vault_ocid, management_endpoint, compartment_name = (
            _resolve_infra(
                args, config, tenancy_ocid, identity_client, kms_vault_client, log
            )
        )

        report: Dict[str, Any] = {
            "cluster_id": cluster_id,
            "derived_names": {
                "kms_key": names.kms_key,
                "user": names.user,
                "group": names.group,
                "policy": names.policy,
                "secret_private_key": names.secret_private_key,
                "secret_fingerprint": names.secret_fingerprint,
                "secret_user_ocid": names.secret_user_ocid,
            },
            "compartment": {"name": compartment_name, "ocid": compartment_ocid},
            "vault": {
                "name": args.vault_name,
                "ocid": vault_ocid,
                "management_endpoint": management_endpoint,
            },
        }

        # KMS unseal key: look up in any non-deleted state for accurate reporting.
        _mgmt_client = common.make_client(
            oci.key_management.KmsManagementClient,
            config,
            service_endpoint=management_endpoint,
        )
        _kms_candidates = [
            k
            for k in common.list_all(
                _mgmt_client.list_keys, compartment_id=compartment_ocid
            )
            if k.display_name == names.kms_key
            and k.lifecycle_state
            not in {"DELETED", "DELETING", "PENDING_DELETION", "SCHEDULING_DELETION"}
        ]
        kms_key = _kms_candidates[0] if _kms_candidates else None
        kms_key_ocid: Optional[str] = kms_key.id if kms_key else None

        # Fetch the full key model to report authoritative shape properties.
        # list_keys returns KeySummary objects which lack key_shape detail.
        _kms_algorithm: Optional[str] = None
        _kms_key_length: Optional[int] = None
        _kms_protection_mode: Optional[str] = None
        _kms_matches_expected_shape: Optional[bool] = None
        if kms_key_ocid is not None:
            try:
                _full_key_data = _mgmt_client.get_key(kms_key_ocid).data
                _kms_key_shape = getattr(_full_key_data, "key_shape", None)
                _kms_algorithm = (
                    getattr(_kms_key_shape, "algorithm", None)
                    if _kms_key_shape is not None
                    else None
                )
                _kms_key_length = (
                    getattr(_kms_key_shape, "length", None)
                    if _kms_key_shape is not None
                    else None
                )
                _kms_protection_mode = getattr(_full_key_data, "protection_mode", None)
                _kms_matches_expected_shape = (
                    _kms_algorithm == "AES"
                    and _kms_key_length == 32
                    and _kms_protection_mode == "SOFTWARE"
                )
            except Exception as exc:
                log.debug(
                    "Could not fetch full key model for '%s' [%s]: %s",
                    names.kms_key,
                    kms_key_ocid,
                    exc,
                )

        report["kms_key"] = {
            "name": names.kms_key,
            "ocid": kms_key_ocid,
            "lifecycle_state": kms_key.lifecycle_state if kms_key else None,
            "algorithm": _kms_algorithm,
            "key_length": _kms_key_length,
            "protection_mode": _kms_protection_mode,
            "matches_expected_shape": _kms_matches_expected_shape,
        }

        # IAM user.
        users = [
            u
            for u in common.list_all(
                identity_client.list_users,
                compartment_id=tenancy_ocid,
                name=names.user,
            )
            if u.name == names.user
        ]
        user = users[0] if users else None
        user_ocid: Optional[str] = user.id if user else None
        report["user"] = {
            "name": names.user,
            "ocid": user_ocid,
            "lifecycle_state": user.lifecycle_state if user else None,
        }

        # IAM group.
        groups = [
            g
            for g in common.list_all(
                identity_client.list_groups,
                compartment_id=tenancy_ocid,
                name=names.group,
            )
            if g.name == names.group
        ]
        group = groups[0] if groups else None
        report["group"] = {
            "name": names.group,
            "ocid": group.id if group else None,
            "lifecycle_state": group.lifecycle_state if group else None,
        }

        # User-group membership.
        membership_exists = False
        membership_active = False
        if user_ocid and group is not None:
            _memberships = common.list_all(
                identity_client.list_user_group_memberships,
                compartment_id=tenancy_ocid,
                user_id=user_ocid,
                group_id=group.id,
            )
            membership_exists = bool(_memberships)
            membership_active = any(
                getattr(membership, "lifecycle_state", None) == "ACTIVE"
                for membership in _memberships
            )
        report["membership_exists"] = membership_exists
        report["membership_active"] = membership_active

        # IAM policy.
        policies = [
            p
            for p in common.list_all(
                identity_client.list_policies, compartment_id=tenancy_ocid
            )
            if p.name == names.policy
        ]
        policy = policies[0] if policies else None
        if policy:
            stmts = list(policy.statements or [])
            correctly_scoped: Optional[bool] = None
            if kms_key_ocid:
                expected_stmt = _unseal_policy_statement(
                    names.group, compartment_name, kms_key_ocid
                )
                expected_norm = " ".join(expected_stmt.split()).lower()
                correctly_scoped = (
                    len(stmts) == 1
                    and " ".join(stmts[0].split()).lower() == expected_norm
                )
            report["policy"] = {
                "name": names.policy,
                "ocid": policy.id,
                "lifecycle_state": policy.lifecycle_state,
                "statements": stmts,
                "correctly_scoped": correctly_scoped,
            }
        else:
            report["policy"] = {
                "name": names.policy,
                "ocid": None,
                "lifecycle_state": None,
                "correctly_scoped": None,
            }

        # API keys on the user.
        if user_ocid:
            api_keys = common.list_all(identity_client.list_api_keys, user_id=user_ocid)
            report["api_keys"] = [
                {
                    "fingerprint": k.fingerprint,
                    "lifecycle_state": getattr(k, "lifecycle_state", "ACTIVE"),
                    "time_created": str(getattr(k, "time_created", "")),
                }
                for k in api_keys
            ]
        else:
            report["api_keys"] = []

        # Vault secrets.
        fp_value = _read_secret_value(
            vaults_client,
            secrets_client,
            compartment_ocid,
            vault_ocid,
            names.secret_fingerprint,
            log,
        )
        uid_value = _read_secret_value(
            vaults_client,
            secrets_client,
            compartment_ocid,
            vault_ocid,
            names.secret_user_ocid,
            log,
        )

        def _secret_entry(secret_name: str, include_value: bool) -> Dict[str, Any]:
            s = common.lookup_existing_secret(
                vaults_client, compartment_ocid, vault_ocid, secret_name, log
            )
            if s:
                entry: Dict[str, Any] = {
                    "exists": True,
                    "ocid": s.id,
                    "lifecycle_state": s.lifecycle_state,
                }
                if include_value:
                    entry["value"] = _read_secret_value(
                        vaults_client,
                        secrets_client,
                        compartment_ocid,
                        vault_ocid,
                        secret_name,
                        log,
                    )
                return entry
            return {"exists": False, "ocid": None}

        report["secrets"] = {
            "private_key": _secret_entry(names.secret_private_key, include_value=False),
            "fingerprint": _secret_entry(names.secret_fingerprint, include_value=True),
            "user_ocid": _secret_entry(names.secret_user_ocid, include_value=False),
        }
        secrets_active = all(
            entry.get("exists") and entry.get("lifecycle_state") == "ACTIVE"
            for entry in report["secrets"].values()
        )

        # Private-key fingerprint validation (non-sensitive boolean).
        # Read the private key PEM, derive its fingerprint, and compare to the
        # stored fingerprint.  The PEM itself is never included in the report.
        pk_matches_fingerprint: Optional[bool] = None
        if report["secrets"]["private_key"]["exists"] and fp_value:
            _pk_raw = _read_secret_value(
                vaults_client,
                secrets_client,
                compartment_ocid,
                vault_ocid,
                names.secret_private_key,
                log,
            )
            if _pk_raw is not None:
                try:
                    _derived_fp = common.fingerprint_from_private_pem(_pk_raw)
                    pk_matches_fingerprint = _derived_fp == fp_value
                except (ValueError, RuntimeError):
                    pk_matches_fingerprint = False
            else:
                pk_matches_fingerprint = False
        report["secrets"]["private_key"]["matches_fingerprint"] = pk_matches_fingerprint

        # Strengthened provisioning_complete: all resources must exist in their
        # expected active/enabled states, membership and policy must be ACTIVE,
        # the policy must be exactly correctly scoped (using the authoritative
        # compartment name), all three secrets must be ACTIVE, the stored user
        # OCID must match, the
        # stored fingerprint must be a live API key, the private key must
        # derive the same fingerprint, and the KMS key must have the required
        # AES-256 SOFTWARE shape (matches_expected_shape must be True).
        kms_enabled = kms_key is not None and kms_key.lifecycle_state == "ENABLED"
        user_active = user is not None and user.lifecycle_state == "ACTIVE"
        group_active = group is not None and group.lifecycle_state == "ACTIVE"
        policy_active = report["policy"].get("lifecycle_state") == "ACTIVE"
        api_fps = {k["fingerprint"] for k in report["api_keys"]}
        provisioning_complete = bool(
            kms_enabled
            and report["kms_key"].get("matches_expected_shape") is True
            and user_active
            and group_active
            and membership_active
            and policy_active
            and report["policy"].get("correctly_scoped") is True
            and secrets_active
            and fp_value is not None
            and fp_value in api_fps
            and uid_value == user_ocid
            and pk_matches_fingerprint is True
        )
        report["provisioning_complete"] = provisioning_complete

    except ServiceError as exc:
        log.error(
            "OCI error (status=%s code=%s): %s",
            getattr(exc, "status", "?"),
            getattr(exc, "code", "?"),
            getattr(exc, "message", str(exc)),
        )
        return 1
    except (RuntimeError, OSError) as exc:
        log.error("Aborting: %s", exc)
        return 1

    print(json.dumps(report, indent=2, sort_keys=True, default=str))
    log.info("manage-unseal show complete.")
    return 0


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main(argv: Optional[List[str]] = None) -> int:
    """Entry point for the ``manage-unseal`` console script.

    Args:
        argv: Optional explicit argv list (useful for testing).

    Returns:
        Process exit code.
    """
    args = parse_args(argv)

    subcommand_loggers: Dict[str, str] = {
        "create": f"{LOGGER_NAME}.create",
        "rotate": f"{LOGGER_NAME}.rotate",
        "show": f"{LOGGER_NAME}.show",
    }
    logger_name = subcommand_loggers.get(args.subcommand, LOGGER_NAME)
    log = common.setup_logging(args.verbose, logger_name)

    dispatch = {
        "create": cmd_create,
        "rotate": cmd_rotate,
        "show": cmd_show,
    }
    handler = dispatch.get(args.subcommand)
    if handler is None:  # pragma: no cover — argparse enforces valid choices
        log.error("Unknown subcommand: %s", args.subcommand)
        return 1

    return handler(args, log)


if __name__ == "__main__":
    sys.exit(main())
