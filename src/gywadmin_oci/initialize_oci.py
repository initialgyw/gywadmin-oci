#!/usr/bin/env python3
"""Initialize OCI Always Free Tier resources for homelab secrets management.

This script provisions an idempotent baseline on Oracle Cloud Infrastructure
for the ``gywadmin-homelab`` project::

    Compartment            (default: cpm_automation)
    +-- Object Storage Bucket  (default: bucket_automation, versioned, private)
    +-- KMS Vault              (default: vault_automation, DEFAULT type, free)
        +-- Master Encryption Key  (default: mek_automation, AES-256, software)

In addition it creates an IAM service-account user, a group, the membership
linking them, and an IAM policy that allows the group to write to the bucket
and read secret-bundles from the vault. A 4096-bit RSA API key is generated
locally, encrypted with a random passphrase, uploaded to OCI for the user,
and written to a user-supplied output directory along with a drop-in OCI
config snippet.

Optionally (with ``--create-sa-keys``) an OCI Customer Secret Key
(S3-compatible access key + secret key) is created for the service-account
user and written to ``<output_dir>/<sa>_aws_credentials.ini`` in AWS CLI
shared-credentials format (``[default]`` profile with ``aws_access_key_id``
and ``aws_secret_access_key``) so Terraform's AWS provider, the ``aws``
CLI, and ``boto3`` can authenticate against the OCI S3-compatible endpoint.
Every invocation with that flag REPLACES all existing Customer Secret Keys
on the user (OCI caps users at 2).

All resources are stamped with a configurable freeform tag (default
``created_by=initialize-oci.py``) and each step is idempotent: re-running the
script with the same arguments will reuse existing resources rather than
creating duplicates.

The script must run from an OCI principal that already has tenancy-admin
authority (i.e. the root/owner account). Authentication is sourced from the
OCI CLI configuration file (default ``~/.oci/config``); the script refuses
to run if the config is missing, invalid, or non-functional.

Dependencies
------------
* Python 3.9.6+
* ``oci`` and ``cryptography`` from PyPI

Install with::

    pip install -r py-requirements.txt

Usage
-----
::

    initialize-oci --help
    initialize-oci --create-sa-keys
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import secrets
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import gywadmin_oci.common as common

# Re-export the optional-import flags / errors and the SDK handles so the
# rest of this module continues to read like the pre-extraction version.
oci = common.oci  # type: ignore[assignment]
ServiceError = common.ServiceError  # type: ignore[assignment,misc]

# Optional ``cryptography`` deps are still imported here because the API-key
# generation path uses them directly. The import is wrapped so ``--help``
# works without them; :func:`_require_dependencies` enforces presence at
# runtime.
try:  # pragma: no cover - import guard
    from cryptography.hazmat.primitives import serialization  # type: ignore
    from cryptography.hazmat.primitives.asymmetric import rsa  # type: ignore
except Exception:  # pragma: no cover - import guard
    serialization = None  # type: ignore[assignment]
    rsa = None  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
DEFAULT_COMPARTMENT = "cpm_automation"
DEFAULT_BUCKET = "bucket_automation"
DEFAULT_VAULT = "vault_automation"
DEFAULT_MEK = "mek_automation"
DEFAULT_SERVICE_ACCOUNT = "sa_automation"
DEFAULT_GROUP = "grp_automation"
DEFAULT_POLICY = "policy_grp_automation"
DEFAULT_OUTPUT_DIR = str(Path(__file__).resolve().parent / "output")
DEFAULT_TAG_KEY = "created_by"
DEFAULT_TAG_VALUE = "initialize-oci.py"
DEFAULT_OCI_CONFIG = "~/.oci/config"
DEFAULT_OCI_PROFILE = "DEFAULT"

# Polling / waiting
DEFAULT_WAIT_SECONDS = 1800  # 30 min ceiling: vaults can take 10-15 min
DEFAULT_INTERVAL_SECONDS = 30

# RSA key size for OCI API signing key. OCI accepts up to 4096 bits.
RSA_KEY_BITS = 4096

LOGGER_NAME = "initialize-oci"

# Dry-run sentinel used only by this script (a vault management endpoint URL,
# not an OCID). OCID-shaped placeholders come from ``common.dry_run_ocid``.
_DRY_RUN_VAULT_MGMT_ENDPOINT = "https://vault-mgmt.dryrun.example"


def _dry_run_ocid(kind: str) -> str:
    """Thin wrapper around :func:`common.dry_run_ocid` (kept for call-site stability)."""
    return common.dry_run_ocid(kind)


def _is_dry_run_ocid(value: object) -> bool:
    """Thin wrapper around :func:`common.is_dry_run_ocid`."""
    return common.is_dry_run_ocid(value)


# ---------------------------------------------------------------------------
# Typed argument / context containers
# ---------------------------------------------------------------------------
@dataclass
class Args:
    """Container for parsed CLI arguments.

    Each attribute mirrors a flag declared in :func:`parse_args` and exists
    so the rest of the program can rely on type-checked attribute access
    instead of poking at an :class:`argparse.Namespace`.
    """

    compartment: str
    bucket: str
    vault: str
    mek: str
    service_account: str
    group: str
    policy: str
    output_dir: Path
    tag_key: str
    tag_value: str
    oci_config_file: Path
    oci_profile: str
    region: Optional[str]
    verbose: int
    dry_run: bool
    wait_seconds: int
    interval_seconds: int
    create_sa_keys: bool


@dataclass
class Context:
    """Runtime context shared across every ``ensure_*`` function.

    Holds the OCI service clients, the resolved tenancy and region, the
    freeform-tag dict to stamp every resource with, the parsed CLI
    arguments, and the active logger.
    """

    args: Args
    log: logging.Logger
    tenancy_ocid: str
    region: str
    config: Dict[str, Any]
    identity: Any
    object_storage: Any
    kms_vault: Any
    freeform_tags: Dict[str, str] = field(default_factory=dict)

    @property
    def dry_run(self) -> bool:
        return self.args.dry_run


# ---------------------------------------------------------------------------
# CLI parsing & logging
# ---------------------------------------------------------------------------
def parse_args(argv: Optional[List[str]] = None) -> Args:
    """Parse command-line arguments into a typed :class:`Args` instance.

    Args:
        argv: Optional explicit argv list (mostly useful for testing).

    Returns:
        Populated :class:`Args` dataclass.
    """
    parser = argparse.ArgumentParser(
        prog="initialize-oci.py",
        description=(
            "Idempotently create the OCI compartment, bucket, vault, MEK, "
            "service-account user, group, membership, and policy used by "
            "the gywadmin-homelab automation."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument(
        "--compartment",
        default=DEFAULT_COMPARTMENT,
        help="Name of the compartment to create at the tenancy root.",
    )
    parser.add_argument(
        "--bucket",
        default=DEFAULT_BUCKET,
        help="Name of the Object Storage bucket to create in the compartment.",
    )
    parser.add_argument(
        "--vault",
        default=DEFAULT_VAULT,
        help="Display name of the KMS Vault (DEFAULT/free type).",
    )
    parser.add_argument(
        "--mek",
        default=DEFAULT_MEK,
        help="Display name of the master encryption key created inside the vault.",
    )
    parser.add_argument(
        "--service-account",
        default=DEFAULT_SERVICE_ACCOUNT,
        help="Name of the IAM user that automation will authenticate as.",
    )
    parser.add_argument(
        "--group",
        default=DEFAULT_GROUP,
        help="Name of the IAM group the service account is added to.",
    )
    parser.add_argument(
        "--policy",
        default=DEFAULT_POLICY,
        help="Name of the IAM policy that grants the group access.",
    )
    parser.add_argument(
        "--output-dir",
        default=DEFAULT_OUTPUT_DIR,
        help="Directory to write the generated API key, passphrase, and credentials into.",
    )
    parser.add_argument(
        "--tag-key",
        default=DEFAULT_TAG_KEY,
        help="Freeform tag key applied to every resource.",
    )
    parser.add_argument(
        "--tag-value",
        default=DEFAULT_TAG_VALUE,
        help="Freeform tag value applied to every resource.",
    )
    parser.add_argument(
        "--oci-config-file",
        default=DEFAULT_OCI_CONFIG,
        help="Path to the OCI CLI config file.",
    )
    parser.add_argument(
        "--oci-profile",
        default=DEFAULT_OCI_PROFILE,
        help="Profile within the OCI CLI config file to authenticate as.",
    )
    parser.add_argument(
        "--region",
        default=None,
        help="Override the region in the OCI CLI config (e.g. us-ashburn-1).",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help=(
            "Increase verbosity. Repeat to increase: -v=INFO, -vv=DEBUG "
            "(without urllib3/oci internals), -vvv=TRACE (with urllib3 DEBUG)."
        ),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Look up existing resources but do not create or modify anything.",
    )
    parser.add_argument(
        "--wait-seconds",
        type=int,
        default=DEFAULT_WAIT_SECONDS,
        help="Maximum seconds to wait for an asynchronous resource to become ready.",
    )
    parser.add_argument(
        "--interval-seconds",
        type=int,
        default=DEFAULT_INTERVAL_SECONDS,
        help="Polling interval, in seconds, while waiting for a resource state.",
    )
    parser.add_argument(
        "--create-sa-keys",
        action="store_true",
        default=False,
        help=(
            "Generate an OCI Customer Secret Key (S3-compatible access key + "
            "secret key) for the service-account user and write it to the "
            "output directory. Every invocation REPLACES any existing "
            "Customer Secret Keys on the user (OCI caps users at 2)."
        ),
    )

    parsed = parser.parse_args(argv)

    return Args(
        compartment=parsed.compartment,
        bucket=parsed.bucket,
        vault=parsed.vault,
        mek=parsed.mek,
        service_account=parsed.service_account,
        group=parsed.group,
        policy=parsed.policy,
        output_dir=Path(parsed.output_dir).expanduser().resolve(),
        tag_key=parsed.tag_key,
        tag_value=parsed.tag_value,
        oci_config_file=Path(parsed.oci_config_file).expanduser().resolve(),
        oci_profile=parsed.oci_profile,
        region=parsed.region,
        verbose=parsed.verbose,
        dry_run=parsed.dry_run,
        wait_seconds=parsed.wait_seconds,
        interval_seconds=parsed.interval_seconds,
        create_sa_keys=parsed.create_sa_keys,
    )


def setup_logging(verbosity: int) -> logging.Logger:
    """Configure root logging from a ``-v`` count value.

    Thin wrapper around :func:`gywadmin_oci.common.setup_logging` that pins the
    logger name to this script.
    """
    return common.setup_logging(verbosity, LOGGER_NAME)


# ---------------------------------------------------------------------------
# Dependency / authentication preflight
# ---------------------------------------------------------------------------
def _require_dependencies(log: logging.Logger) -> None:
    """Abort the run if optional third-party dependencies are missing.

    This script needs both ``oci`` and ``cryptography`` (the latter for the
    RSA-4096 API key generation path).

    Args:
        log: Active logger for emitting error context.

    Raises:
        SystemExit: With code ``2`` if either dependency is unavailable.
    """
    common.require_dependencies(log, need_cryptography=True)


def load_oci_config(
    config_path: Path,
    profile: str,
    region_override: Optional[str],
    log: logging.Logger,
) -> Dict[str, Any]:
    """Load and validate an OCI CLI config profile.

    Thin wrapper around :func:`gywadmin_oci.common.load_oci_config`.
    """
    return common.load_oci_config(config_path, profile, region_override, log)


def verify_oci_authenticated(config: Dict[str, Any], log: logging.Logger) -> str:
    """Verify the loaded OCI config can actually call the API.

    Thin wrapper around :func:`gywadmin_oci.common.verify_oci_authenticated`.
    """
    return common.verify_oci_authenticated(config, log)


def build_clients(config: Dict[str, Any]) -> Dict[str, Any]:
    """Construct the OCI service clients used by the script.

    Args:
        config: Validated OCI config dict.

    Returns:
        A mapping with keys ``identity``, ``object_storage``, ``kms_vault``.
    """
    return {
        "identity": oci.identity.IdentityClient(config),
        "object_storage": oci.object_storage.ObjectStorageClient(config),
        "kms_vault": oci.key_management.KmsVaultClient(config),
    }


# ---------------------------------------------------------------------------
# Generic helpers — thin wrappers around :mod:`gywadmin_oci.common`
# ---------------------------------------------------------------------------
def _wait_for_state(*args: Any, **kwargs: Any) -> Any:
    """Poll until a resource reaches a target lifecycle state.

    See :func:`gywadmin_oci.common.wait_for_state` for full semantics.
    """
    return common.wait_for_state(*args, **kwargs)


def _list_all(list_fn: Any, **kwargs: Any) -> List[Any]:
    """Page through an OCI list call and return all items."""
    return common.list_all(list_fn, **kwargs)


def _set_secure_perms(path: Path, mode: int) -> None:
    """Best-effort ``chmod`` that is silent on unsupported filesystems."""
    common.set_secure_perms(path, mode)


# ---------------------------------------------------------------------------
# Resource-creation primitives
# ---------------------------------------------------------------------------
def ensure_compartment(ctx: Context) -> str:
    """Create or look up the automation compartment at the tenancy root.

    Args:
        ctx: Shared runtime context.

    Returns:
        OCID of the compartment.
    """
    name = ctx.args.compartment
    log = ctx.log

    existing = [
        c
        for c in _list_all(
            ctx.identity.list_compartments,
            compartment_id=ctx.tenancy_ocid,
            compartment_id_in_subtree=False,
            access_level="ACCESSIBLE",
        )
        if c.name == name and c.lifecycle_state in {"ACTIVE", "CREATING"}
    ]
    if existing:
        comp = existing[0]
        log.info(
            "compartment '%s' exists [%s, state=%s]",
            name,
            comp.id,
            comp.lifecycle_state,
        )
        if comp.lifecycle_state != "ACTIVE":
            _wait_for_state(
                lambda: ctx.identity.get_compartment(comp.id),
                ["ACTIVE"],
                label=f"compartment {name}",
                log=log,
                max_wait=ctx.args.wait_seconds,
                interval=ctx.args.interval_seconds,
            )
        return comp.id

    if ctx.dry_run:
        log.info(
            "[DRY-RUN] would create compartment '%s' under tenancy %s",
            name,
            ctx.tenancy_ocid,
        )
        return _dry_run_ocid("compartment")

    log.info("Creating compartment '%s' under tenancy %s", name, ctx.tenancy_ocid)
    details = oci.identity.models.CreateCompartmentDetails(
        compartment_id=ctx.tenancy_ocid,
        name=name,
        description=f"Created by {DEFAULT_TAG_VALUE} for gywadmin-homelab automation.",
        freeform_tags=ctx.freeform_tags,
    )
    resp = ctx.identity.create_compartment(details)
    comp = _wait_for_state(
        lambda: ctx.identity.get_compartment(resp.data.id),
        ["ACTIVE"],
        label=f"compartment {name}",
        log=log,
        max_wait=ctx.args.wait_seconds,
        interval=ctx.args.interval_seconds,
    )
    log.info("compartment '%s' created [%s]", name, comp.id)
    return comp.id


def ensure_bucket(ctx: Context, compartment_ocid: str) -> Tuple[str, str]:
    """Create or look up the Object Storage bucket inside the compartment.

    Versioning is enabled and public access is disabled by default.

    Args:
        ctx: Shared runtime context.
        compartment_ocid: OCID of the parent compartment.

    Returns:
        Tuple of ``(namespace, bucket_name)``.
    """
    name = ctx.args.bucket
    log = ctx.log
    namespace = ctx.object_storage.get_namespace().data

    try:
        existing = ctx.object_storage.get_bucket(namespace, name).data
        log.info(
            "bucket '%s' exists in namespace '%s' (compartment=%s)",
            name,
            namespace,
            existing.compartment_id,
        )
        return namespace, name
    except ServiceError as exc:
        if getattr(exc, "status", None) != 404:
            raise

    if ctx.dry_run:
        log.info(
            "[DRY-RUN] would create bucket '%s' in namespace '%s'", name, namespace
        )
        return namespace, name

    log.info("Creating bucket '%s' in namespace '%s'", name, namespace)
    details = oci.object_storage.models.CreateBucketDetails(
        name=name,
        compartment_id=compartment_ocid,
        public_access_type="NoPublicAccess",
        versioning="Enabled",
        storage_tier="Standard",
        freeform_tags=ctx.freeform_tags,
    )
    ctx.object_storage.create_bucket(namespace, details)
    log.info("bucket '%s' created", name)
    return namespace, name


def ensure_vault(ctx: Context, compartment_ocid: str) -> Tuple[str, str]:
    """Create or look up the KMS Vault, returning its OCID and management endpoint.

    Args:
        ctx: Shared runtime context.
        compartment_ocid: OCID of the parent compartment.

    Returns:
        Tuple of ``(vault_ocid, management_endpoint)``.
    """
    name = ctx.args.vault
    log = ctx.log

    if ctx.dry_run and _is_dry_run_ocid(compartment_ocid):
        log.info(
            "[DRY-RUN] parent compartment is a placeholder; would create vault '%s'",
            name,
        )
        return _dry_run_ocid("vault"), _DRY_RUN_VAULT_MGMT_ENDPOINT

    existing = [
        v
        for v in _list_all(ctx.kms_vault.list_vaults, compartment_id=compartment_ocid)
        if v.display_name == name and v.lifecycle_state in {"ACTIVE", "CREATING"}
    ]
    if existing:
        vault = existing[0]
        log.info(
            "vault '%s' exists [%s, state=%s]", name, vault.id, vault.lifecycle_state
        )
        if vault.lifecycle_state != "ACTIVE":
            vault = _wait_for_state(
                lambda: ctx.kms_vault.get_vault(vault.id),
                ["ACTIVE"],
                label=f"vault {name}",
                log=log,
                max_wait=ctx.args.wait_seconds,
                interval=ctx.args.interval_seconds,
            )
        return vault.id, vault.management_endpoint

    if ctx.dry_run:
        log.info(
            "[DRY-RUN] would create DEFAULT vault '%s' in compartment %s",
            name,
            compartment_ocid,
        )
        return _dry_run_ocid("vault"), _DRY_RUN_VAULT_MGMT_ENDPOINT

    log.info("Creating DEFAULT vault '%s' in compartment %s", name, compartment_ocid)
    details = oci.key_management.models.CreateVaultDetails(
        compartment_id=compartment_ocid,
        display_name=name,
        vault_type="DEFAULT",
        freeform_tags=ctx.freeform_tags,
    )
    resp = ctx.kms_vault.create_vault(details)
    vault = _wait_for_state(
        lambda: ctx.kms_vault.get_vault(resp.data.id),
        ["ACTIVE"],
        label=f"vault {name}",
        log=log,
        max_wait=ctx.args.wait_seconds,
        interval=ctx.args.interval_seconds,
    )
    log.info("vault '%s' active [%s]", name, vault.id)
    return vault.id, vault.management_endpoint


def ensure_master_encryption_key(
    ctx: Context, compartment_ocid: str, management_endpoint: str
) -> str:
    """Create or look up the master encryption key (MEK) inside the vault.

    Args:
        ctx: Shared runtime context.
        compartment_ocid: OCID of the parent compartment.
        management_endpoint: ``management_endpoint`` URL from the vault.

    Returns:
        OCID of the MEK.
    """
    name = ctx.args.mek
    log = ctx.log

    if ctx.dry_run and (
        _is_dry_run_ocid(compartment_ocid)
        or management_endpoint == _DRY_RUN_VAULT_MGMT_ENDPOINT
    ):
        log.info("[DRY-RUN] vault is a placeholder; would create MEK '%s'", name)
        return _dry_run_ocid("key")

    mgmt = oci.key_management.KmsManagementClient(
        ctx.config, service_endpoint=management_endpoint
    )

    existing = [
        k
        for k in _list_all(mgmt.list_keys, compartment_id=compartment_ocid)
        if k.display_name == name
        and k.lifecycle_state in {"ENABLED", "CREATING", "ENABLING"}
    ]
    if existing:
        key = existing[0]
        log.info("MEK '%s' exists [%s, state=%s]", name, key.id, key.lifecycle_state)
        if key.lifecycle_state != "ENABLED":
            _wait_for_state(
                lambda: mgmt.get_key(key.id),
                ["ENABLED"],
                label=f"MEK {name}",
                log=log,
                max_wait=ctx.args.wait_seconds,
                interval=ctx.args.interval_seconds,
            )
        return key.id

    if ctx.dry_run:
        log.info(
            "[DRY-RUN] would create MEK '%s' in vault management %s",
            name,
            management_endpoint,
        )
        return _dry_run_ocid("key")

    log.info("Creating MEK '%s' (AES-256, software-protected)", name)
    details = oci.key_management.models.CreateKeyDetails(
        compartment_id=compartment_ocid,
        display_name=name,
        key_shape=oci.key_management.models.KeyShape(algorithm="AES", length=32),
        protection_mode="SOFTWARE",
        freeform_tags=ctx.freeform_tags,
    )
    resp = mgmt.create_key(details)
    key = _wait_for_state(
        lambda: mgmt.get_key(resp.data.id),
        ["ENABLED"],
        label=f"MEK {name}",
        log=log,
        max_wait=ctx.args.wait_seconds,
        interval=ctx.args.interval_seconds,
    )
    log.info("MEK '%s' enabled [%s]", name, key.id)
    return key.id


def ensure_user(ctx: Context) -> str:
    """Create or look up the IAM service-account user at the tenancy level.

    Args:
        ctx: Shared runtime context.

    Returns:
        OCID of the user.
    """
    name = ctx.args.service_account
    log = ctx.log

    existing = [
        u
        for u in _list_all(
            ctx.identity.list_users, compartment_id=ctx.tenancy_ocid, name=name
        )
        if u.name == name and u.lifecycle_state in {"ACTIVE", "CREATING"}
    ]
    if existing:
        user = existing[0]
        log.info("user '%s' exists [%s, state=%s]", name, user.id, user.lifecycle_state)
        return user.id

    if ctx.dry_run:
        log.info("[DRY-RUN] would create user '%s'", name)
        return _dry_run_ocid("user")

    log.info("Creating user '%s'", name)
    details = oci.identity.models.CreateUserDetails(
        compartment_id=ctx.tenancy_ocid,
        name=name,
        description=f"Service account managed by {DEFAULT_TAG_VALUE}.",
        freeform_tags=ctx.freeform_tags,
    )
    resp = ctx.identity.create_user(details)
    log.info("user '%s' created [%s]", name, resp.data.id)
    return resp.data.id


def ensure_group(ctx: Context) -> str:
    """Create or look up the IAM group at the tenancy level.

    Args:
        ctx: Shared runtime context.

    Returns:
        OCID of the group.
    """
    name = ctx.args.group
    log = ctx.log

    existing = [
        g
        for g in _list_all(
            ctx.identity.list_groups, compartment_id=ctx.tenancy_ocid, name=name
        )
        if g.name == name and g.lifecycle_state in {"ACTIVE", "CREATING"}
    ]
    if existing:
        group = existing[0]
        log.info(
            "group '%s' exists [%s, state=%s]", name, group.id, group.lifecycle_state
        )
        return group.id

    if ctx.dry_run:
        log.info("[DRY-RUN] would create group '%s'", name)
        return _dry_run_ocid("group")

    log.info("Creating group '%s'", name)
    details = oci.identity.models.CreateGroupDetails(
        compartment_id=ctx.tenancy_ocid,
        name=name,
        description=f"Group managed by {DEFAULT_TAG_VALUE}.",
        freeform_tags=ctx.freeform_tags,
    )
    resp = ctx.identity.create_group(details)
    log.info("group '%s' created [%s]", name, resp.data.id)
    return resp.data.id


def ensure_membership(ctx: Context, user_ocid: str, group_ocid: str) -> None:
    """Ensure the user is a member of the group.

    Args:
        ctx: Shared runtime context.
        user_ocid: User OCID.
        group_ocid: Group OCID.
    """
    log = ctx.log
    if ctx.dry_run and (_is_dry_run_ocid(user_ocid) or _is_dry_run_ocid(group_ocid)):
        log.info("[DRY-RUN] would add user %s to group %s", user_ocid, group_ocid)
        return

    memberships = _list_all(
        ctx.identity.list_user_group_memberships,
        compartment_id=ctx.tenancy_ocid,
        user_id=user_ocid,
        group_id=group_ocid,
    )
    if memberships:
        log.info("user %s already in group %s", user_ocid, group_ocid)
        return

    if ctx.dry_run:
        log.info("[DRY-RUN] would add user %s to group %s", user_ocid, group_ocid)
        return

    log.info("Adding user %s to group %s", user_ocid, group_ocid)
    ctx.identity.add_user_to_group(
        oci.identity.models.AddUserToGroupDetails(
            user_id=user_ocid, group_id=group_ocid
        )
    )


# ---------------------------------------------------------------------------
# API key generation & upload
# ---------------------------------------------------------------------------
def _compute_oci_fingerprint(public_key_der: bytes) -> str:
    """Compute the OCI API key fingerprint for a DER-encoded public key.

    OCI defines the fingerprint as the colon-separated MD5 hex digest of the
    DER-encoded ``SubjectPublicKeyInfo`` form of the public key (matching
    ``openssl rsa -pubout -outform DER ... | openssl md5 -c``).

    Args:
        public_key_der: DER-encoded ``SubjectPublicKeyInfo`` bytes.

    Returns:
        Colon-separated 32-character lowercase hex fingerprint.
    """
    digest = hashlib.md5(public_key_der).hexdigest()
    return ":".join(digest[i : i + 2] for i in range(0, len(digest), 2))


def _generate_api_key(passphrase: str) -> Dict[str, Any]:
    """Generate an RSA-4096 keypair, encrypt the private half, and serialize both.

    Args:
        passphrase: Passphrase used to encrypt the PKCS#8 private key.

    Returns:
        Dict with keys ``private_pem``, ``public_pem``, ``public_der``,
        ``fingerprint``.
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=RSA_KEY_BITS)
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(
            passphrase.encode("utf-8")
        ),
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    public_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return {
        "private_pem": private_pem,
        "public_pem": public_pem,
        "public_der": public_der,
        "fingerprint": _compute_oci_fingerprint(public_der),
    }


def _credentials_paths(output_dir: Path, sa_name: str) -> Dict[str, Path]:
    """Compute the standard set of output file paths for the service account.

    Args:
        output_dir: Resolved output directory.
        sa_name: Service account / IAM user name.

    Returns:
        Dict mapping a logical name to its absolute path.
    """
    return {
        "private_key": output_dir / f"{sa_name}.pem",
        "public_key": output_dir / f"{sa_name}_public.pem",
        "credentials": output_dir / f"{sa_name}_credentials.json",
        "oci_config": output_dir / f"{sa_name}_oci_config.ini",
        "aws_credentials": output_dir / f"{sa_name}_aws_credentials.ini",
    }


def _write_credentials(
    paths: Dict[str, Path],
    keypair: Dict[str, Any],
    passphrase: str,
    user_ocid: str,
    tenancy_ocid: str,
    region: str,
    user_name: str,
) -> None:
    """Persist the freshly generated key material and metadata to disk.

    Args:
        paths: Output of :func:`_credentials_paths`.
        keypair: Output of :func:`_generate_api_key`.
        passphrase: Passphrase used to encrypt the private key.
        user_ocid: OCID of the IAM user the key is uploaded for.
        tenancy_ocid: Tenancy OCID.
        region: Active OCI region.
        user_name: IAM user name; used as the OCI config profile section.
    """
    paths["private_key"].write_bytes(keypair["private_pem"])
    _set_secure_perms(paths["private_key"], 0o600)

    paths["public_key"].write_bytes(keypair["public_pem"])
    _set_secure_perms(paths["public_key"], 0o644)

    payload = {
        "user_name": user_name,
        "user_ocid": user_ocid,
        "tenancy_ocid": tenancy_ocid,
        "region": region,
        "fingerprint": keypair["fingerprint"],
        "key_file": str(paths["private_key"]),
        "passphrase": passphrase,
    }
    paths["credentials"].write_text(
        json.dumps(payload, indent=2) + "\n", encoding="utf-8"
    )
    _set_secure_perms(paths["credentials"], 0o600)

    config_section = (
        f"[{user_name.upper()}]\n"
        f"user={user_ocid}\n"
        f"fingerprint={keypair['fingerprint']}\n"
        f"tenancy={tenancy_ocid}\n"
        f"region={region}\n"
        f"key_file={paths['private_key']}\n"
        f"pass_phrase={passphrase}\n"
    )
    paths["oci_config"].write_text(config_section, encoding="utf-8")
    _set_secure_perms(paths["oci_config"], 0o600)


def ensure_api_key(ctx: Context, user_ocid: str) -> Dict[str, Any]:
    """Ensure the SA user has a usable API key, generating new material if needed.

    Behaviour:

    * If the local ``<sa>.pem`` and ``<sa>_credentials.json`` both exist and
      the credentials' fingerprint is still attached to the user in OCI,
      do nothing.
    * Otherwise generate a new RSA-4096 keypair with a random passphrase,
      upload the public half to OCI, and write the local artifacts. Existing
      OCI API keys are left in place (OCI users can have up to 3 keys).

    Args:
        ctx: Shared runtime context.
        user_ocid: OCID of the SA IAM user.

    Returns:
        Dict describing the active key (``fingerprint``, ``key_file``,
        ``credentials_file``, ``new``).
    """
    log = ctx.log
    sa_name = ctx.args.service_account
    output_dir = ctx.args.output_dir
    paths = _credentials_paths(output_dir, sa_name)

    if ctx.dry_run and _is_dry_run_ocid(user_ocid):
        log.info("[DRY-RUN] would generate and upload a new API key for %s", sa_name)
        return {
            "fingerprint": "dryrun",
            "key_file": str(paths["private_key"]),
            "credentials_file": str(paths["credentials"]),
            "new": True,
        }

    existing_keys = _list_all(ctx.identity.list_api_keys, user_id=user_ocid)
    existing_fingerprints = {k.fingerprint for k in existing_keys}

    if paths["private_key"].is_file() and paths["credentials"].is_file():
        try:
            stored = json.loads(paths["credentials"].read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            log.warning(
                "Could not parse %s: %s; will regenerate.", paths["credentials"], exc
            )
            stored = None
        if stored and stored.get("fingerprint") in existing_fingerprints:
            log.info(
                "API key for %s already in OCI and present locally [%s]; skipping.",
                sa_name,
                stored["fingerprint"],
            )
            return {
                "fingerprint": stored["fingerprint"],
                "key_file": str(paths["private_key"]),
                "credentials_file": str(paths["credentials"]),
                "new": False,
            }
        log.warning(
            "Local key/credentials present but do not match an existing OCI API key; "
            "issuing a new key."
        )

    if len(existing_keys) >= 3:
        log.error(
            "User %s already has %d API keys (OCI maximum is 3). Remove one before re-running.",
            sa_name,
            len(existing_keys),
        )
        raise SystemExit(5)

    if ctx.dry_run:
        log.info("[DRY-RUN] would generate and upload a new API key for %s", sa_name)
        return {
            "fingerprint": "dryrun",
            "key_file": str(paths["private_key"]),
            "credentials_file": str(paths["credentials"]),
            "new": True,
        }

    output_dir.mkdir(parents=True, exist_ok=True)
    _set_secure_perms(output_dir, 0o700)

    passphrase = secrets.token_urlsafe(32)
    log.info("Generating RSA-%d keypair for %s", RSA_KEY_BITS, sa_name)
    keypair = _generate_api_key(passphrase)

    log.info(
        "Uploading public key to OCI user %s [fingerprint=%s]",
        sa_name,
        keypair["fingerprint"],
    )
    ctx.identity.upload_api_key(
        user_ocid,
        oci.identity.models.CreateApiKeyDetails(
            key=keypair["public_pem"].decode("utf-8")
        ),
    )

    _write_credentials(
        paths=paths,
        keypair=keypair,
        passphrase=passphrase,
        user_ocid=user_ocid,
        tenancy_ocid=ctx.tenancy_ocid,
        region=ctx.region,
        user_name=sa_name,
    )
    log.info(
        "Wrote private key, public key, credentials JSON, and OCI config snippet to %s",
        output_dir,
    )

    return {
        "fingerprint": keypair["fingerprint"],
        "key_file": str(paths["private_key"]),
        "credentials_file": str(paths["credentials"]),
        "new": True,
    }


# ---------------------------------------------------------------------------
# Customer Secret Key (S3-compatible access key + secret key)
# ---------------------------------------------------------------------------
def _write_aws_credentials(
    path: Path,
    *,
    access_key: str,
    secret_key: str,
) -> None:
    """Write an AWS CLI shared-credentials INI file with the ``[default]`` profile.

    Format matches the standard ``~/.aws/credentials`` layout so the OCI
    Customer Secret Key can be consumed directly by AWS-compatible tooling
    (``aws`` CLI, ``boto3``, the Terraform AWS provider) against the OCI
    S3-compatible endpoint. The file is chmod'd to ``0o600``.

    Args:
        path: Destination INI path.
        access_key: OCI Customer Secret Key id (the access key).
        secret_key: OCI Customer Secret Key secret value (only returned by
            OCI at creation time).
    """
    body = (
        "[default]\n"
        f"aws_access_key_id = {access_key}\n"
        f"aws_secret_access_key = {secret_key}\n"
    )
    path.write_text(body, encoding="utf-8")
    _set_secure_perms(path, 0o600)


def ensure_customer_secret_key(
    ctx: Context,
    user_ocid: str,
) -> Optional[Dict[str, Any]]:
    """Create a fresh Customer Secret Key for the SA user (S3-compatible auth).

    Only runs when ``--create-sa-keys`` is set. Semantics are imperative
    "replace": every invocation deletes every existing Customer Secret Key
    on the user (OCI caps users at 2) and creates a new one. The secret
    value is returned by OCI exactly once at creation time and is written
    to ``<output_dir>/<sa>_aws_credentials.ini`` in AWS shared-credentials
    format (``[default]`` profile with ``aws_access_key_id`` and
    ``aws_secret_access_key``), mode ``0o600``; the secret is never logged.

    Args:
        ctx: Shared runtime context.
        user_ocid: OCID of the SA IAM user.

    Returns:
        ``None`` if ``--create-sa-keys`` was not passed. Otherwise a dict
        with keys ``access_key``, ``credentials_file``, ``display_name``,
        ``new``.
    """
    if not ctx.args.create_sa_keys:
        return None

    log = ctx.log
    sa_name = ctx.args.service_account
    output_dir = ctx.args.output_dir
    paths = _credentials_paths(output_dir, sa_name)
    aws_path = paths["aws_credentials"]
    display_name = (
        f"{sa_name}-tf-{datetime.now(tz=timezone.utc).strftime('%Y%m%d-%H%M%S')}"
    )

    if ctx.dry_run and _is_dry_run_ocid(user_ocid):
        log.info(
            "[DRY-RUN] would replace Customer Secret Keys for %s (display_name=%s)",
            sa_name,
            display_name,
        )
        return {
            "access_key": "dryrun",
            "credentials_file": str(aws_path),
            "display_name": display_name,
            "new": True,
        }

    existing = _list_all(ctx.identity.list_customer_secret_keys, user_id=user_ocid)
    if existing:
        log.warning(
            "Replacing %d existing Customer Secret Key(s) on user %s: %s",
            len(existing),
            sa_name,
            ", ".join(
                f"{k.id} (display_name={getattr(k, 'display_name', '?')}, "
                f"state={getattr(k, 'lifecycle_state', '?')})"
                for k in existing
            ),
        )
        if ctx.dry_run:
            log.info(
                "[DRY-RUN] would delete %d existing Customer Secret Key(s) "
                "and create a new one for %s",
                len(existing),
                sa_name,
            )
            return {
                "access_key": "dryrun",
                "credentials_file": str(aws_path),
                "display_name": display_name,
                "new": True,
            }
        for key in existing:
            log.info(
                "Deleting Customer Secret Key %s (display_name=%s)",
                key.id,
                getattr(key, "display_name", "?"),
            )
            ctx.identity.delete_customer_secret_key(user_ocid, key.id)

    if ctx.dry_run:
        log.info(
            "[DRY-RUN] would create Customer Secret Key for %s (display_name=%s)",
            sa_name,
            display_name,
        )
        return {
            "access_key": "dryrun",
            "credentials_file": str(aws_path),
            "display_name": display_name,
            "new": True,
        }

    output_dir.mkdir(parents=True, exist_ok=True)
    _set_secure_perms(output_dir, 0o700)

    log.info(
        "Creating Customer Secret Key for %s (display_name=%s)", sa_name, display_name
    )
    details = oci.identity.models.CreateCustomerSecretKeyDetails(
        display_name=display_name
    )
    resp = ctx.identity.create_customer_secret_key(details, user_ocid)
    access_key = resp.data.id
    secret_key = resp.data.key

    _write_aws_credentials(
        aws_path,
        access_key=access_key,
        secret_key=secret_key,
    )
    log.info(
        "Wrote AWS-format credentials INI to %s [access_key=%s]",
        aws_path,
        access_key,
    )

    return {
        "access_key": access_key,
        "credentials_file": str(aws_path),
        "display_name": display_name,
        "new": True,
    }


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------
def _policy_statements(
    group_name: str, compartment_name: str, bucket_name: str
) -> List[str]:
    """Build the IAM policy statements granting the SA group its access.

    Args:
        group_name: Name of the IAM group.
        compartment_name: Name of the parent compartment.
        bucket_name: Name of the Object Storage bucket.

    Returns:
        Ordered list of policy statement strings.
    """
    return [
        f"Allow group {group_name} to manage objects in compartment {compartment_name} "
        f"where target.bucket.name='{bucket_name}'",
        f"Allow group {group_name} to read secret-family in compartment {compartment_name}",
        f"Allow group {group_name} to read vaults in compartment {compartment_name}",
    ]


def _normalize_statement(statement: str) -> str:
    """Collapse whitespace and lowercase a policy statement for comparison.

    Args:
        statement: Raw policy statement string.

    Returns:
        Whitespace-collapsed, lowercased statement.
    """
    return " ".join(statement.split()).lower()


def ensure_policy(
    ctx: Context, group_name: str, compartment_name: str, bucket_name: str
) -> str:
    """Create or update the IAM policy that scopes the group's access.

    Args:
        ctx: Shared runtime context.
        group_name: IAM group name to allow.
        compartment_name: Compartment name to scope statements within.
        bucket_name: Bucket name for the object-write rule.

    Returns:
        OCID of the policy.
    """
    name = ctx.args.policy
    log = ctx.log
    desired = _policy_statements(group_name, compartment_name, bucket_name)
    desired_norm = {_normalize_statement(s) for s in desired}

    existing = [
        p
        for p in _list_all(ctx.identity.list_policies, compartment_id=ctx.tenancy_ocid)
        if p.name == name and p.lifecycle_state in {"ACTIVE", "CREATING"}
    ]
    if existing:
        policy = existing[0]
        existing_norm = {_normalize_statement(s) for s in (policy.statements or [])}
        missing = desired_norm - existing_norm
        if not missing:
            log.info(
                "policy '%s' exists and contains all required statements [%s]",
                name,
                policy.id,
            )
            return policy.id

        if ctx.dry_run:
            log.info(
                "[DRY-RUN] would update policy '%s' to add %d missing statement(s)",
                name,
                len(missing),
            )
            return policy.id

        merged = list(policy.statements or [])
        for stmt in desired:
            if _normalize_statement(stmt) not in existing_norm:
                merged.append(stmt)
        log.info(
            "Updating policy '%s' to add %d missing statement(s)",
            name,
            len(missing),
        )
        ctx.identity.update_policy(
            policy.id,
            oci.identity.models.UpdatePolicyDetails(
                statements=merged,
                description=policy.description,
                freeform_tags={**(policy.freeform_tags or {}), **ctx.freeform_tags},
            ),
        )
        return policy.id

    if ctx.dry_run:
        log.info("[DRY-RUN] would create policy '%s' at tenancy root", name)
        return _dry_run_ocid("policy")

    log.info("Creating policy '%s' at tenancy root", name)
    details = oci.identity.models.CreatePolicyDetails(
        compartment_id=ctx.tenancy_ocid,
        name=name,
        description=f"Created by {DEFAULT_TAG_VALUE}: grant {group_name} access to "
        f"{bucket_name} and vault secrets in {compartment_name}.",
        statements=desired,
        freeform_tags=ctx.freeform_tags,
    )
    resp = ctx.identity.create_policy(details)
    log.info("policy '%s' created [%s]", name, resp.data.id)
    return resp.data.id


# ---------------------------------------------------------------------------
# Summary writer
# ---------------------------------------------------------------------------
def write_summary(ctx: Context, payload: Dict[str, Any]) -> Path:
    """Persist a JSON summary of every OCID/name produced by the run.

    Args:
        ctx: Shared runtime context.
        payload: Mapping of summary fields.

    Returns:
        Absolute path to the summary file.
    """
    output_dir = ctx.args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    _set_secure_perms(output_dir, 0o700)
    summary_path = output_dir / "initialize-oci-summary.json"
    summary_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    _set_secure_perms(summary_path, 0o600)
    return summary_path


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------
def main(argv: Optional[List[str]] = None) -> int:
    """Entry point: parse args, authenticate, run every ``ensure_*`` step.

    Args:
        argv: Optional explicit argv list.

    Returns:
        Process exit code: ``0`` on success, non-zero on failure.
    """
    args = parse_args(argv)
    log = setup_logging(args.verbose)

    log.info("initialize-oci starting (dry_run=%s)", args.dry_run)
    log.debug("parsed args: %s", args)

    _require_dependencies(log)

    config = load_oci_config(
        config_path=args.oci_config_file,
        profile=args.oci_profile,
        region_override=args.region,
        log=log,
    )
    tenancy_ocid = verify_oci_authenticated(config, log)
    region = config.get("region", "")

    clients = build_clients(config)
    ctx = Context(
        args=args,
        log=log,
        tenancy_ocid=tenancy_ocid,
        region=region,
        config=config,
        identity=clients["identity"],
        object_storage=clients["object_storage"],
        kms_vault=clients["kms_vault"],
        freeform_tags={args.tag_key: args.tag_value},
    )

    try:
        compartment_ocid = ensure_compartment(ctx)
        namespace, bucket_name = ensure_bucket(ctx, compartment_ocid)
        vault_ocid, vault_mgmt_endpoint = ensure_vault(ctx, compartment_ocid)
        mek_ocid = ensure_master_encryption_key(
            ctx, compartment_ocid, vault_mgmt_endpoint
        )
        user_ocid = ensure_user(ctx)
        group_ocid = ensure_group(ctx)
        ensure_membership(ctx, user_ocid, group_ocid)
        api_key_info = ensure_api_key(ctx, user_ocid)
        customer_secret_key_info = ensure_customer_secret_key(ctx, user_ocid)
        policy_ocid = ensure_policy(ctx, args.group, args.compartment, bucket_name)
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

    summary = {
        "dry_run": args.dry_run,
        "tenancy_ocid": tenancy_ocid,
        "region": region,
        "compartment": {"name": args.compartment, "ocid": compartment_ocid},
        "bucket": {"name": bucket_name, "namespace": namespace},
        "vault": {
            "name": args.vault,
            "ocid": vault_ocid,
            "management_endpoint": vault_mgmt_endpoint,
        },
        "mek": {"name": args.mek, "ocid": mek_ocid},
        "service_account": {
            "name": args.service_account,
            "ocid": user_ocid,
            "api_key": api_key_info,
            **(
                {"customer_secret_key": customer_secret_key_info}
                if customer_secret_key_info is not None
                else {}
            ),
        },
        "group": {"name": args.group, "ocid": group_ocid},
        "policy": {"name": args.policy, "ocid": policy_ocid},
        "freeform_tags": ctx.freeform_tags,
    }
    summary_path = write_summary(ctx, summary)
    log.info("Summary written to %s", summary_path)
    log.info("initialize-oci complete")
    return 0


if __name__ == "__main__":
    sys.exit(main())
