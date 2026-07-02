"""gywadmin-oci: OCI Vault + initialization helpers for gywadmin-homelab.

Re-exports the public helper surface from :mod:`gywadmin_oci.common` so callers
can write ``from gywadmin_oci import setup_logging`` instead of reaching into the
submodule.
"""

from __future__ import annotations

from gywadmin_oci.common import (
    DEFAULT_SUMMARY_PATH,
    DELETION_LIFECYCLE_STATES,
    HAS_CRYPTO,
    HAS_OCI,
    MAX_ACTIVE_VERSIONS_ALWAYS_FREE,
    MAX_PENDING_VERSIONS_ALWAYS_FREE,
    MAX_SECRET_DELETION_DAYS,
    MAX_SECRETS_ALWAYS_FREE,
    MIN_SECRET_DELETION_DAYS,
    TERMINAL_FAILURE_STATES,
    WARN_SECRETS_THRESHOLD,
    OciSummarySecrets,
    ServiceError,
    atomic_write,
    auto_pick_mek,
    dry_run_ocid,
    format_oci_time,
    is_dry_run_ocid,
    list_all,
    load_oci_config,
    load_summary,
    lookup_compartment,
    lookup_existing_secret,
    lookup_vault,
    now_utc,
    oci,
    parse_oci_time,
    prompt_destructive_confirm,
    require_dependencies,
    set_secure_perms,
    setup_logging,
    validate_summary_file,
    verify_oci_authenticated,
    wait_for_state,
)

__version__ = "0.1.0"

__all__ = [
    "__version__",
    # Functions
    "setup_logging",
    "require_dependencies",
    "load_oci_config",
    "verify_oci_authenticated",
    "wait_for_state",
    "list_all",
    "set_secure_perms",
    "atomic_write",
    "dry_run_ocid",
    "is_dry_run_ocid",
    "lookup_compartment",
    "lookup_vault",
    "auto_pick_mek",
    "lookup_existing_secret",
    "format_oci_time",
    "parse_oci_time",
    "now_utc",
    "prompt_destructive_confirm",
    "validate_summary_file",
    "load_summary",
    # Classes
    "OciSummarySecrets",
    # Constants
    "DEFAULT_SUMMARY_PATH",
    "DELETION_LIFECYCLE_STATES",
    "TERMINAL_FAILURE_STATES",
    "MIN_SECRET_DELETION_DAYS",
    "MAX_SECRET_DELETION_DAYS",
    "MAX_SECRETS_ALWAYS_FREE",
    "WARN_SECRETS_THRESHOLD",
    "MAX_ACTIVE_VERSIONS_ALWAYS_FREE",
    "MAX_PENDING_VERSIONS_ALWAYS_FREE",
    # Module handles / flags
    "oci",
    "ServiceError",
    "HAS_OCI",
    "HAS_CRYPTO",
]
