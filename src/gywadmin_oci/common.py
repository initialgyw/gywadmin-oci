"""Shared helpers for the gywadmin-homelab OCI scripts.

``initialize-oci.py`` and ``manage-vault.py`` import from this module.
Behaviour is intentionally identical to the helpers that previously lived
inside ``initialize-oci.py``; this is a relocation, not a rewrite.

Public surface
--------------

* :func:`setup_logging` — configure root + noisy-third-party log levels from
  a ``-v`` count value.
* :func:`require_dependencies` — abort if optional third-party deps
  (``oci``, optionally ``cryptography``) are missing.
* :func:`load_oci_config` — load and validate an OCI CLI config profile.
* :func:`verify_oci_authenticated` — live ``get_user`` preflight; returns
  the tenancy OCID.
* :func:`wait_for_state` — 404/5xx-tolerant polling helper.
* :func:`list_all` — pagination helper around ``oci.pagination``.
* :func:`set_secure_perms` — best-effort POSIX permission helper.
* :func:`dry_run_ocid` / :func:`is_dry_run_ocid` — placeholder OCID helpers
  used during dry-runs to short-circuit downstream API calls.
* :func:`lookup_compartment` — find a compartment OCID by name at tenancy root.
* :func:`lookup_vault` — find a KMS vault OCID + management endpoint by name.
* :func:`auto_pick_mek` — auto-discover the single ENABLED MEK in a vault.
* :func:`lookup_existing_secret` — find an existing secret by name in a vault.
* :func:`format_oci_time` — RFC 3339 UTC timestamp with ``Z`` suffix.
* :func:`parse_oci_time` — strict RFC 3339 parser; raises ``ValueError``.
* :func:`prompt_destructive_confirm` — TTY / ``--yes`` / non-TTY confirmation
  gate; raises ``SystemExit(11)`` on refusal.
* ``DELETION_LIFECYCLE_STATES`` — frozenset of ``*_DELETION`` states.
* ``MIN_SECRET_DELETION_DAYS`` / ``MAX_SECRET_DELETION_DAYS`` — OCI-documented
  bounds for ``ScheduleSecretDeletionDetails.time_of_deletion``.
"""

from __future__ import annotations

import json
import logging
import os
import stat
import sys
import tempfile
import time
from dataclasses import dataclass, fields
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Optional third-party imports.
#
# Wrapped so ``--help`` and basic argument parsing work even if the ``oci``
# SDK is not installed. Real usage is gated by :func:`require_dependencies`.
# ---------------------------------------------------------------------------
try:  # pragma: no cover - import guard
    import oci  # type: ignore
    from oci.exceptions import ServiceError  # type: ignore

    HAS_OCI = True
    OCI_IMPORT_ERROR: Optional[BaseException] = None
except Exception as exc:  # pragma: no cover - import guard
    oci = None  # type: ignore[assignment]
    ServiceError = Exception  # type: ignore[assignment,misc]
    HAS_OCI = False
    OCI_IMPORT_ERROR = exc

try:  # pragma: no cover - import guard
    from cryptography.hazmat.primitives import serialization  # type: ignore  # noqa: F401
    from cryptography.hazmat.primitives.asymmetric import rsa  # type: ignore  # noqa: F401

    HAS_CRYPTO = True
    CRYPTO_IMPORT_ERROR: Optional[BaseException] = None
except Exception as exc:  # pragma: no cover - import guard
    HAS_CRYPTO = False
    CRYPTO_IMPORT_ERROR = exc


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
# Failure-side lifecycle states we should bail on if a resource enters them
# while we are waiting for it to become usable.
TERMINAL_FAILURE_STATES = frozenset(
    {
        "FAILED",
        "DELETED",
        "PENDING_DELETION",
        "SCHEDULING_DELETION",
        "DELETING",
        "TERMINATED",
        "TERMINATING",
    }
)

# Lifecycle states that mean "the existing name is reserved and cannot be
# reused until the deletion completes or is cancelled".
DELETION_LIFECYCLE_STATES = frozenset({"SCHEDULING_DELETION", "PENDING_DELETION"})

# Loggers that emit at least one DEBUG line per HTTP call when DEBUG is on.
# Suppressed at -vv, unleashed at -vvv.
NOISY_THIRD_PARTY_LOGGERS = ("urllib3", "oci.circuit_breaker", "oci.config")

# Dry-run sentinels. ``ensure_*`` functions return placeholder OCIDs so
# downstream functions can detect "the parent doesn't really exist yet" and
# skip live API calls instead of failing with an InvalidParameter error.
DRY_RUN_OCID_PREFIX = "ocid1.dryrun."

# ---------------------------------------------------------------------------
# Deletion-window bounds
#
# Secret deletion:
#   Source: OCI Secret Management docs — "Deleting a Secret"
#   https://docs.oracle.com/en-us/iaas/Content/secret-management/Tasks/delete-secret.htm
#   Quote: "By default, the service schedules secrets for deletion 30 days
#   from the current date and time. You can set a range between 1 day and
#   30 days."
MIN_SECRET_DELETION_DAYS: int = 1
MAX_SECRET_DELETION_DAYS: int = 30


# ---------------------------------------------------------------------------
# OCI Always Free tier limits for Vault / Secret Management
#
#   Source: OCI Service Limits — "Vault" section
#   https://docs.oracle.com/en-us/iaas/Content/General/service-limits/default.htm
#
#   - 150 secrets per tenancy.
#   - 40 versions per secret (20 active + 20 pending deletion).
#   - 10 virtual vaults per region.
#
# The WARN threshold below is local policy (not OCI-enforced) and gives us
# soft-warn headroom before the hard cap:
#
#   * ``WARN_SECRETS_THRESHOLD`` (140): start warning at create time.
#   * ``MAX_SECRETS_ALWAYS_FREE`` (150): hard refuse to create.
#   * ``MAX_ACTIVE_VERSIONS_ALWAYS_FREE`` (20): the OCI-documented cap on
#     active versions per secret. Surfaced in docstrings; ``update-secret``
#     prunes ALL non-CURRENT active versions post-push so this should never
#     be reached.
#   * ``MAX_PENDING_VERSIONS_ALWAYS_FREE`` (20): the OCI-documented cap on
#     pending-deletion versions per secret. ``update-secret`` warns when
#     observed at or above this.
MAX_SECRETS_ALWAYS_FREE: int = 150
WARN_SECRETS_THRESHOLD: int = 140

MAX_ACTIVE_VERSIONS_ALWAYS_FREE: int = 20
MAX_PENDING_VERSIONS_ALWAYS_FREE: int = 20

# Default path for the summary JSON produced by ``initialize-oci.py``.
DEFAULT_SUMMARY_PATH = Path("script_outputs/initialize-oci-summary.json")


# ---------------------------------------------------------------------------
# Dry-run OCID helpers
# ---------------------------------------------------------------------------
def dry_run_ocid(kind: str) -> str:
    """Return a deterministic placeholder OCID for a dry-run resource.

    Args:
        kind: Short noun describing the resource (``"compartment"``,
            ``"vault"``, ``"key"``, ``"user"``, ``"group"``, ``"policy"``,
            ``"secret"``).

    Returns:
        A placeholder string of the form ``ocid1.dryrun.<kind>`` that
        :func:`is_dry_run_ocid` recognises.
    """
    return f"{DRY_RUN_OCID_PREFIX}{kind}"


def is_dry_run_ocid(value: object) -> bool:
    """Return ``True`` if ``value`` is a placeholder OCID from a dry-run.

    Args:
        value: Any value; non-strings always return ``False``.
    """
    return isinstance(value, str) and value.startswith(DRY_RUN_OCID_PREFIX)


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
def setup_logging(verbosity: int, logger_name: str) -> logging.Logger:
    """Configure root logging based on a ``-v`` count value.

    Levels:

    * ``0`` (no flag): root WARNING; noisy third-party loggers WARNING.
    * ``1`` (``-v``): root INFO; noisy third-party loggers WARNING.
    * ``2`` (``-vv``): root DEBUG; noisy third-party loggers (``urllib3``,
      ``oci.circuit_breaker``, ``oci.config``) clamped to INFO so script
      DEBUG output is not drowned by HTTP-level noise.
    * ``3+`` (``-vvv``): root DEBUG and noisy loggers also DEBUG (TRACE).

    Args:
        verbosity: Non-negative count, typically from ``argparse`` ``-v``.
        logger_name: Name of the script-specific logger to return.

    Returns:
        The script's named logger, ready to use.
    """
    if verbosity >= 3:
        root_level = logging.DEBUG
        third_party_level = logging.DEBUG
    elif verbosity == 2:
        root_level = logging.DEBUG
        third_party_level = logging.INFO
    elif verbosity == 1:
        root_level = logging.INFO
        third_party_level = logging.WARNING
    else:
        root_level = logging.WARNING
        third_party_level = logging.WARNING

    logging.basicConfig(
        level=root_level,
        format="%(asctime)s %(levelname)-7s %(name)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )
    # ``basicConfig`` is a no-op if the root logger already has handlers, so
    # explicitly set the root level too (matters when reusing an interpreter).
    logging.getLogger().setLevel(root_level)
    for noisy in NOISY_THIRD_PARTY_LOGGERS:
        logging.getLogger(noisy).setLevel(third_party_level)
    return logging.getLogger(logger_name)


# ---------------------------------------------------------------------------
# Dependency / authentication preflight
# ---------------------------------------------------------------------------
def require_dependencies(
    log: logging.Logger,
    *,
    need_cryptography: bool = False,
) -> None:
    """Abort the run if required third-party dependencies are missing.

    Args:
        log: Active logger for emitting error context.
        need_cryptography: If ``True``, also require ``cryptography``.
            Defaults to ``False``; only ``initialize-oci.py`` needs it.

    Raises:
        SystemExit: With code ``2`` if any required dependency is missing.
    """
    missing: List[str] = []
    if not HAS_OCI:
        missing.append("oci")
        log.debug("oci import error: %s", OCI_IMPORT_ERROR)
    if need_cryptography and not HAS_CRYPTO:
        missing.append("cryptography")
        log.debug("cryptography import error: %s", CRYPTO_IMPORT_ERROR)
    if missing:
        log.error(
            "Missing required Python packages: %s. Install with: "
            "pip install -r py-requirements.txt",
            ", ".join(missing),
        )
        raise SystemExit(2)


def load_oci_config(
    config_path: Path,
    profile: str,
    region_override: Optional[str],
    log: logging.Logger,
) -> Dict[str, Any]:
    """Load and validate an OCI CLI config profile.

    Args:
        config_path: Filesystem path to the OCI CLI config file.
        profile: Section name within the config file.
        region_override: Optional region string that overrides ``region`` in
            the loaded config.
        log: Active logger.

    Returns:
        A dict suitable for passing to ``oci`` service clients.

    Raises:
        SystemExit: With code ``3`` if the config is missing or invalid.
    """
    if not config_path.is_file():
        log.error(
            "OCI config file not found at %s. Run `oci setup config` first.",
            config_path,
        )
        raise SystemExit(3)

    try:
        config = oci.config.from_file(str(config_path), profile_name=profile)
    except Exception as exc:  # pragma: no cover - oci raises various errors
        log.error(
            "Failed to load OCI config from %s [%s]: %s", config_path, profile, exc
        )
        raise SystemExit(3) from exc

    if region_override:
        log.info(
            "Overriding region from --region: %s -> %s",
            config.get("region"),
            region_override,
        )
        config["region"] = region_override

    try:
        oci.config.validate_config(config)
    except Exception as exc:  # pragma: no cover - depends on user config
        log.error("OCI config did not validate: %s", exc)
        raise SystemExit(3) from exc

    return config


def verify_oci_authenticated(
    config: Dict[str, Any],
    log: logging.Logger,
    *,
    level: int = logging.INFO,
) -> str:
    """Verify the loaded OCI config can actually call the API.

    Performs a lightweight ``get_user`` against the configured user OCID to
    detect things like expired keys, mistyped fingerprints, or revoked users.

    Args:
        config: OCI config dict from :func:`load_oci_config`.
        log: Active logger.
        level: Logging level for the success line; defaults to INFO. Pass
            ``logging.DEBUG`` from scripts that want a quieter ``-v`` mode.

    Returns:
        The tenancy OCID associated with the authenticated principal.

    Raises:
        SystemExit: With code ``4`` if the API call fails.
    """
    identity = oci.identity.IdentityClient(config)
    user_ocid = config.get("user")
    tenancy_ocid = config.get("tenancy")
    if not user_ocid or not tenancy_ocid:
        log.error("OCI config is missing 'user' or 'tenancy' fields.")
        raise SystemExit(4)

    try:
        user = identity.get_user(user_ocid).data
    except ServiceError as exc:
        log.error(
            "OCI authentication test failed (status=%s code=%s): %s",
            getattr(exc, "status", "?"),
            getattr(exc, "code", "?"),
            getattr(exc, "message", str(exc)),
        )
        raise SystemExit(4) from exc
    except Exception as exc:  # pragma: no cover - network etc.
        log.error("OCI authentication test failed: %s", exc)
        raise SystemExit(4) from exc

    log.log(
        level,
        "Authenticated as user %s (%s) in tenancy %s, region %s",
        user.name,
        user.id,
        tenancy_ocid,
        config.get("region"),
    )

    return tenancy_ocid


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------
def wait_for_state(
    get_fn: Callable[[], Any],
    target_states: Iterable[str],
    *,
    label: str,
    log: logging.Logger,
    max_wait: int,
    interval: int,
) -> Any:
    """Poll ``get_fn`` until the resource enters one of ``target_states``.

    Tolerates short-lived transient errors thrown by ``get_fn`` itself:

    * **HTTP 404** — typically OCI's ``NotAuthorizedOrNotFound`` returned
      while a freshly-created IAM resource (compartment, group, policy,
      user) is still propagating across the IAM control plane. Treated as
      "not yet visible" and retried.
    * **HTTP 5xx** — transient server/proxy issue. Retried.
    * **Anything else** (400, 401, 403, 409, ...) — re-raised immediately
      because it indicates a real problem rather than propagation lag.

    Transient retries use a smaller sleep (``min(5, interval)``) so the
    common IAM lag (typically 1-3 seconds) does not block on the long
    ``interval`` tuned for slow vault provisioning.

    Args:
        get_fn: Zero-arg callable returning an OCI ``Response`` whose
            ``.data`` exposes a ``lifecycle_state`` attribute.
        target_states: Iterable of acceptable lifecycle states.
        label: Human-readable label used in log lines and error messages.
        log: Active logger.
        max_wait: Maximum total seconds to wait before raising.
        interval: Seconds between successful polls.

    Returns:
        The resource model object once it reaches a target state.

    Raises:
        RuntimeError: If the resource enters a terminal failure state.
        TimeoutError: If ``max_wait`` elapses without reaching a target
            state (whether due to lifecycle stalls or repeated transient
            errors).
        ServiceError: Re-raised as-is for non-transient OCI errors from
            ``get_fn``.
    """
    target_set = {s.upper() for s in target_states}
    started = time.monotonic()
    deadline = started + max_wait
    heartbeat_interval = 120  # seconds between "still waiting" status logs
    transient_sleep = max(1, min(5, interval))
    last_state: Optional[str] = None
    last_log_time = 0.0
    while True:
        try:
            resp = get_fn()
        except ServiceError as exc:
            status = getattr(exc, "status", None)
            code = getattr(exc, "code", "?")
            is_transient = status == 404 or (isinstance(status, int) and status >= 500)
            if not is_transient:
                raise
            now = time.monotonic()
            transient_label = f"<status={status}>"
            if (
                last_state != transient_label
                or (now - last_log_time) >= heartbeat_interval
            ):
                elapsed = int(now - started)
                log.info(
                    "%s not yet visible (status=%s code=%s, elapsed=%ds); retrying...",
                    label,
                    status,
                    code,
                    elapsed,
                )
                last_state = transient_label
                last_log_time = now
            if now >= deadline:
                raise TimeoutError(
                    f"{label} did not become visible within {max_wait}s "
                    f"(last error: status={status} code={code})"
                ) from exc
            time.sleep(transient_sleep)
            continue
        state = (getattr(resp.data, "lifecycle_state", None) or "").upper()
        now = time.monotonic()
        if state != last_state or (now - last_log_time) >= heartbeat_interval:
            elapsed = int(now - started)
            log.info(
                "%s lifecycle_state=%s (elapsed=%ds)",
                label,
                state or "<unknown>",
                elapsed,
            )
            last_state = state
            last_log_time = now
        if state in target_set:
            return resp.data
        # Treat terminal failures as fatal unless a target state asked for them.
        if state in TERMINAL_FAILURE_STATES and state not in target_set:
            raise RuntimeError(f"{label} entered terminal state {state}")
        if now >= deadline:
            raise TimeoutError(
                f"{label} did not reach {sorted(target_set)} within "
                f"{max_wait}s (last state: {state or 'unknown'})"
            )
        time.sleep(interval)


def list_all(list_fn: Callable[..., Any], **kwargs: Any) -> List[Any]:
    """Page through an OCI list call and return all items.

    Args:
        list_fn: Bound list method on a service client (e.g.
            ``identity.list_compartments``).
        **kwargs: Keyword arguments forwarded to ``list_fn``.

    Returns:
        Aggregated list of all returned model objects across pages.
    """
    return list(oci.pagination.list_call_get_all_results(list_fn, **kwargs).data)


# ---------------------------------------------------------------------------
# OCI summary data model (shared by update_github_secrets.py)
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class OciSummarySecrets:
    """Typed container for the seven secrets extracted from the OCI summary.

    All fields are required non-empty strings.  Construct via
    :meth:`from_initialize_oci_summary` to extract values from the JSON
    produced by ``initialize-oci.py``.
    """

    AWS_ACCESS_KEY_ID: str
    AWS_SECRET_ACCESS_KEY: str
    OCI_CLI_TENANCY: str
    OCI_CLI_USER: str
    OCI_CLI_FINGERPRINT: str
    OCI_CLI_KEY_CONTENT: str
    TF_VAR_private_key_password: str

    def __post_init__(self) -> None:
        for f in fields(self):
            value = getattr(self, f.name)
            if not isinstance(value, str):
                raise TypeError(
                    f"{f.name} must be a string, got {type(value).__name__}"
                )
            if not value:
                raise ValueError(f"{f.name} must be a non-empty string")

    @classmethod
    def from_initialize_oci_summary(cls, data: Dict[str, Any]) -> "OciSummarySecrets":
        """Extract secrets from the JSON shape produced by ``initialize-oci.py``.

        Args:
            data: Parsed JSON dict from the summary file.

        Returns:
            A fully-populated :class:`OciSummarySecrets` instance.

        Raises:
            KeyError: A required JSON path is missing.
            TypeError: A required value is not a string (e.g. a nested dict is
                ``None``).
            ValueError: A required value is an empty string.
        """
        try:
            kwargs = dict(
                AWS_ACCESS_KEY_ID=data["service_account"]["customer_secret_key"][
                    "access_key"
                ],
                AWS_SECRET_ACCESS_KEY=data["service_account"]["customer_secret_key"][
                    "secret_key"
                ],
                OCI_CLI_TENANCY=data["tenancy_ocid"],
                OCI_CLI_USER=data["service_account"]["ocid"],
                OCI_CLI_FINGERPRINT=data["service_account"]["api_key"]["fingerprint"],
                OCI_CLI_KEY_CONTENT=data["service_account"]["api_key"]["private_pem"],
                TF_VAR_private_key_password=data["service_account"]["api_key"][
                    "passphrase"
                ],
            )
        except (KeyError, TypeError) as e:
            # TypeError covers e.g. data["service_account"] being None.
            raise KeyError(str(e)) from e
        return cls(**kwargs)

    def as_ordered_items(self) -> List[tuple]:
        """Return ``(name, value)`` pairs in dataclass field declaration order.

        Returns:
            List of ``(field_name, field_value)`` tuples.
        """
        return [(f.name, getattr(self, f.name)) for f in fields(self)]


# ---------------------------------------------------------------------------
# Summary file helpers (shared by update_github_secrets.py)
# ---------------------------------------------------------------------------
def validate_summary_file(path: Path, *, log: logging.Logger) -> None:
    """Assert that *path* is a readable regular file.

    On POSIX systems, warns (but does not abort) if the file has group- or
    other-readable/writable/executable bits set.

    Args:
        path: Filesystem path to the summary JSON file.
        log: Active logger.

    Raises:
        SystemExit: With code ``3`` if the path does not exist, is not a
            regular file, or cannot be stat'd.
    """
    try:
        if not path.exists():
            log.error("Summary file not found: %s", path)
            raise SystemExit(3)
        if not path.is_file():
            log.error("Summary path is not a regular file: %s", path)
            raise SystemExit(3)
        if os.name == "posix":
            mode = path.stat().st_mode
            if mode & (stat.S_IRWXG | stat.S_IRWXO):
                log.warning(
                    "Summary file %s has insecure permissions (mode=%o); "
                    "recommend chmod 600",
                    path,
                    mode & 0o777,
                )
    except SystemExit:
        raise
    except OSError as exc:
        log.error("Cannot access summary file %s: %s", path, exc)
        raise SystemExit(3) from exc


def load_summary(path: Path, *, log: logging.Logger) -> Dict[str, Any]:
    """Read and parse the JSON summary file.

    Args:
        path: Filesystem path to the summary JSON file.
        log: Active logger.

    Returns:
        Parsed JSON as a dict.

    Raises:
        SystemExit: With code ``3`` on read error or invalid JSON.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        log.error("Failed to read summary file %s: %s", path, exc)
        raise SystemExit(3) from exc

    try:
        return json.loads(text)  # type: ignore[return-value]
    except json.JSONDecodeError as exc:
        log.error("Invalid JSON in summary file %s: %s", path, exc)
        raise SystemExit(3) from exc


# ---------------------------------------------------------------------------
# Atomic file write helper
# ---------------------------------------------------------------------------
def atomic_write(path: Path, content: bytes, *, mode: int = 0o600) -> None:
    """Write bytes to ``path`` atomically with the given POSIX mode.

    Writes to a temp file in the same directory, fsyncs, sets the requested
    mode, and renames. On non-POSIX platforms the chmod is best-effort.

    Args:
        path: Destination file path.
        content: Raw bytes to write.
        mode: POSIX permission bits (default ``0o600``).
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        if os.name == "posix":
            os.chmod(tmp_name, mode)
        os.replace(tmp_name, path)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def set_secure_perms(path: Path, mode: int) -> None:
    """Best-effort ``chmod`` that is silent on filesystems where it is unsupported.

    Args:
        path: File or directory to modify.
        mode: Octal permission bits (e.g. ``0o600``).
    """
    try:
        os.chmod(path, mode)
    except OSError:
        # Some filesystems (e.g. Windows or certain network mounts) reject
        # POSIX permission bits. The credentials directory is private to the
        # user anyway; not worth aborting the run over.
        pass


# ---------------------------------------------------------------------------
# Time helpers
# ---------------------------------------------------------------------------
def format_oci_time(dt: datetime) -> str:
    """Format a datetime as an RFC 3339 UTC timestamp with ``Z`` suffix.

    Args:
        dt: A datetime object. If naive, it is assumed to be UTC.

    Returns:
        String of the form ``2026-05-09T12:34:56Z``.
    """
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    utc = dt.astimezone(timezone.utc)
    return utc.strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_oci_time(s: str) -> datetime:
    """Parse a strict RFC 3339 timestamp string into a timezone-aware datetime.

    Accepts the ``Z`` suffix (UTC) or a numeric ``+HH:MM`` / ``-HH:MM``
    offset. Fractional seconds are accepted but truncated to microseconds.

    Args:
        s: RFC 3339 timestamp string.

    Returns:
        Timezone-aware ``datetime`` in UTC.

    Raises:
        ValueError: If the string cannot be parsed.
    """
    # Normalise the ``Z`` suffix to ``+00:00`` for ``fromisoformat``.
    normalised = s.strip()
    if normalised.endswith("Z"):
        normalised = normalised[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(normalised)
    except ValueError as exc:
        raise ValueError(f"Cannot parse RFC 3339 timestamp: {s!r}") from exc
    if dt.tzinfo is None:
        raise ValueError(f"Timestamp has no timezone info: {s!r}")
    return dt.astimezone(timezone.utc)


def now_utc() -> datetime:
    """Return the current UTC time as a timezone-aware datetime."""
    return datetime.now(tz=timezone.utc)


# ---------------------------------------------------------------------------
# Confirmation gate
# ---------------------------------------------------------------------------
def prompt_destructive_confirm(
    message: str,
    *,
    yes: bool,
    log: logging.Logger,
) -> bool:
    """Gate destructive operations behind an interactive or ``--yes`` confirm.

    Rules:
    * If ``yes=True`` (``--yes`` flag): log the confirmation at INFO and
      return ``True``.
    * If ``yes=False`` and stdin is a TTY: prompt interactively.
    * If ``yes=False`` and stdin is **not** a TTY: log an error and raise
      ``SystemExit(11)``.

    Args:
        message: Human-readable description of the destructive action.
        yes: Whether ``--yes`` was passed.
        log: Active logger.

    Returns:
        ``True`` if the user confirmed.

    Raises:
        SystemExit: With code ``11`` if the user declined or if stdin is not
            a TTY and ``--yes`` was not passed.
    """
    is_tty = sys.stdin.isatty()

    if yes:
        log.info("Confirmed (--yes): %s", message)
        return True

    if not is_tty:
        log.error(
            "Destructive operation requires confirmation but stdin is not a TTY. "
            "Pass --yes to confirm non-interactively."
        )
        log.error("Refused: %s", message)
        raise SystemExit(11)

    # Interactive TTY path.
    print(f"\n⚠  {message}", file=sys.stderr)
    print("   Proceed? [y/N] ", end="", file=sys.stderr, flush=True)
    try:
        answer = input()
    except (EOFError, KeyboardInterrupt):
        print("", file=sys.stderr)
        log.info("Aborted by user.")
        raise SystemExit(11)
    if answer.strip().lower() not in ("y", "yes"):
        log.info("Aborted by user.")
        raise SystemExit(11)
    return True


# ---------------------------------------------------------------------------
# Resource lookup helpers (shared between manage-vault.py subcommands)
# ---------------------------------------------------------------------------
def lookup_compartment(
    identity_client: Any,
    tenancy_ocid: str,
    name: str,
    log: logging.Logger,
) -> str:
    """Find the compartment by name at the tenancy root.

    Args:
        identity_client: Authenticated ``IdentityClient``.
        tenancy_ocid: Tenancy OCID (parent for the lookup).
        name: Compartment display name.
        log: Active logger.

    Returns:
        Compartment OCID.

    Raises:
        SystemExit: With code ``5`` if not found.
    """
    matches = [
        c
        for c in list_all(
            identity_client.list_compartments,
            compartment_id=tenancy_ocid,
            compartment_id_in_subtree=False,
            access_level="ACCESSIBLE",
        )
        if c.name == name and c.lifecycle_state == "ACTIVE"
    ]
    if not matches:
        log.error(
            "Compartment '%s' not found under tenancy %s. Run initialize-oci.py "
            "or create the compartment manually.",
            name,
            tenancy_ocid,
        )
        raise SystemExit(5)
    comp = matches[0]
    log.debug("compartment '%s' resolved to %s", name, comp.id)
    return comp.id


def lookup_vault(
    kms_vault_client: Any,
    compartment_ocid: str,
    name: str,
    log: logging.Logger,
) -> Tuple[str, str]:
    """Find the KMS Vault by display name within a compartment.

    Args:
        kms_vault_client: Authenticated ``KmsVaultClient``.
        compartment_ocid: OCID of the parent compartment.
        name: Vault display name.
        log: Active logger.

    Returns:
        Tuple of ``(vault_ocid, management_endpoint)``.

    Raises:
        SystemExit: With code ``5`` if not found.
    """
    matches = [
        v
        for v in list_all(kms_vault_client.list_vaults, compartment_id=compartment_ocid)
        if v.display_name == name and v.lifecycle_state == "ACTIVE"
    ]
    if not matches:
        log.error(
            "Vault '%s' not found in compartment %s. Run initialize-oci.py or "
            "create the vault manually.",
            name,
            compartment_ocid,
        )
        raise SystemExit(5)
    vault = matches[0]
    log.debug(
        "vault '%s' resolved to %s (mgmt_endpoint=%s)",
        name,
        vault.id,
        vault.management_endpoint,
    )
    return vault.id, vault.management_endpoint


def auto_pick_mek(
    config: Dict[str, Any],
    compartment_ocid: str,
    management_endpoint: str,
    vault_name: str,
    log: logging.Logger,
) -> Tuple[str, str]:
    """Auto-discover the single ENABLED MEK in the vault.

    Args:
        config: OCI config dict.
        compartment_ocid: OCID of the parent compartment.
        management_endpoint: Vault ``management_endpoint`` URL.
        vault_name: Vault display name (for log messages only).
        log: Active logger.

    Returns:
        Tuple of ``(mek_ocid, mek_display_name)``.

    Raises:
        SystemExit: With code ``6`` if zero or more than one ENABLED key is
            present in the vault.
    """
    mgmt = oci.key_management.KmsManagementClient(
        config, service_endpoint=management_endpoint
    )
    enabled = [
        k
        for k in list_all(mgmt.list_keys, compartment_id=compartment_ocid)
        if k.lifecycle_state == "ENABLED"
    ]
    if len(enabled) == 0:
        log.error(
            "Vault '%s' has no ENABLED master encryption keys. Create one (e.g. "
            "via initialize-oci.py) before storing secrets.",
            vault_name,
        )
        raise SystemExit(6)
    if len(enabled) > 1:
        names = ", ".join(sorted(k.display_name for k in enabled))
        log.error(
            "Vault '%s' has %d ENABLED keys; auto-pick is ambiguous. Candidates: %s. "
            "Disable or remove all but one before re-running.",
            vault_name,
            len(enabled),
            names,
        )
        raise SystemExit(6)
    mek = enabled[0]
    log.debug("auto-selected MEK '%s' (%s)", mek.display_name, mek.id)
    return mek.id, mek.display_name


def lookup_existing_secret(
    vaults_client: Any,
    compartment_ocid: str,
    vault_ocid: str,
    secret_name: str,
    log: logging.Logger,
) -> Optional[Any]:
    """Find an existing secret by name in the vault.

    Args:
        vaults_client: Authenticated ``oci.vault.VaultsClient``.
        compartment_ocid: OCID of the parent compartment.
        vault_ocid: OCID of the parent vault.
        secret_name: Secret display name.
        log: Active logger.

    Returns:
        The full ``Secret`` model (via ``get_secret``) if the secret exists in
        any non-deleted state, else ``None``. Upgrading from the summary
        ensures ``current_version_number`` is populated; the summary lacks it.

    Raises:
        SystemExit: With code ``8`` if the name is held by a secret that is
            currently in a deletion lifecycle state.
    """
    matches = [
        s
        for s in list_all(
            vaults_client.list_secrets,
            compartment_id=compartment_ocid,
            vault_id=vault_ocid,
            name=secret_name,
        )
        if s.secret_name == secret_name
    ]
    if not matches:
        return None

    # Server-side ``name`` filter is sometimes a prefix match; we already
    # filtered by exact name above. Pick the freshest non-deleted match.
    for secret in matches:
        if secret.lifecycle_state in DELETION_LIFECYCLE_STATES:
            log.error(
                "Secret '%s' is in lifecycle state %s; the name is reserved until "
                "deletion completes or is cancelled. Cancel the deletion or wait, "
                "then retry.",
                secret_name,
                secret.lifecycle_state,
            )
            raise SystemExit(8)
    # Prefer ACTIVE; fall back to any non-deleted state to let
    # ``wait_for_state`` settle it before update.
    for state_pref in ("ACTIVE",):
        for s in matches:
            if s.lifecycle_state == state_pref:
                log.debug(
                    "secret '%s' already exists (%s, state=%s)",
                    secret_name,
                    s.id,
                    s.lifecycle_state,
                )
                return vaults_client.get_secret(s.id).data
    fallback = matches[0]
    log.debug(
        "secret '%s' already exists (%s, state=%s); will wait for ACTIVE before update",
        secret_name,
        fallback.id,
        fallback.lifecycle_state,
    )
    return vaults_client.get_secret(fallback.id).data
