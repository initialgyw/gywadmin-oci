#!/usr/bin/env python3
"""OCI Vault management CLI — five subcommands for day-2 secret operations.

Subcommands
-----------

``add-secret``
    Create a **new** secret in an OCI Vault. Refuses to overwrite: if the
    name is already in use the command exits 12. Enforces the OCI Always
    Free tier cap of 150 secrets (warns at 140, hard-fails at 150).
    Optional ``--tags 'k=v,k2=v2'`` attaches freeform tags at creation.

``update-secret``
    Push a **new version** onto an existing secret and then deprecate +
    schedule-delete every other active version. Refuses to create: exits 5
    if the secret does not exist. Optional, mutually exclusive
    ``--add-tags`` / ``--remove-tags`` / ``--set-tags`` flags mutate the
    secret's freeform tags in the same call. **If** ``--secret-value`` is
    omitted **and** at least one tag flag is provided, the command performs
    a tags-only metadata update: no new version is pushed and no prune is
    performed.

``get-secret``
    Reveal a secret's value via the data-plane ``SecretsClient``. Always
    reads the ``LATEST`` stage (the most recently pushed version) and
    supports three output formats (``raw``, ``base64``, ``json``). Emits
    an INFO audit log line before revealing the value (visible with
    ``-v`` or higher).

``delete-secret``
    Schedule a secret for deletion with a configurable retention window
    (1–30 days). Idempotent: already-deleting secrets exit 0.

``list-secrets``
    List secrets in a vault as a three-column table (Name, Lifecycle,
    Tags). Use ``--output-format json`` for a full payload.

Exit codes
----------

| Code | Meaning |
|------|---------|
| 0    | Success (or clean dry-run, or idempotent no-op). |
| 1    | Generic OCI / polling failure. |
| 2    | Required Python deps missing. |
| 3    | OCI config file missing or invalid. |
| 4    | OCI authentication preflight failed. |
| 5    | Compartment, vault, or secret not found (or ``update-secret`` target missing). |
| 6    | ``add-secret`` could not resolve exactly one requested ENABLED master encryption key. |
| 7    | Permission denied on secret create/update. |
| 8    | Secret name held by a ``*_DELETION``-state resource. |
| 9    | Bad value-source argument: empty stdin with ``--secret-value -``, non-TTY stdin without ``--secret-value``, interactive entry aborted, mismatched confirmations after 3 attempts, or empty interactive value. |
| 10   | Bad ``--time-of-deletion`` or ``--days`` argument. |
| 11   | Destructive operation refused (non-TTY without ``--yes``, or user declined). |
| 12   | ``add-secret``: secret already exists (use ``update-secret`` to push a new version). |
| 13   | ``add-secret``: refusing to exceed Always Free tier cap of 150 secrets. |
| 14   | Reserved (formerly: ``update-secret`` pre-push prune failed; logic removed). |
| 15   | ``get-secret``: ``LATEST`` stage not found on the secret (zero-version edge case). |
| 16   | ``update-secret``: post-push cleanup of one or more old versions failed; the new version IS already pushed and ACTIVE. |

Dependencies
------------
* Python 3.9.6+
* ``oci`` from PyPI

Install::

    pip install -r py-requirements.txt

``--help`` works without these installed.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import json
import logging
import sys
from datetime import timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import gywadmin_oci.common as common

oci = common.oci  # type: ignore[assignment]
ServiceError = common.ServiceError  # type: ignore[assignment,misc]

# ---------------------------------------------------------------------------
# Defaults / constants
# ---------------------------------------------------------------------------
DEFAULT_VAULT_NAME = "vault_automation"
DEFAULT_VAULT_COMPARTMENT_NAME = "cpm_automation"
DEFAULT_OCI_CONFIG = "~/.oci/config"
DEFAULT_OCI_PROFILE = "DEFAULT"
DEFAULT_WAIT_SECONDS = 600
DEFAULT_INTERVAL_SECONDS = 10
DEFAULT_MEK_NAME = "mek_automation"

# Per-subcommand logger names.
_LOGGER_ADD_SECRET = "manage-vault.add-secret"
_LOGGER_UPDATE_SECRET = "manage-vault.update-secret"
_LOGGER_GET_SECRET = "manage-vault.get-secret"
_LOGGER_DELETE_SECRET = "manage-vault.delete-secret"
_LOGGER_LIST_SECRETS = "manage-vault.list-secrets"

# Stages that mean a version is "active" (i.e. counts toward the Always Free
# 20-active-versions cap). DEPRECATED versions are scheduled for deletion and
# do not count as active.
_ACTIVE_VERSION_STAGES = frozenset({"CURRENT", "PENDING", "LATEST", "PREVIOUS"})


# ---------------------------------------------------------------------------
# CLI parsing
# ---------------------------------------------------------------------------
def _build_common_parser() -> argparse.ArgumentParser:
    """Build the shared parent parser with universal flags.

    Returns:
        An ``ArgumentParser`` with ``add_help=False`` suitable for use as a
        ``parents=[...]`` entry in subparsers.
    """
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument(
        "--vault-name",
        default=DEFAULT_VAULT_NAME,
        help="Display name of the target KMS Vault. (default: %(default)s)",
    )
    p.add_argument(
        "--vault-compartment-name",
        default=DEFAULT_VAULT_COMPARTMENT_NAME,
        help=(
            "Name of the compartment that contains the vault "
            "(looked up at tenancy root). (default: %(default)s)"
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
        help=(
            "Path to an initialize-oci-summary.json file. When provided, "
            "authenticate as the service account (sa_automation) using the API "
            "key embedded in the summary instead of reading --oci-config-file. "
            "Falls back to --oci-config-file when omitted. (default: %(default)s)"
        ),
    )
    p.add_argument(
        "--region",
        default=None,
        help="Override the region in the OCI CLI config (e.g. us-ashburn-1).",
    )
    p.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help=(
            "Increase verbosity. Repeat to increase: -v=INFO, -vv=DEBUG "
            "(without urllib3/oci internals), -vvv=TRACE (with urllib3 DEBUG)."
        ),
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Look up existing resources but do not create or modify anything.",
    )
    p.add_argument(
        "--wait-seconds",
        type=int,
        default=DEFAULT_WAIT_SECONDS,
        help="Maximum seconds to wait for a resource to reach its target state. (default: %(default)s)",
    )
    p.add_argument(
        "--interval-seconds",
        type=int,
        default=DEFAULT_INTERVAL_SECONDS,
        help="Polling interval in seconds while waiting. (default: %(default)s)",
    )
    return p


def _nonempty_mek_name(value: str) -> str:
    """Normalize a non-empty KMS key display name for argparse.

    Args:
        value: Raw command-line argument.

    Returns:
        The surrounding-whitespace-trimmed key display name.

    Raises:
        argparse.ArgumentTypeError: If the name is empty after trimming.
    """
    name = value.strip()
    if not name:
        raise argparse.ArgumentTypeError("must not be empty or whitespace-only")
    return name


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    """Parse command-line arguments.

    Args:
        argv: Optional explicit argv list (useful for testing).

    Returns:
        Parsed ``argparse.Namespace``.
    """
    common_parser = _build_common_parser()

    parser = argparse.ArgumentParser(
        prog="manage-vault.py",
        description=(
            "OCI Vault management CLI. Five subcommands for day-2 secret "
            "operations. Run 'manage-vault.py <subcommand> --help' for "
            "per-subcommand usage."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    # ---- add-secret --------------------------------------------------------
    sp_add = subparsers.add_parser(
        "add-secret",
        parents=[common_parser],
        help="Create a new secret (refuses to overwrite an existing name).",
        description=(
            "Create a NEW secret in an OCI Vault. Refuses to overwrite an "
            "existing secret: if the name is already in use the command exits "
            "12 (use 'update-secret' to push a new version). Enforces the OCI "
            "Always Free tier cap of "
            f"{common.MAX_SECRETS_ALWAYS_FREE} secrets — warns at "
            f"{common.WARN_SECRETS_THRESHOLD} and hard-fails (exit 13) at "
            f"{common.MAX_SECRETS_ALWAYS_FREE}. The master encryption key is "
            f"selected by exact display name and defaults to {DEFAULT_MEK_NAME!r}."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    sp_add.add_argument(
        "--secret-name",
        "--name",
        "-n",
        required=True,
        help="Display name of the secret to create.",
    )
    sp_add.add_argument(
        "--mek-name",
        type=_nonempty_mek_name,
        default=DEFAULT_MEK_NAME,
        metavar="NAME",
        help=(
            "Exact display name of the ENABLED KMS key that encrypts this new "
            "secret. Other enabled keys are allowed. (default: %(default)s)"
        ),
    )
    sp_add.add_argument(
        "--secret-value",
        "--value",
        required=False,
        default=None,
        help=(
            "Secret value. May be: a literal string (WARNING: visible to other "
            "users via 'ps' and to your shell's history — avoid for sensitive "
            "values); a single '-' to read raw bytes from stdin until EOF; or "
            "omitted entirely to be prompted interactively (hidden input + "
            "confirmation). Non-TTY stdin without this flag is rejected."
        ),
    )
    sp_add.add_argument(
        "--tags",
        required=False,
        default=None,
        help=(
            "Freeform tags to attach at creation, as comma-separated "
            "'KEY=VALUE' pairs (e.g. 'env=prod,role=db'). Keys and values are "
            "whitespace-trimmed. No escaping is supported: tag keys and values "
            "must not contain ',' or '='. Omit the flag to create the secret "
            "with no freeform tags."
        ),
    )

    # ---- update-secret -----------------------------------------------------
    sp_update = subparsers.add_parser(
        "update-secret",
        parents=[common_parser],
        help="Push a new version onto an existing secret; prune older versions.",
        description=(
            "Push a new version onto an EXISTING secret in an OCI Vault and "
            "then deprecate + schedule-delete every other active version. "
            "Refuses to create: if the secret does not exist the command "
            "exits 5 (use 'add-secret' to create). After a successful update "
            "the secret has exactly one active version (the new CURRENT) plus "
            "any pre-existing PENDING_DELETION versions. Old-version cleanup "
            "is best-effort: if any per-version cleanup fails the command "
            "exits 16 (the new version is still pushed and ACTIVE). "
            "Optional, mutually exclusive --add-tags / --remove-tags / "
            "--set-tags flags mutate the secret's freeform tags in the same "
            "call. If --secret-value is OMITTED and at least one tag flag is "
            "provided, the command performs a tags-only metadata update: no "
            "new version is pushed, no prompt is shown, and no prune is "
            "performed."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    sp_update.add_argument(
        "--secret-name",
        "--name",
        "-n",
        required=True,
        help="Display name of the existing secret to update.",
    )
    sp_update.add_argument(
        "--secret-value",
        "--value",
        required=False,
        default=None,
        help=(
            "Secret value. Same resolution rules as add-secret: literal "
            "string, '-' for stdin, or omitted for interactive prompt."
        ),
    )
    sp_update_tags = sp_update.add_mutually_exclusive_group()
    sp_update_tags.add_argument(
        "--add-tags",
        required=False,
        default=None,
        help=(
            "Merge these freeform tags into the existing set (overwrites on "
            "key collision). Format: 'KEY=VALUE,KEY2=VALUE2'. Mutually "
            "exclusive with --remove-tags / --set-tags."
        ),
    )
    sp_update_tags.add_argument(
        "--remove-tags",
        required=False,
        default=None,
        help=(
            "Remove these freeform tag KEYS from the secret. Format: "
            "'KEY1,KEY2'. Missing keys are silently ignored. Mutually "
            "exclusive with --add-tags / --set-tags."
        ),
    )
    sp_update_tags.add_argument(
        "--set-tags",
        required=False,
        default=None,
        help=(
            "Replace the entire freeform-tags map. Format: "
            "'KEY=VALUE,KEY2=VALUE2'. Pass an empty string (--set-tags '') "
            "to clear all freeform tags. Mutually exclusive with "
            "--add-tags / --remove-tags."
        ),
    )

    # ---- get-secret --------------------------------------------------------
    sp_get = subparsers.add_parser(
        "get-secret",
        parents=[common_parser],
        help="Reveal a secret's value (data-plane read of LATEST).",
        description=(
            "Reveal the value of a vault secret via the OCI data-plane "
            "SecretsClient. Always reads the LATEST stage (the most recently "
            "pushed version). An INFO audit log line is emitted before the "
            "value is written (use -v to see it). The raw bytes are written "
            "to stdout with no trailing newline (use --output-format base64 "
            "or json for safer transport)."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    sp_get.add_argument(
        "--secret-name",
        "--name",
        "-n",
        required=True,
        help="Display name of the secret to reveal.",
    )
    sp_get.add_argument(
        "--output-format",
        choices=["raw", "base64", "json"],
        default="raw",
        help=(
            "Output format. 'raw' writes the decoded bytes to stdout with no "
            "trailing newline (pipeline-friendly). 'base64' writes the "
            "base64-encoded value with a trailing newline. 'json' writes a "
            "JSON object with name, id, version, stages, content_type and "
            "content_base64. (default: %(default)s)"
        ),
    )

    # ---- delete-secret -----------------------------------------------------
    sp_del = subparsers.add_parser(
        "delete-secret",
        parents=[common_parser],
        help="Schedule a secret for deletion.",
        description=(
            "Schedule a vault secret for deletion. The secret enters "
            "PENDING_DELETION state and is permanently deleted after the "
            "retention window (1–30 days). Idempotent: already-deleting "
            "secrets exit 0."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    sp_del.add_argument(
        "--secret-name",
        "--name",
        "-n",
        required=True,
        help="Display name of the secret to schedule for deletion.",
    )
    sp_del.add_argument(
        "--days",
        type=int,
        default=0,
        help=(
            "Days from now until deletion. Valid values: 0 (use the OCI minimum, "
            f"{common.MIN_SECRET_DELETION_DAYS} day) or "
            f"{common.MIN_SECRET_DELETION_DAYS}–{common.MAX_SECRET_DELETION_DAYS}. "
            "Values outside this range are rejected. (default: %(default)s)"
        ),
    )
    sp_del.add_argument(
        "--time-of-deletion",
        default=None,
        metavar="RFC3339",
        help=(
            "Explicit deletion timestamp in RFC 3339 format "
            "(e.g. 2026-06-01T00:00:00Z). Overrides --days. Must be within "
            f"{common.MIN_SECRET_DELETION_DAYS}–{common.MAX_SECRET_DELETION_DAYS} "
            "days from now; values outside this range are rejected."
        ),
    )
    sp_del.add_argument(
        "--yes",
        action="store_true",
        help="Confirm destructive operations non-interactively (required when stdin is not a TTY).",
    )

    # ---- list-secrets ------------------------------------------------------
    sp_list = subparsers.add_parser(  # noqa: F841
        "list-secrets",
        parents=[common_parser],
        help="List secrets in a vault (name, lifecycle, tags).",
        description=(
            "List the secrets in an OCI Vault as a three-column table "
            "(Name, Lifecycle, Tags). 'Lifecycle' is blank for ACTIVE secrets "
            "and shows the state otherwise. 'Tags' shows freeform tags only as "
            "'key=value' pairs. Use --output-format json for a full payload "
            "including defined_tags and system_tags. Read-only; --dry-run is "
            "inherited from the common parser and is a no-op for this command."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    sp_list.add_argument(
        "--name-prefix",
        default=None,
        help="Optional secret-name prefix filter (server-side, prefix match).",
    )
    sp_list.add_argument(
        "--output-format",
        choices=["table", "json"],
        default="table",
        help="Output format. (default: %(default)s)",
    )

    ns = parser.parse_args(argv)

    # Normalise config path.
    ns.oci_config_file = Path(ns.oci_config_file).expanduser().resolve()
    if ns.summary_file is not None:
        ns.summary_file = Path(ns.summary_file).expanduser().resolve()

    return ns


# ---------------------------------------------------------------------------
# Tag-parsing helpers (shared by add-secret and update-secret)
# ---------------------------------------------------------------------------
def _parse_tags_kv(value: Optional[str], log: logging.Logger) -> Dict[str, str]:
    """Parse a ``--tags`` / ``--add-tags`` / ``--set-tags`` value.

    Format: comma-separated ``KEY=VALUE`` pairs, e.g. ``'env=dev,role=db'``.
    Whitespace around keys and values is stripped. An empty input (``None``
    or the empty string) returns an empty dict (callers use that to mean
    "no tags" for create and "clear all tags" for ``--set-tags``).

    No escaping is supported: any value containing ``,`` or ``=`` after
    splitting is rejected. Keys containing ``=`` (i.e. a key with no value
    separator) are rejected.

    Args:
        value: Raw flag value or ``None``.
        log: Active logger.

    Returns:
        ``Dict[str, str]`` of parsed tags (possibly empty).

    Raises:
        SystemExit: With code ``10`` on any malformed pair.
    """
    if value is None or value == "":
        return {}

    out: Dict[str, str] = {}
    for raw_pair in value.split(","):
        pair = raw_pair.strip()
        if not pair:
            log.error("Tag input contains an empty pair: %r", value)
            raise SystemExit(10)
        if "=" not in pair:
            log.error("Tag pair %r is missing '=' (expected KEY=VALUE).", pair)
            raise SystemExit(10)
        # Reject more than one '=' (no escaping supported).
        if pair.count("=") > 1:
            log.error(
                "Tag pair %r contains more than one '='. Escaping is not "
                "supported; tag values must not contain '=' or ','.",
                pair,
            )
            raise SystemExit(10)
        key, val = pair.split("=", 1)
        key = key.strip()
        val = val.strip()
        if not key:
            log.error("Tag pair %r has an empty key.", raw_pair)
            raise SystemExit(10)
        out[key] = val
    return out


def _parse_tag_keys(value: Optional[str], log: logging.Logger) -> List[str]:
    """Parse a ``--remove-tags`` value: comma-separated **keys** only.

    Format: ``'k1,k2,k3'``. Whitespace stripped. Empty input is an empty
    list. Any pair containing ``=`` is rejected (this flag takes keys
    only, not key=value pairs).

    Args:
        value: Raw flag value or ``None``.
        log: Active logger.

    Returns:
        List of distinct tag keys in input order.

    Raises:
        SystemExit: With code ``10`` on any malformed input.
    """
    if value is None or value == "":
        return []

    seen: set = set()
    out: List[str] = []
    for raw_key in value.split(","):
        key = raw_key.strip()
        if not key:
            log.error("--remove-tags input contains an empty key: %r", value)
            raise SystemExit(10)
        if "=" in key:
            log.error(
                "--remove-tags takes keys only, not KEY=VALUE pairs; got %r.",
                key,
            )
            raise SystemExit(10)
        if key not in seen:
            seen.add(key)
            out.append(key)
    return out


def _resolve_tag_mutation(
    existing: Dict[str, str],
    args: argparse.Namespace,
    log: logging.Logger,
) -> Tuple[Dict[str, str], Optional[str]]:
    """Apply the mutually-exclusive ``--add-tags`` / ``--remove-tags`` /
    ``--set-tags`` flags to an existing freeform-tag dict.

    Exactly one of the three flags may be set (enforced by argparse's
    mutually-exclusive group). When none is set, the input is returned
    unchanged.

    Args:
        existing: Current freeform_tags on the secret (may be ``None``).
        args: Parsed CLI arguments. Looks at ``add_tags`` (str),
            ``remove_tags`` (str), ``set_tags`` (str). Each may be ``None``.
        log: Active logger.

    Returns:
        Tuple ``(resolved_tags, mode)`` where ``mode`` is ``"add"``,
        ``"remove"``, ``"set"``, or ``None`` if no flag was given.

    Raises:
        SystemExit: With code ``10`` propagated from the parsing helpers.
    """
    base = dict(existing or {})
    add = getattr(args, "add_tags", None)
    remove = getattr(args, "remove_tags", None)
    # --set-tags '' is a legitimate "clear all" so we distinguish None from "".
    set_flag = getattr(args, "set_tags", None)

    if add is not None:
        new = _parse_tags_kv(add, log)
        base.update(new)
        return base, "add"
    if remove is not None:
        keys = _parse_tag_keys(remove, log)
        for k in keys:
            base.pop(k, None)
        return base, "remove"
    if set_flag is not None:
        # Explicit replace (empty string => empty dict).
        return _parse_tags_kv(set_flag, log), "set"
    return base, None


# ---------------------------------------------------------------------------
# add-secret helpers (preserved from manage-vault-secrets.py)
# ---------------------------------------------------------------------------
def _load_secret_value(
    args: argparse.Namespace, log: logging.Logger
) -> Tuple[bytes, str]:
    """Resolve ``--secret-value`` into raw bytes plus a source label.

    Resolution order:

    1. ``--secret-value -`` → read raw bytes from stdin until EOF. Empty stdin
       is rejected. Source label ``"stdin"``.
    2. ``--secret-value <literal>`` → use the literal string (UTF-8 encoded).
       A warning is emitted because literals are visible via ``ps`` and shell
       history. Source label ``"cli"``.
    3. ``--secret-value`` omitted → if stdin is a TTY, prompt twice (hidden)
       and require the two entries to match. Up to 3 attempts. Source label
       ``"prompt"``. If stdin is not a TTY, fail with exit 9.

    SECURITY: raw bytes are never logged. Only ``len`` leaves this function.

    Args:
        args: Parsed CLI arguments.
        log: Active logger.

    Returns:
        Tuple of ``(raw_bytes, source)`` where ``source`` is ``"stdin"``,
        ``"cli"``, or ``"prompt"``.

    Raises:
        SystemExit: With code ``9`` for any value-source failure (empty stdin,
            non-TTY without ``--secret-value``, aborted prompt, mismatched
            confirmations, or empty interactive value).
    """
    # Case 1: --secret-value - (stdin pipe)
    if args.secret_value == "-":
        try:
            raw = sys.stdin.buffer.read()
        except Exception as exc:  # pragma: no cover - hard to simulate
            log.error("Failed to read secret value from stdin: %s", exc)
            raise SystemExit(9) from exc
        if not raw:
            log.error(
                "--secret-value was '-' but stdin produced 0 bytes; refusing to "
                "store an empty secret."
            )
            raise SystemExit(9)
        return raw, "stdin"

    # Case 2: --secret-value <literal>
    if args.secret_value is not None:
        log.warning(
            "--secret-value passed on the command line; visible to ps/shell history. "
            "For sensitive values pipe via '--secret-value -' or omit the flag to be "
            "prompted interactively."
        )
        return args.secret_value.encode("utf-8"), "cli"

    # Case 3: omitted -> interactive prompt (only on a TTY)
    if not sys.stdin.isatty():
        log.error(
            "--secret-value was not provided and stdin is not a TTY. "
            "Pass --secret-value <value>, pipe a value via '--secret-value -', "
            "or run interactively to be prompted."
        )
        raise SystemExit(9)

    max_attempts = 3
    for attempt in range(1, max_attempts + 1):
        try:
            first = getpass.getpass("Secret value: ")
            second = getpass.getpass("Confirm secret value: ")
        except (EOFError, KeyboardInterrupt) as exc:
            log.error("Interactive secret entry aborted: %s", type(exc).__name__)
            raise SystemExit(9) from exc

        if not first:
            log.error(
                "Empty secret value; refusing to store an empty secret "
                "(attempt %d/%d).",
                attempt,
                max_attempts,
            )
            continue
        if first != second:
            log.error(
                "Values did not match (attempt %d/%d).",
                attempt,
                max_attempts,
            )
            continue
        return first.encode("utf-8"), "prompt"

    log.error(
        "Failed to obtain a confirmed secret value after %d attempts.",
        max_attempts,
    )
    raise SystemExit(9)


def _encode_secret_content(raw: bytes) -> str:
    """Base64-encode raw secret bytes for ``Base64SecretContentDetails``."""
    return base64.b64encode(raw).decode("ascii")


def _create_secret(
    vaults_client: Any,
    *,
    compartment_ocid: str,
    vault_ocid: str,
    mek_ocid: str,
    secret_name: str,
    base64_content: str,
    freeform_tags: Dict[str, str],
    wait_seconds: int,
    interval_seconds: int,
    log: logging.Logger,
) -> Any:
    """Create a new vault secret and wait for it to reach ACTIVE."""
    content = oci.vault.models.Base64SecretContentDetails(
        content_type="BASE64",
        content=base64_content,
        stage="CURRENT",
    )
    details = oci.vault.models.CreateSecretDetails(
        compartment_id=compartment_ocid,
        vault_id=vault_ocid,
        key_id=mek_ocid,
        secret_name=secret_name,
        secret_content=content,
        freeform_tags=freeform_tags,
    )
    log.info("Creating secret '%s' in vault %s", secret_name, vault_ocid)
    resp = vaults_client.create_secret(details)
    secret = common.wait_for_state(
        lambda: vaults_client.get_secret(resp.data.id),
        ["ACTIVE"],
        label=f"secret {secret_name}",
        log=log,
        max_wait=wait_seconds,
        interval=interval_seconds,
    )
    log.info(
        "secret '%s' active [%s, current_version=%s]",
        secret_name,
        secret.id,
        getattr(secret, "current_version_number", "?"),
    )
    return secret


def _update_secret(
    vaults_client: Any,
    *,
    secret_id: str,
    secret_name: str,
    base64_content: str,
    freeform_tags: Optional[Dict[str, str]],
    wait_seconds: int,
    interval_seconds: int,
    log: logging.Logger,
) -> Any:
    """Push a new version onto an existing vault secret.

    Args:
        freeform_tags: The full freeform-tag map to set on the secret. The
            caller is responsible for resolving any add/remove/set mutations
            against the existing tags before calling.
    """
    content = oci.vault.models.Base64SecretContentDetails(
        content_type="BASE64",
        content=base64_content,
        stage="CURRENT",
    )
    details = oci.vault.models.UpdateSecretDetails(
        secret_content=content,
        freeform_tags=dict(freeform_tags or {}),
    )
    log.info("Updating secret '%s' (%s) — pushing new version", secret_name, secret_id)
    vaults_client.update_secret(secret_id, details)
    secret = common.wait_for_state(
        lambda: vaults_client.get_secret(secret_id),
        ["ACTIVE"],
        label=f"secret {secret_name}",
        log=log,
        max_wait=wait_seconds,
        interval=interval_seconds,
    )
    log.info(
        "secret '%s' active [%s, current_version=%s]",
        secret_name,
        secret.id,
        getattr(secret, "current_version_number", "?"),
    )
    return secret


def _update_secret_tags_only(
    vaults_client: Any,
    *,
    secret_id: str,
    secret_name: str,
    freeform_tags: Dict[str, str],
    wait_seconds: int,
    interval_seconds: int,
    log: logging.Logger,
) -> Any:
    """Patch ``freeform_tags`` on an existing secret without pushing a new version.

    Issues an ``UpdateSecretDetails`` call with only ``freeform_tags`` set
    (no ``secret_content``). OCI treats this as a metadata-only update:
    ``current_version_number`` is unchanged and no new version is created.

    Args:
        vaults_client: Authenticated ``oci.vault.VaultsClient``.
        secret_id: OCID of the parent secret.
        secret_name: Display name (for log lines).
        freeform_tags: Full freeform-tag map to set on the secret.
        wait_seconds: Max polling time for the secret to settle on ACTIVE.
        interval_seconds: Polling interval.
        log: Active logger.

    Returns:
        The fresh ``Secret`` model after the update settles on ACTIVE.
    """
    details = oci.vault.models.UpdateSecretDetails(
        freeform_tags=dict(freeform_tags or {}),
    )
    log.info(
        "Updating freeform_tags on '%s' (%s) — metadata-only, no new version",
        secret_name,
        secret_id,
    )
    vaults_client.update_secret(secret_id, details)
    secret = common.wait_for_state(
        lambda: vaults_client.get_secret(secret_id),
        ["ACTIVE"],
        label=f"secret {secret_name}",
        log=log,
        max_wait=wait_seconds,
        interval=interval_seconds,
    )
    log.info(
        "secret '%s' active [%s, freeform_tags=%s]",
        secret_name,
        secret.id,
        getattr(secret, "freeform_tags", None),
    )
    return secret


# ---------------------------------------------------------------------------
# list-secrets helpers
# ---------------------------------------------------------------------------
def _list_secrets_rows(
    vaults_client: Any,
    compartment_ocid: str,
    vault_ocid: str,
    name_prefix: Optional[str],
    log: logging.Logger,
) -> List[Dict[str, Any]]:
    """Fetch all secrets in the vault and build per-secret row dicts.

    Each row dict contains:
    ``name``, ``id``, ``lifecycle_state``, ``freeform_tags``,
    ``defined_tags``, ``system_tags``.

    Uses only the summaries from ``list_secrets`` (single paginated call).
    No per-secret ``get_secret`` / ``list_secret_versions`` is issued.

    Args:
        vaults_client: Authenticated ``oci.vault.VaultsClient``.
        compartment_ocid: OCID of the parent compartment.
        vault_ocid: OCID of the target vault.
        name_prefix: Optional server-side prefix filter; ``None`` lists all.
        log: Active logger.

    Returns:
        List of row dicts sorted by ``name`` ascending.
    """
    list_kwargs: Dict[str, Any] = {
        "compartment_id": compartment_ocid,
        "vault_id": vault_ocid,
    }
    if name_prefix is not None:
        list_kwargs["name"] = name_prefix

    summaries = common.list_all(vaults_client.list_secrets, **list_kwargs)
    log.info("Fetched %d secret summaries.", len(summaries))

    rows: List[Dict[str, Any]] = []
    for summary in summaries:
        rows.append(
            {
                "name": summary.secret_name,
                "id": summary.id,
                "lifecycle_state": summary.lifecycle_state,
                "freeform_tags": dict(getattr(summary, "freeform_tags", None) or {}),
                "defined_tags": dict(getattr(summary, "defined_tags", None) or {}),
                "system_tags": dict(getattr(summary, "system_tags", None) or {}),
            }
        )

    rows.sort(key=lambda r: r["name"])
    return rows


def _render_lifecycle_cell(state: str) -> str:
    """Render the Lifecycle cell: blank for ACTIVE, state string otherwise.

    Args:
        state: Lifecycle state string from the OCI API.

    Returns:
        Empty string for ``"ACTIVE"``; the state string for all other values.
    """
    return "" if state == "ACTIVE" else state


def _render_freeform_tags_kv(freeform: Dict[str, str]) -> str:
    """Render freeform tags as a sorted ``key=value`` comma-separated string.

    Args:
        freeform: Freeform tags dict.

    Returns:
        Comma-separated ``k=v`` pairs sorted by key, or empty string if none.
    """
    if not freeform:
        return ""
    return ", ".join(f"{k}={v}" for k, v in sorted(freeform.items()))


def _print_table(rows: List[Dict[str, Any]]) -> None:
    """Print a three-column padded table to stdout.

    Columns: Name | Lifecycle | Tags.

    Args:
        rows: List of row dicts as returned by :func:`_list_secrets_rows`.
    """
    headers = ("Name", "Lifecycle", "Tags")

    # Build display cells for every row so we can compute column widths.
    cells: List[Tuple[str, str, str]] = []
    for row in rows:
        cells.append(
            (
                row["name"],
                _render_lifecycle_cell(row["lifecycle_state"]),
                _render_freeform_tags_kv(row["freeform_tags"]),
            )
        )

    # Column widths: max of header width and widest data cell.
    col_widths = [len(h) for h in headers]
    for row_cells in cells:
        for i, cell in enumerate(row_cells):
            col_widths[i] = max(col_widths[i], len(cell))

    def _fmt_row(cols: Tuple[str, ...]) -> str:
        return "  ".join(c.ljust(col_widths[i]) for i, c in enumerate(cols))

    separator = "  ".join("-" * w for w in col_widths)

    print(_fmt_row(headers))
    print(separator)
    for row_cells in cells:
        print(_fmt_row(row_cells))


def _print_json(rows: List[Dict[str, Any]]) -> None:
    """Print the full rows payload as JSON to stdout.

    Args:
        rows: List of row dicts as returned by :func:`_list_secrets_rows`.
    """
    print(json.dumps(rows, indent=2, sort_keys=True, default=str))


def _resolve_oci_config(
    args: argparse.Namespace, log: logging.Logger
) -> Dict[str, Any]:
    """Load the OCI config for a subcommand.

    Prefers the service-account credentials embedded in ``--summary-file``
    when provided; otherwise falls back to ``--oci-config-file`` (default
    ``~/.oci/config``). An explicitly-provided summary that fails to load
    hard-fails (SystemExit 3); there is no silent fallback.
    """
    if getattr(args, "summary_file", None) is not None:
        log.info(
            "Authenticating via service account from summary file %s",
            args.summary_file,
        )
        return common.load_oci_config_from_summary(
            summary_path=args.summary_file,
            region_override=args.region,
            log=log,
        )
    return common.load_oci_config(
        config_path=args.oci_config_file,
        profile=args.oci_profile,
        region_override=args.region,
        log=log,
    )


# ---------------------------------------------------------------------------
# Subcommand implementations
# ---------------------------------------------------------------------------
def cmd_add_secret(args: argparse.Namespace, log: logging.Logger) -> int:
    """Implement the ``add-secret`` subcommand.

    Byte-for-byte behaviourally equivalent to the former
    ``manage-vault-secrets.py`` ``main()`` post-arg-parse body.

    Args:
        args: Parsed CLI arguments.
        log: Active logger (name: ``manage-vault.add-secret``).

    Returns:
        Process exit code (0 = success).
    """
    log.info("manage-vault add-secret starting (dry_run=%s)", args.dry_run)
    log.debug(
        "parsed args (value redacted): %s",
        {
            **{k: v for k, v in vars(args).items() if k != "secret_value"},
            "secret_value": "<redacted>",
        },
    )

    # SECURITY: raw secret bytes are loaded once here and never logged or
    # serialized. Only ``len`` leaves this scope.
    #
    # Loaded before the dependency check because the value-source validation
    # (e.g. empty stdin) is pure-Python and should report cleanly even on a
    # box without ``oci`` installed.
    raw_value, value_source = _load_secret_value(args, log)
    value_bytes = len(raw_value)
    base64_content = _encode_secret_content(raw_value)
    log.info(
        "Loaded secret value from %s (%d bytes)",
        value_source,
        value_bytes,
    )

    # Parse freeform tags (also pre-import for clean error reporting).
    freeform_tags = _parse_tags_kv(getattr(args, "tags", None), log)
    if freeform_tags:
        log.info(
            "Will attach %d freeform tag(s): %s", len(freeform_tags), freeform_tags
        )

    common.require_dependencies(log, need_cryptography=False)

    config = _resolve_oci_config(args, log)
    tenancy_ocid = common.verify_oci_authenticated(config, log, level=logging.DEBUG)

    identity_client = common.make_client(oci.identity.IdentityClient, config)
    kms_vault_client = common.make_client(oci.key_management.KmsVaultClient, config)
    vaults_client = common.make_client(oci.vault.VaultsClient, config)

    try:
        compartment_ocid = common.lookup_compartment(
            identity_client, tenancy_ocid, args.vault_compartment_name, log
        )
        vault_ocid, mgmt_endpoint = common.lookup_vault(
            kms_vault_client, compartment_ocid, args.vault_name, log
        )
        mek_ocid, mek_name = common.auto_pick_mek(
            config,
            compartment_ocid,
            mgmt_endpoint,
            args.vault_name,
            log,
            mek_name=args.mek_name,
        )

        existing = common.lookup_existing_secret(
            vaults_client, compartment_ocid, vault_ocid, args.secret_name, log
        )

        if existing is not None:
            log.error(
                "Secret '%s' already exists in vault '%s' (id=%s, lifecycle=%s); "
                "add-secret refuses to overwrite. Use 'update-secret' to push a "
                "new version.",
                args.secret_name,
                args.vault_name,
                existing.id,
                existing.lifecycle_state,
            )
            return 12

        # Enforce the OCI Always Free tier 150-secret cap on the target vault.
        # We count non-deletion-state secrets (PENDING_DELETION etc. still
        # count against the per-tenancy cap server-side, but we only refuse
        # locally on the "live" headroom view; the server will reject if we
        # are truly out of room).
        all_secrets = common.list_all(
            vaults_client.list_secrets,
            compartment_id=compartment_ocid,
            vault_id=vault_ocid,
        )
        live_count = sum(
            1
            for s in all_secrets
            if s.lifecycle_state not in common.DELETION_LIFECYCLE_STATES
        )
        if live_count >= common.MAX_SECRETS_ALWAYS_FREE:
            log.error(
                "Vault '%s' already holds %d/%d secrets (Always Free tier cap). "
                "Refusing to create '%s'. Delete unused secrets first.",
                args.vault_name,
                live_count,
                common.MAX_SECRETS_ALWAYS_FREE,
                args.secret_name,
            )
            return 13
        if live_count >= common.WARN_SECRETS_THRESHOLD:
            log.warning(
                "Vault '%s' has %d/%d secrets — approaching the Always Free "
                "tier cap. Consider pruning unused secrets.",
                args.vault_name,
                live_count,
                common.MAX_SECRETS_ALWAYS_FREE,
            )

        if args.dry_run:
            log.info(
                "[DRY-RUN] would create secret '%s' (vault=%s mek=%s, "
                "current_count=%d/%d, freeform_tags=%s)",
                args.secret_name,
                args.vault_name,
                mek_name,
                live_count,
                common.MAX_SECRETS_ALWAYS_FREE,
                freeform_tags,
            )
            action = "would-create"
            secret_ocid = common.dry_run_ocid("secret")
            current_version: Any = None
            lifecycle_state = "DRY-RUN"
        else:
            secret = _create_secret(
                vaults_client,
                compartment_ocid=compartment_ocid,
                vault_ocid=vault_ocid,
                mek_ocid=mek_ocid,
                secret_name=args.secret_name,
                base64_content=base64_content,
                freeform_tags=freeform_tags,
                wait_seconds=args.wait_seconds,
                interval_seconds=args.interval_seconds,
                log=log,
            )
            action = "created"
            secret_ocid = secret.id
            current_version = getattr(secret, "current_version_number", None)
            lifecycle_state = secret.lifecycle_state
    except ServiceError as exc:
        status = getattr(exc, "status", "?")
        code = getattr(exc, "code", "?")
        message = getattr(exc, "message", str(exc))
        # A 404 (or NotAuthorizedOrNotFound) on create/update, *after* we have
        # already confirmed the parents exist, almost always means the
        # principal is missing 'manage secret-family' on the compartment.
        if status == 404 or code == "NotAuthorizedOrNotFound":
            log.error(
                "Secret create/update was rejected by IAM (status=%s code=%s message=%s).",
                status,
                code,
                message,
            )
            log.error(
                "The 'manage secret-family' permission is required to create/update "
                "vault secrets. Either re-run with --oci-profile pointing at an "
                "admin profile, or extend the IAM policy:"
            )
            log.error(
                "    Allow group <grp> to manage secret-family in compartment %s",
                args.vault_compartment_name,
            )
            return 7
        log.error(
            "Aborting on OCI error (status=%s code=%s): %s",
            status,
            code,
            message,
        )
        return 1
    except (RuntimeError, TimeoutError, OSError) as exc:
        log.error("Aborting: %s", exc)
        return 1

    log.info(
        "manage-vault add-secret complete (action=%s, secret=%s, current_version=%s, lifecycle_state=%s)",
        action,
        secret_ocid,
        current_version,
        lifecycle_state,
    )
    return 0


def _classify_versions(versions: List[Any]) -> Tuple[List[Any], List[Any]]:
    """Split a list of ``SecretVersionSummary`` into (active, pending_deletion).

    A version is "active" when its ``stages`` list intersects
    :data:`_ACTIVE_VERSION_STAGES` AND it is not scheduled for deletion.

    A version is "pending_deletion" when it has a scheduled ``time_of_deletion``.

    DEPRECATED-only versions that are not yet scheduled for deletion are
    counted as neither (they no longer occupy an active slot but have not
    been scheduled).

    Args:
        versions: Raw version summaries from ``list_secret_versions``.

    Returns:
        Tuple ``(active, pending_deletion)`` lists.
    """
    active: List[Any] = []
    pending_del: List[Any] = []
    for v in versions:
        if getattr(v, "time_of_deletion", None) is not None:
            pending_del.append(v)
            continue
        stages = set(getattr(v, "stages", None) or [])
        if stages & _ACTIVE_VERSION_STAGES:
            active.append(v)
    return active, pending_del


def _deprecate_and_schedule_delete_each(
    vaults_client: Any,
    *,
    secret_id: str,
    secret_name: str,
    versions: List[Any],
    log: logging.Logger,
) -> bool:
    """Deprecate and schedule-delete every version in ``versions``.

    A version must transition through DEPRECATED before it can be scheduled
    for deletion (per OCI Vault docs). Best-effort: any per-version error
    is logged at ERROR and the loop continues; the return value reports
    whether anything failed.

    Args:
        vaults_client: Authenticated ``oci.vault.VaultsClient``.
        secret_id: OCID of the parent secret.
        secret_name: Display name (for log lines).
        versions: Iterable of version summaries to deprecate.
        log: Active logger.

    Returns:
        ``True`` if any per-version deprecate/schedule call failed;
        ``False`` if every version was processed cleanly (or the input
        was empty).
    """
    if not versions:
        return False

    now = common.now_utc()
    # Use the OCI-documented minimum retention so the slot frees as soon as
    # possible. Add a 1-minute buffer to absorb wall-clock skew.
    tod = now + timedelta(days=common.MIN_SECRET_DELETION_DAYS) + timedelta(minutes=1)
    tod_str = common.format_oci_time(tod)

    any_failed = False
    for v in versions:
        vnum = int(getattr(v, "version_number"))
        try:
            log.info(
                "Scheduling deletion of version %d of '%s' at %s (already DEPRECATED post-push)",
                vnum,
                secret_name,
                tod_str,
            )
            vaults_client.schedule_secret_version_deletion(
                secret_id,
                vnum,
                oci.vault.models.ScheduleSecretVersionDeletionDetails(
                    time_of_deletion=tod
                ),
            )
            # Wait for the parent secret to return to ACTIVE state so that
            # subsequent version deletion requests do not fail with a 409 UPDATING conflict.
            common.wait_for_state(
                lambda: vaults_client.get_secret(secret_id),
                ["ACTIVE"],
                label=f"secret {secret_name}",
                log=log,
                max_wait=60,
                interval=2,
            )
        except ServiceError as exc:
            log.error(
                "Failed to schedule deletion of version %d of '%s' "
                "(status=%s code=%s): %s — continuing",
                vnum,
                secret_name,
                getattr(exc, "status", "?"),
                getattr(exc, "code", "?"),
                getattr(exc, "message", str(exc)),
            )
            any_failed = True
            continue
        except (RuntimeError, OSError) as exc:
            log.error(
                "Failed to schedule deletion of version %d of '%s': %s — continuing",
                vnum,
                secret_name,
                exc,
            )
            any_failed = True
            continue

    return any_failed


def cmd_update_secret(args: argparse.Namespace, log: logging.Logger) -> int:
    """Implement the ``update-secret`` subcommand.

    Two modes, selected automatically based on the flags passed:

    * **value-push**: ``--secret-value`` is provided (literal, ``-`` for
      stdin, or omitted on a TTY to be prompted). A new version is pushed
      and every other active version is deprecated + schedule-deleted
      post-push. Best-effort cleanup; partial failure → exit 16.
    * **tags-only**: ``--secret-value`` is omitted AND at least one of
      ``--add-tags`` / ``--remove-tags`` / ``--set-tags`` is given. A
      metadata-only update is issued (no new version, no prune).

    Either mode refuses to create: exits 5 if the secret does not exist.
    Tag mutation flags are mutually exclusive and resolved against the
    existing freeform tags before the update.

    Args:
        args: Parsed CLI arguments.
        log: Active logger (name: ``manage-vault.update-secret``).

    Returns:
        Process exit code (0 = success, 16 = post-push cleanup failure).
    """
    # Decide mode BEFORE loading the secret value. If the caller passed any
    # tag flag and did NOT pass --secret-value, we skip the value-loading
    # entirely (which would otherwise prompt on a TTY or exit 9 on a pipe).
    has_tag_mutation = (
        getattr(args, "add_tags", None) is not None
        or getattr(args, "remove_tags", None) is not None
        or getattr(args, "set_tags", None) is not None
    )
    tags_only_mode = args.secret_value is None and has_tag_mutation

    log.info(
        "manage-vault update-secret starting (dry_run=%s, mode=%s)",
        args.dry_run,
        "tags-only" if tags_only_mode else "value-push",
    )
    log.debug(
        "parsed args (value redacted): %s",
        {
            **{k: v for k, v in vars(args).items() if k != "secret_value"},
            "secret_value": "<redacted>",
        },
    )

    # Value loading happens only in value-push mode. In tags-only mode we
    # skip both _load_secret_value and the base64 encoding step.
    if tags_only_mode:
        base64_content = None  # type: ignore[assignment]
    else:
        # SECURITY: raw secret bytes are loaded once here and never logged or
        # serialized. Only ``len`` leaves this scope.
        raw_value, value_source = _load_secret_value(args, log)
        value_bytes = len(raw_value)
        base64_content = _encode_secret_content(raw_value)
        log.info("Loaded secret value from %s (%d bytes)", value_source, value_bytes)

    common.require_dependencies(log, need_cryptography=False)

    config = _resolve_oci_config(args, log)
    tenancy_ocid = common.verify_oci_authenticated(config, log, level=logging.DEBUG)

    identity_client = common.make_client(oci.identity.IdentityClient, config)
    kms_vault_client = common.make_client(oci.key_management.KmsVaultClient, config)
    vaults_client = common.make_client(oci.vault.VaultsClient, config)

    cleanup_failed = False

    try:
        compartment_ocid = common.lookup_compartment(
            identity_client, tenancy_ocid, args.vault_compartment_name, log
        )
        vault_ocid, _mgmt_endpoint = common.lookup_vault(
            kms_vault_client, compartment_ocid, args.vault_name, log
        )

        existing = common.lookup_existing_secret(
            vaults_client, compartment_ocid, vault_ocid, args.secret_name, log
        )
        if existing is None:
            log.error(
                "Secret '%s' not found in vault '%s'. Use 'add-secret' to create.",
                args.secret_name,
                args.vault_name,
            )
            return 5

        # Resolve the freeform-tags mutation BEFORE pushing.
        resolved_tags, tag_mode = _resolve_tag_mutation(
            getattr(existing, "freeform_tags", None) or {}, args, log
        )
        if tag_mode is not None:
            log.info(
                "Tag mutation mode=%s; resolved freeform_tags=%s",
                tag_mode,
                resolved_tags,
            )

        # ---- tags-only short-circuit -----------------------------------
        # When the caller passed only tag flags (no --secret-value), do a
        # metadata-only update: no version list, no push, no post-push
        # prune. This is the fast path for renaming/retagging a secret.
        if tags_only_mode:
            if args.dry_run:
                log.info(
                    "[DRY-RUN] would update freeform_tags on '%s' to %s "
                    "(no new version, tag_mode=%s)",
                    args.secret_name,
                    resolved_tags,
                    tag_mode,
                )
                action = "would-tags-update"
                secret_ocid = existing.id
                current_version = getattr(existing, "current_version_number", None)
                lifecycle_state = existing.lifecycle_state
            else:
                # Settle any mid-transition lifecycle state first.
                if existing.lifecycle_state != "ACTIVE":
                    common.wait_for_state(
                        lambda: vaults_client.get_secret(existing.id),
                        ["ACTIVE"],
                        label=f"secret {args.secret_name}",
                        log=log,
                        max_wait=args.wait_seconds,
                        interval=args.interval_seconds,
                    )
                secret = _update_secret_tags_only(
                    vaults_client,
                    secret_id=existing.id,
                    secret_name=args.secret_name,
                    freeform_tags=resolved_tags,
                    wait_seconds=args.wait_seconds,
                    interval_seconds=args.interval_seconds,
                    log=log,
                )
                action = "tags-updated"
                secret_ocid = secret.id
                current_version = getattr(secret, "current_version_number", None)
                lifecycle_state = secret.lifecycle_state

            log.info(
                "manage-vault update-secret complete (action=%s, secret=%s, "
                "current_version=%s, lifecycle_state=%s, cleanup_failed=False)",
                action,
                secret_ocid,
                current_version,
                lifecycle_state,
            )
            return 0

        # Enumerate current versions (informational + cleanup source).
        versions = common.list_all(
            vaults_client.list_secret_versions, secret_id=existing.id
        )
        active, pending_del = _classify_versions(versions)
        log.info(
            "Secret '%s' currently has %d active version(s) and %d pending-deletion "
            "version(s) (total summaries: %d).",
            args.secret_name,
            len(active),
            len(pending_del),
            len(versions),
        )
        if len(pending_del) >= common.MAX_PENDING_VERSIONS_ALWAYS_FREE:
            log.warning(
                "Secret '%s' already has %d/%d pending-deletion versions; OCI may "
                "reject further updates until some are fully deleted.",
                args.secret_name,
                len(pending_del),
                common.MAX_PENDING_VERSIONS_ALWAYS_FREE,
            )

        current_version_before = getattr(existing, "current_version_number", "?")
        if args.dry_run:
            log.info(
                "[DRY-RUN] would update secret '%s' to a new version "
                "(current_version=%s, active_versions=%d, tag_mode=%s)",
                args.secret_name,
                current_version_before,
                len(active),
                tag_mode,
            )
            # Pre-compute which versions would be pruned post-push.
            # current_version_before is the CURRENT pre-push; the new version
            # will be CURRENT post-push, so EVERY active version we see now
            # (including the pre-push CURRENT) would be deprecated.
            for v in active:
                vnum = int(getattr(v, "version_number"))
                log.info(
                    "[DRY-RUN] would deprecate+schedule-delete version %d of '%s' "
                    "after pushing the new version",
                    vnum,
                    args.secret_name,
                )
            action = "would-update"
            secret_ocid = existing.id
            current_version: Any = current_version_before
            lifecycle_state = existing.lifecycle_state
        else:
            # If the existing secret is mid-transition, settle it before
            # update so OCI does not reject the call with a 409.
            if existing.lifecycle_state != "ACTIVE":
                common.wait_for_state(
                    lambda: vaults_client.get_secret(existing.id),
                    ["ACTIVE"],
                    label=f"secret {args.secret_name}",
                    log=log,
                    max_wait=args.wait_seconds,
                    interval=args.interval_seconds,
                )
            secret = _update_secret(
                vaults_client,
                secret_id=existing.id,
                secret_name=args.secret_name,
                base64_content=base64_content,
                freeform_tags=resolved_tags,
                wait_seconds=args.wait_seconds,
                interval_seconds=args.interval_seconds,
                log=log,
            )
            action = "updated"
            secret_ocid = secret.id
            current_version = getattr(secret, "current_version_number", None)
            lifecycle_state = secret.lifecycle_state

            # Post-push cleanup: schedule-delete every deprecated version.
            # Best-effort: a failure flips cleanup_failed but does not abort.
            try:
                post_versions = common.list_all(
                    vaults_client.list_secret_versions, secret_id=existing.id
                )
            except ServiceError as exc:
                log.error(
                    "Failed to re-list secret versions for post-push cleanup "
                    "(status=%s code=%s): %s",
                    getattr(exc, "status", "?"),
                    getattr(exc, "code", "?"),
                    getattr(exc, "message", str(exc)),
                )
                cleanup_failed = True
                post_versions = []

            to_prune = [
                v
                for v in post_versions
                if "DEPRECATED" in (getattr(v, "stages", None) or [])
                and getattr(v, "time_of_deletion", None) is None
            ]
            log.info(
                "Post-push cleanup: %d deprecated version(s) found to prune.",
                len(to_prune),
            )
            cleanup_failed_some = _deprecate_and_schedule_delete_each(
                vaults_client,
                secret_id=existing.id,
                secret_name=args.secret_name,
                versions=to_prune,
                log=log,
            )
            if cleanup_failed_some:
                cleanup_failed = True
    except ServiceError as exc:
        status = getattr(exc, "status", "?")
        code = getattr(exc, "code", "?")
        message = getattr(exc, "message", str(exc))
        if status == 404 or code == "NotAuthorizedOrNotFound":
            log.error(
                "Secret update was rejected by IAM (status=%s code=%s message=%s).",
                status,
                code,
                message,
            )
            log.error(
                "The 'manage secret-family' permission is required to update "
                "vault secrets."
            )
            return 7
        log.error(
            "Aborting on OCI error (status=%s code=%s): %s", status, code, message
        )
        return 1
    except (RuntimeError, TimeoutError, OSError) as exc:
        log.error("Aborting: %s", exc)
        return 1

    log.info(
        "manage-vault update-secret complete (action=%s, secret=%s, current_version=%s, "
        "lifecycle_state=%s, cleanup_failed=%s)",
        action,
        secret_ocid,
        current_version,
        lifecycle_state,
        cleanup_failed,
    )
    if cleanup_failed:
        log.error(
            "One or more old version cleanups failed. The new version IS already "
            "pushed and ACTIVE; re-run update-secret (or manually deprecate the "
            "stragglers) to retry."
        )
        return 16
    return 0


def cmd_get_secret(args: argparse.Namespace, log: logging.Logger) -> int:
    """Implement the ``get-secret`` subcommand.

    Reveals a secret's value via the OCI data-plane ``SecretsClient``.
    Always reads the ``LATEST`` stage (the most recently pushed version).

    The raw bytes are never logged. An INFO audit log line is emitted
    immediately before the value is written to stdout (visible with ``-v``
    or higher).

    Args:
        args: Parsed CLI arguments.
        log: Active logger (name: ``manage-vault.get-secret``).

    Returns:
        Process exit code (0 = success).
    """
    log.info(
        "manage-vault get-secret starting (secret=%s, output_format=%s, dry_run=%s)",
        args.secret_name,
        args.output_format,
        args.dry_run,
    )

    common.require_dependencies(log, need_cryptography=False)

    config = _resolve_oci_config(args, log)
    tenancy_ocid = common.verify_oci_authenticated(config, log, level=logging.DEBUG)

    identity_client = common.make_client(oci.identity.IdentityClient, config)
    kms_vault_client = common.make_client(oci.key_management.KmsVaultClient, config)
    vaults_client = common.make_client(oci.vault.VaultsClient, config)

    try:
        compartment_ocid = common.lookup_compartment(
            identity_client, tenancy_ocid, args.vault_compartment_name, log
        )
        vault_ocid, _mgmt_endpoint = common.lookup_vault(
            kms_vault_client, compartment_ocid, args.vault_name, log
        )

        existing = common.lookup_existing_secret(
            vaults_client, compartment_ocid, vault_ocid, args.secret_name, log
        )
        if existing is None:
            log.error(
                "Secret '%s' not found in vault '%s'.",
                args.secret_name,
                args.vault_name,
            )
            return 5

        # Always read the LATEST stage (the most recently pushed version).
        selector_label = "stage=LATEST"

        if args.dry_run:
            log.info(
                "[DRY-RUN] would reveal secret '%s' (%s) — not contacting the data plane",
                args.secret_name,
                selector_label,
            )
            return 0

        # Audit log line BEFORE the reveal. The principal is the tenancy OCID
        # from the OCI config preflight — we cannot derive the IAM user from
        # the config alone without an extra API call.
        log.info(
            "Revealing secret '%s' (%s, id=%s) to stdout (principal_tenancy=%s, output_format=%s)",
            args.secret_name,
            selector_label,
            existing.id,
            tenancy_ocid,
            args.output_format,
        )

        secrets_client = common.make_client(oci.secrets.SecretsClient, config)
        try:
            bundle = secrets_client.get_secret_bundle(
                secret_id=existing.id, stage="LATEST"
            ).data
        except ServiceError as exc:
            status = getattr(exc, "status", "?")
            code = getattr(exc, "code", "?")
            message = getattr(exc, "message", str(exc))
            if status == 404:
                log.error(
                    "Requested %s on secret '%s' not found (status=%s code=%s): %s",
                    selector_label,
                    args.secret_name,
                    status,
                    code,
                    message,
                )
                return 15
            raise

        content = bundle.secret_bundle_content
        content_type = getattr(content, "content_type", None)
        content_b64 = getattr(content, "content", None)
        if content_type != "BASE64" or content_b64 is None:
            log.error(
                "Unexpected secret bundle content_type=%r; cannot decode.",
                content_type,
            )
            return 1

        version_number = getattr(bundle, "version_number", None)
        stages = list(getattr(bundle, "stages", None) or [])

        if args.output_format == "raw":
            raw = base64.b64decode(content_b64)
            sys.stdout.buffer.write(raw)
            sys.stdout.buffer.flush()
        elif args.output_format == "base64":
            print(content_b64)
        else:  # json
            payload = {
                "secret_name": args.secret_name,
                "secret_id": existing.id,
                "version_number": version_number,
                "stages": stages,
                "content_type": content_type,
                "content_base64": content_b64,
            }
            print(json.dumps(payload, indent=2, sort_keys=True, default=str))

        log.info(
            "manage-vault get-secret complete (secret=%s, version=%s, stages=%s)",
            existing.id,
            version_number,
            stages,
        )
        return 0

    except ServiceError as exc:
        status = getattr(exc, "status", "?")
        code = getattr(exc, "code", "?")
        message = getattr(exc, "message", str(exc))
        if status == 404 or code == "NotAuthorizedOrNotFound":
            log.error(
                "Secret read was rejected by IAM (status=%s code=%s message=%s).",
                status,
                code,
                message,
            )
            log.error(
                "The 'read secret-family' permission is required to read vault "
                "secret bundles."
            )
            return 7
        log.error(
            "Aborting on OCI error (status=%s code=%s): %s", status, code, message
        )
        return 1
    except (RuntimeError, OSError) as exc:
        log.error("Aborting: %s", exc)
        return 1


def cmd_delete_secret(args: argparse.Namespace, log: logging.Logger) -> int:
    """Implement the ``delete-secret`` subcommand.

    Args:
        args: Parsed CLI arguments.
        log: Active logger (name: ``manage-vault.delete-secret``).

    Returns:
        Process exit code.
    """
    log.info(
        "manage-vault delete-secret starting (secret=%s, dry_run=%s)",
        args.secret_name,
        args.dry_run,
    )

    common.require_dependencies(log, need_cryptography=False)

    config = _resolve_oci_config(args, log)
    tenancy_ocid = common.verify_oci_authenticated(config, log, level=logging.DEBUG)

    identity_client = common.make_client(oci.identity.IdentityClient, config)
    kms_vault_client = common.make_client(oci.key_management.KmsVaultClient, config)
    vaults_client = common.make_client(oci.vault.VaultsClient, config)

    try:
        compartment_ocid = common.lookup_compartment(
            identity_client, tenancy_ocid, args.vault_compartment_name, log
        )
        vault_ocid, _mgmt_endpoint = common.lookup_vault(
            kms_vault_client, compartment_ocid, args.vault_name, log
        )

        # lookup_existing_secret raises SystemExit(8) for *_DELETION states,
        # but for delete-secret we want to treat those as idempotent (exit 0).
        # We do the lookup manually here.
        all_matches = [
            s
            for s in common.list_all(
                vaults_client.list_secrets,
                compartment_id=compartment_ocid,
                vault_id=vault_ocid,
                name=args.secret_name,
            )
            if s.secret_name == args.secret_name
        ]

        if not all_matches:
            log.error(
                "Secret '%s' not found in vault '%s'.",
                args.secret_name,
                args.vault_name,
            )
            return 5

        secret_summary = all_matches[0]

        # Idempotent: already scheduled for deletion.
        if secret_summary.lifecycle_state in common.DELETION_LIFECYCLE_STATES:
            time_of_del = getattr(secret_summary, "time_of_deletion", None)
            log.info(
                "Secret '%s' (%s) is already scheduled for deletion at %s (state=%s); nothing to do.",
                args.secret_name,
                secret_summary.id,
                common.format_oci_time(time_of_del) if time_of_del else "unknown",
                secret_summary.lifecycle_state,
            )
            return 0

        # Compute time_of_deletion.
        now = common.now_utc()
        min_days = common.MIN_SECRET_DELETION_DAYS
        max_days = common.MAX_SECRET_DELETION_DAYS

        if args.time_of_deletion:
            try:
                tod = common.parse_oci_time(args.time_of_deletion)
            except ValueError as exc:
                log.error("Invalid --time-of-deletion: %s", exc)
                return 10
            min_allowed = now + timedelta(days=min_days)
            max_allowed = now + timedelta(days=max_days)
            # Allow 1-minute slack on the lower bound to absorb wall-clock skew.
            if tod < min_allowed - timedelta(minutes=1) or tod > max_allowed:
                log.error(
                    "--time-of-deletion %s is outside the allowed window (%s to %s).",
                    args.time_of_deletion,
                    common.format_oci_time(min_allowed),
                    common.format_oci_time(max_allowed),
                )
                return 10
            # Defensive cap (should not be reachable after validation above).
            upper = max_allowed
            tod = min(tod, upper)
        else:
            if args.days != 0 and (args.days < min_days or args.days > max_days):
                log.error(
                    "--days must be 0 or between %d and %d (got %d).",
                    min_days,
                    max_days,
                    args.days,
                )
                return 10
            effective_days = args.days if args.days != 0 else min_days
            upper = now + timedelta(days=max_days)
            tod = now + timedelta(days=effective_days) + timedelta(minutes=1)
            # Defensive cap (should not be reachable after validation above).
            tod = min(tod, upper)

        tod_str = common.format_oci_time(tod)

        if args.dry_run:
            log.info(
                "[DRY-RUN] would schedule deletion of secret '%s' (%s) at %s",
                args.secret_name,
                secret_summary.id,
                tod_str,
            )
            return 0

        # Confirmation gate (skipped on dry-run so --yes is not required).
        common.prompt_destructive_confirm(
            f"Schedule deletion of secret '{args.secret_name}' ({secret_summary.id}) at {tod_str}?",
            yes=args.yes,
            log=log,
        )

        log.info(
            "Scheduling deletion of secret '%s' (%s) at %s",
            args.secret_name,
            secret_summary.id,
            tod_str,
        )
        vaults_client.schedule_secret_deletion(
            secret_summary.id,
            oci.vault.models.ScheduleSecretDeletionDetails(time_of_deletion=tod),
        )

        final = common.wait_for_state(
            lambda: vaults_client.get_secret(secret_summary.id),
            ["PENDING_DELETION", "SCHEDULING_DELETION"],
            label=f"secret {args.secret_name}",
            log=log,
            max_wait=args.wait_seconds,
            interval=args.interval_seconds,
        )

        log.info(
            "manage-vault delete-secret complete (secret=%s, time_of_deletion=%s, lifecycle_state=%s)",
            final.id,
            tod_str,
            final.lifecycle_state,
        )
        return 0

    except ServiceError as exc:
        log.error(
            "OCI error (status=%s code=%s): %s",
            getattr(exc, "status", "?"),
            getattr(exc, "code", "?"),
            getattr(exc, "message", str(exc)),
        )
        return 1
    except (RuntimeError, TimeoutError) as exc:
        log.error("Aborting: %s", exc)
        return 1


def cmd_list_secrets(args: argparse.Namespace, log: logging.Logger) -> int:
    """Implement the ``list-secrets`` subcommand.

    Prints a three-column table (Name, Lifecycle, Tags) to stdout, or a full
    JSON payload when ``--output-format json`` is requested.

    IAM note: requires only ``read secret-family`` on the compartment; the
    broader ``manage secret-family`` is not needed for this read-only command.

    Args:
        args: Parsed CLI arguments.
        log: Active logger (name: ``manage-vault.list-secrets``).

    Returns:
        Process exit code (0 = success, 1 = OCI/runtime error, 5 = not found).
    """
    log.info(
        "manage-vault list-secrets starting "
        "(vault=%s, compartment=%s, output_format=%s, dry_run=%s)",
        args.vault_name,
        args.vault_compartment_name,
        args.output_format,
        args.dry_run,
    )
    if args.dry_run:
        log.info(
            "--dry-run is a no-op for list-secrets; proceeding with read-only listing."
        )

    common.require_dependencies(log, need_cryptography=False)

    config = _resolve_oci_config(args, log)
    tenancy_ocid = common.verify_oci_authenticated(config, log, level=logging.DEBUG)

    identity_client = common.make_client(oci.identity.IdentityClient, config)
    kms_vault_client = common.make_client(oci.key_management.KmsVaultClient, config)
    vaults_client = common.make_client(oci.vault.VaultsClient, config)

    try:
        compartment_ocid = common.lookup_compartment(
            identity_client, tenancy_ocid, args.vault_compartment_name, log
        )
        vault_ocid, _mgmt_endpoint = common.lookup_vault(
            kms_vault_client, compartment_ocid, args.vault_name, log
        )

        rows = _list_secrets_rows(
            vaults_client,
            compartment_ocid,
            vault_ocid,
            args.name_prefix,
            log,
        )

        if args.output_format == "json":
            _print_json(rows)
        else:
            _print_table(rows)

        log.info("manage-vault list-secrets complete (%d secrets listed).", len(rows))
        return 0

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


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------
def main(argv: Optional[List[str]] = None) -> int:
    """Entry point.

    Args:
        argv: Optional explicit argv list.

    Returns:
        Process exit code.
    """
    args = parse_args(argv)

    subcommand_loggers = {
        "add-secret": _LOGGER_ADD_SECRET,
        "update-secret": _LOGGER_UPDATE_SECRET,
        "get-secret": _LOGGER_GET_SECRET,
        "delete-secret": _LOGGER_DELETE_SECRET,
        "list-secrets": _LOGGER_LIST_SECRETS,
    }
    logger_name = subcommand_loggers.get(args.subcommand, "manage-vault")
    log = common.setup_logging(args.verbose, logger_name)

    dispatch = {
        "add-secret": cmd_add_secret,
        "update-secret": cmd_update_secret,
        "get-secret": cmd_get_secret,
        "delete-secret": cmd_delete_secret,
        "list-secrets": cmd_list_secrets,
    }

    handler = dispatch.get(args.subcommand)
    if handler is None:
        log.error("Unknown subcommand: %s", args.subcommand)
        return 1

    return handler(args, log)


if __name__ == "__main__":
    sys.exit(main())
