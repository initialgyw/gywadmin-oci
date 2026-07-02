#!/usr/bin/env python3
"""Synchronize OCI initialization output into GitHub Actions repository secrets.

Reads the JSON summary produced by ``initialize-oci.py`` and pushes seven
secrets into a GitHub repository using the ``gh`` CLI.

Secrets set
-----------
* ``AWS_ACCESS_KEY_ID``          — OCI Customer Secret Key access key (S3-compat)
* ``AWS_SECRET_ACCESS_KEY``      — OCI Customer Secret Key secret key (S3-compat)
* ``OCI_CLI_TENANCY``            — Tenancy OCID
* ``OCI_CLI_USER``               — Service-account user OCID
* ``OCI_CLI_FINGERPRINT``        — API key fingerprint
* ``OCI_CLI_KEY_CONTENT``        — RSA private key PEM (encrypted)
* ``TF_VAR_private_key_password`` — Passphrase protecting the private key

Required input
--------------
``--repo / -R OWNER/REPO`` is **strictly required**; there is no env-var
fallback and no ``git remote`` auto-detection.

The summary JSON must contain the following structure (produced by
``initialize-oci.py --create-sa-keys``)::

    {
      "tenancy_ocid": "<string>",
      "service_account": {
        "ocid": "<string>",
        "api_key": {
          "fingerprint": "<string>",
          "private_pem": "<string>",
          "passphrase": "<string>"
        },
        "customer_secret_key": {
          "access_key": "<string>",
          "secret_key": "<string>"
        }
      }
    }

Exit codes
----------
| Code | Meaning                                                              |
|------|----------------------------------------------------------------------|
|  0   | All secrets set (or dry-run completed).                              |
|  1   | One or more secrets failed to set.                                   |
|  2   | ``gh`` CLI not found in PATH.                                        |
|  3   | Summary file missing, unreadable, invalid JSON, or invalid contents. |
|  4   | ``gh auth status`` or ``gh repo view`` preflight failed.             |
| 11   | User declined the confirmation prompt.                               |
"""

from __future__ import annotations

import argparse
import logging
import subprocess
import sys
from pathlib import Path
from typing import Callable, List, Optional

from gywadmin_oci.common import (
    DEFAULT_SUMMARY_PATH,
    OciSummarySecrets,
    load_summary,
    prompt_destructive_confirm,
    setup_logging,
    validate_summary_file,
)

# Backward-compat alias so existing imports (e.g. tests) keep working.
GitHubSecrets = OciSummarySecrets

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
LOGGER_NAME = "update_github_secrets"
GH_TIMEOUT_SECONDS = 30


# ---------------------------------------------------------------------------
# Runner type alias
# ---------------------------------------------------------------------------
Runner = Callable[[List[str], bytes, float], "subprocess.CompletedProcess[bytes]"]


def default_runner(
    argv: List[str], stdin_bytes: bytes, timeout: float
) -> "subprocess.CompletedProcess[bytes]":
    """Invoke a subprocess in bytes mode and return the completed process.

    Args:
        argv: Command and arguments to execute.
        stdin_bytes: Raw bytes to write to the process's stdin.
        timeout: Maximum seconds to wait before raising
            :exc:`subprocess.TimeoutExpired`.

    Returns:
        :class:`subprocess.CompletedProcess` with ``stdout=None`` and
        ``stderr`` as ``bytes``.
    """
    return subprocess.run(
        argv,
        input=stdin_bytes,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )


# ---------------------------------------------------------------------------
# GitHub CLI helpers
# ---------------------------------------------------------------------------
def set_github_secret(
    secret_name: str,
    secret_value: str,
    *,
    repo: str,
    runner: Runner = default_runner,
    timeout: float = GH_TIMEOUT_SECONDS,
    log: logging.Logger,
) -> bool:
    """Push a single secret to a GitHub repository via the ``gh`` CLI.

    The secret value is passed via stdin so it never appears in the process
    argument list.  The value is **never** logged.

    Args:
        secret_name: GitHub Actions secret name (e.g. ``AWS_ACCESS_KEY_ID``).
        secret_value: The secret's plaintext value.
        repo: Target repository in ``OWNER/REPO`` format.
        runner: Callable matching :data:`Runner`; defaults to
            :func:`default_runner`.  Injected for testing.
        timeout: Maximum seconds to wait for ``gh`` to respond.
        log: Active logger.

    Returns:
        ``True`` on success, ``False`` on failure.

    Raises:
        FileNotFoundError: If the ``gh`` binary is not found in PATH.
    """
    argv = ["gh", "secret", "set", secret_name, "--repo", repo]
    stdin_bytes = secret_value.encode("utf-8")

    try:
        result = runner(argv, stdin_bytes, timeout)
    except subprocess.TimeoutExpired:
        log.error("Timed out after %ds setting secret %s", int(timeout), secret_name)
        return False
    # FileNotFoundError propagates to the caller (maps to exit 2).

    if result.returncode != 0:
        raw_stderr = result.stderr or b""
        decoded = raw_stderr.decode("utf-8", errors="replace").strip()
        # Redact the secret value from any error output before logging.
        safe_stderr = decoded.replace(secret_value, "<redacted>")
        log.error(
            "Failed to set secret %s (rc=%d): %s",
            secret_name,
            result.returncode,
            safe_stderr,
        )
        return False

    log.info("Set secret %s", secret_name)
    return True


def preflight_gh(
    repo: str,
    *,
    runner: Runner = default_runner,
    log: logging.Logger,
) -> None:
    """Verify that ``gh`` is authenticated and the target repository is accessible.

    Runs two checks:

    1. ``gh auth status`` — confirms the CLI is authenticated.
    2. ``gh repo view OWNER/REPO --json name -q .name`` — confirms the repo
       slug is valid and the token has access.  A bad ``--repo`` value
       surfaces here (per Q5 in the design spec).

    Args:
        repo: Target repository in ``OWNER/REPO`` format.
        runner: Callable matching :data:`Runner`; defaults to
            :func:`default_runner`.
        log: Active logger.

    Raises:
        SystemExit: With code ``2`` if ``gh`` is not found; code ``4`` if
            either preflight check fails.
    """
    # --- auth status --------------------------------------------------------
    try:
        auth_result = runner(["gh", "auth", "status"], b"", 15.0)
    except FileNotFoundError:
        log.error("gh CLI not found in PATH. Install from https://cli.github.com/")
        raise SystemExit(2)

    if auth_result.returncode != 0:
        raw = (auth_result.stderr or b"").decode("utf-8", errors="replace").strip()
        log.error("gh auth status failed (rc=%d): %s", auth_result.returncode, raw)
        raise SystemExit(4)

    # --- repo view ----------------------------------------------------------
    view_result = runner(
        ["gh", "repo", "view", repo, "--json", "name", "-q", ".name"],
        b"",
        15.0,
    )
    if view_result.returncode != 0:
        raw = (view_result.stderr or b"").decode("utf-8", errors="replace").strip()
        log.error(
            "gh repo view failed for %r (rc=%d): %s",
            repo,
            view_result.returncode,
            raw,
        )
        raise SystemExit(4)

    log.debug("gh auth and repo preflight succeeded for %s", repo)


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------
def process_secrets(
    summary_file: Path,
    *,
    repo: str,
    dry_run: bool,
    yes: bool,
    fail_fast: bool,
    runner: Runner = default_runner,
    log: logging.Logger,
) -> int:
    """Load the summary file and push all secrets to GitHub.

    Args:
        summary_file: Path to the ``initialize-oci-summary.json`` file.
        repo: Target GitHub repository in ``OWNER/REPO`` format.
        dry_run: If ``True``, log the plan and return without contacting GitHub.
        yes: If ``True``, skip the interactive confirmation prompt.
        fail_fast: If ``True``, abort on the first failed secret instead of
            continuing best-effort.
        runner: Subprocess runner; injected for testing.
        log: Active logger.

    Returns:
        Process exit code (``0`` = all succeeded, ``1`` = partial failure,
        ``2`` = ``gh`` not found, ``3`` = bad summary).
    """
    validate_summary_file(summary_file, log=log)
    data = load_summary(summary_file, log=log)

    try:
        secrets = GitHubSecrets.from_initialize_oci_summary(data)
    except (KeyError, TypeError, ValueError) as exc:
        # Never include the offending value in the message.
        log.error("Invalid summary: %s", exc)
        raise SystemExit(3)

    pairs = secrets.as_ordered_items()
    names = [name for name, _ in pairs]
    log.debug("Secrets to set (%d): %s", len(names), ", ".join(names))

    if dry_run:
        log.info(
            "Dry run: would set %d secrets in %s: %s",
            len(pairs),
            repo,
            ", ".join(names),
        )
        return 0

    preflight_gh(repo, runner=runner, log=log)

    prompt_destructive_confirm(
        f"About to overwrite {len(pairs)} secrets in {repo}",
        yes=yes,
        log=log,
    )

    failed: List[str] = []
    succeeded = 0

    for name, value in pairs:
        try:
            ok = set_github_secret(
                name,
                value,
                repo=repo,
                runner=runner,
                log=log,
            )
        except FileNotFoundError:
            log.error("gh CLI not found in PATH")
            return 2

        if ok:
            succeeded += 1
        else:
            failed.append(name)
            if fail_fast:
                break

    total = len(pairs)
    log.info("Set %d/%d secrets", succeeded, total)

    if failed:
        log.error("Failed secrets: %s", ", ".join(failed))
        return 1

    return 0


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main(argv: Optional[List[str]] = None) -> int:
    """Parse arguments and run :func:`process_secrets`.

    Args:
        argv: Optional explicit argv list (useful for testing).

    Returns:
        Process exit code.
    """
    parser = argparse.ArgumentParser(
        description="Update GitHub repository secrets from an OCI initialization summary."
    )
    parser.add_argument(
        "--repo",
        "-R",
        required=True,
        help="Target GitHub repository, e.g. OWNER/REPO.",
    )
    parser.add_argument(
        "--summary-file",
        "-f",
        type=Path,
        default=DEFAULT_SUMMARY_PATH,
        help="Path to initialize-oci-summary.json (default: %(default)s).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the plan without contacting GitHub.",
    )
    parser.add_argument(
        "--yes",
        "-y",
        action="store_true",
        help="Skip the confirmation prompt.",
    )
    parser.add_argument(
        "--fail-fast",
        action="store_true",
        help="Abort on the first failed secret instead of best-effort.",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="count",
        default=0,
        help="Increase verbosity (-v, -vv, -vvv).",
    )

    args = parser.parse_args(argv)
    log = setup_logging(args.verbose, LOGGER_NAME)

    return process_secrets(
        args.summary_file,
        repo=args.repo,
        dry_run=args.dry_run,
        yes=args.yes,
        fail_fast=args.fail_fast,
        log=log,
    )


if __name__ == "__main__":
    sys.exit(main())
