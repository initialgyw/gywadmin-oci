"""Boundary tests for cmd_delete_secret in gywadmin_oci.manage_vault.

Covers:
* MAJOR-1: exit code 10 for out-of-range ``--days`` values.
* MAJOR-1: exit code 10 for out-of-range ``--time-of-deletion`` values.
* MAJOR-3: dry-run must not invoke ``prompt_destructive_confirm``.
* Non-dry-run path must invoke ``prompt_destructive_confirm`` at least once.
"""

from __future__ import annotations

import pytest


# ---------------------------------------------------------------------------
# MAJOR-1: --days boundary validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "days, expected_exit",
    [
        (-1, 10),  # below minimum → rejected
        (0, 0),  # sentinel "use OCI minimum" → accepted
        (1, 0),  # minimum explicit value → accepted
        (30, 0),  # maximum explicit value → accepted
        (31, 10),  # one above maximum → rejected
        (365, 10),  # far above maximum → rejected
    ],
)
def test_delete_secret_days_boundary(
    mv, common, mock_oci, make_args, log, days, expected_exit
):
    """``--days`` values outside [1, 30] (or 0) must return exit code 10."""
    args = make_args(days=days, dry_run=True, yes=True)
    rc = mv.cmd_delete_secret(args, log)
    assert rc == expected_exit, f"days={days}: expected exit {expected_exit}, got {rc}"


# ---------------------------------------------------------------------------
# MAJOR-1: --time-of-deletion boundary validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "tod, expected_exit",
    [
        ("2099-01-01T00:00:00Z", 10),  # far future (> 30 days) → rejected
        ("2020-01-01T00:00:00Z", 10),  # past date (< 1 day) → rejected
    ],
)
def test_delete_secret_time_of_deletion_out_of_range(
    mv, common, mock_oci, make_args, log, tod, expected_exit
):
    """``--time-of-deletion`` outside the 1–30 day window must return exit code 10."""
    args = make_args(time_of_deletion=tod, dry_run=True, yes=True)
    rc = mv.cmd_delete_secret(args, log)
    assert rc == expected_exit, (
        f"time_of_deletion={tod!r}: expected exit {expected_exit}, got {rc}"
    )


# ---------------------------------------------------------------------------
# MAJOR-3: dry-run must not call prompt_destructive_confirm
# ---------------------------------------------------------------------------


def test_delete_secret_dry_run_skips_confirm(mv, common, mock_oci, make_args, log):
    """MAJOR-3: dry-run must not call ``prompt_destructive_confirm``."""
    args = make_args(days=7, dry_run=True, yes=False)
    rc = mv.cmd_delete_secret(args, log)
    assert rc == 0
    assert mock_oci["confirm_calls"] == [], (
        f"Expected zero confirm prompts on dry-run, "
        f"got {len(mock_oci['confirm_calls'])}"
    )


# ---------------------------------------------------------------------------
# Non-dry-run path must invoke prompt_destructive_confirm
# ---------------------------------------------------------------------------


def test_delete_secret_real_run_invokes_confirm(
    mv, common, mock_oci, make_args, log, monkeypatch
):
    """Non-dry-run path must invoke ``prompt_destructive_confirm`` at least once.

    We stub ``oci.vault.VaultsClient`` with a version that has a no-op
    ``schedule_secret_deletion`` method, and stub ``common.wait_for_state``
    so the test does not block on polling.
    """
    import oci  # type: ignore[import]

    getattr(oci, "vault")  # trigger lazy load before patching

    class _FakeVaultsClient:
        def __init__(self, *a, **kw) -> None:  # noqa: ANN002,ANN003
            pass

        def list_secrets(self, **kw):  # noqa: ANN001,ANN201
            # Return a minimal response-like object so list_all can iterate it.
            # common.list_all is already stubbed by mock_oci, so this method
            # is never actually called — but we define it for completeness.
            pass  # pragma: no cover

        def schedule_secret_deletion(self, *a, **kw) -> None:  # noqa: ANN002,ANN003
            """No-op: we only care that confirm was called before this."""

    monkeypatch.setattr(oci.vault, "VaultsClient", _FakeVaultsClient, raising=False)

    # Stub wait_for_state so the test does not block after the deletion call.
    monkeypatch.setattr(common, "wait_for_state", lambda *a, **kw: None)

    args = make_args(days=7, dry_run=False, yes=True)
    try:
        mv.cmd_delete_secret(args, log)
    except Exception:
        # Any late-stage mechanics that blow up are not our concern here;
        # we only care that confirm was invoked before the deletion attempt.
        pass

    assert len(mock_oci["confirm_calls"]) >= 1, (
        "Expected prompt_destructive_confirm to be called on a non-dry-run, "
        f"but confirm_calls={mock_oci['confirm_calls']!r}"
    )
