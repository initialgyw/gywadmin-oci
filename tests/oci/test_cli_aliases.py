"""Pure argparse tests for gywadmin_oci.manage_vault CLI alias parsing.

These tests exercise the argument-parser only; no OCI mocking is required.
Each test function contains a single logical assertion so failures are
immediately pinpointed.
"""

from __future__ import annotations

import pytest


def test_add_secret_canonical_flags(mv):
    """``--secret-name`` / ``--secret-value`` set the expected attributes."""
    args = mv.parse_args(["add-secret", "--secret-name", "n", "--secret-value", "v"])
    assert args.secret_name == "n"
    assert args.secret_value == "v"


def test_add_secret_long_aliases(mv):
    """``--name`` / ``--value`` are accepted aliases for add-secret."""
    args = mv.parse_args(["add-secret", "--name", "n", "--value", "v"])
    assert args.secret_name == "n"
    assert args.secret_value == "v"


def test_add_secret_short_alias_n(mv):
    """``-n`` is an accepted short alias for ``--secret-name`` on add-secret."""
    args = mv.parse_args(["add-secret", "-n", "n", "--value", "v"])
    assert args.secret_name == "n"


def test_add_secret_mixed_canonical_and_alias(mv):
    """``-n`` (short) + ``--secret-value`` (canonical) are accepted together."""
    args = mv.parse_args(["add-secret", "-n", "n", "--secret-value", "v"])
    assert args.secret_name == "n"
    assert args.secret_value == "v"


def test_add_secret_uses_automation_mek_by_default(mv):
    """New secrets default to the general-purpose automation MEK."""
    args = mv.parse_args(["add-secret", "-n", "n", "--value", "v"])
    assert args.mek_name == "mek_automation"


def test_add_secret_accepts_explicit_mek_name(mv):
    """An exact alternative key display name can be supplied at creation."""
    args = mv.parse_args(
        ["add-secret", "-n", "n", "--value", "v", "--mek-name", "application_mek"]
    )
    assert args.mek_name == "application_mek"


def test_add_secret_trims_mek_name(mv):
    """Surrounding whitespace does not become part of the exact key lookup."""
    args = mv.parse_args(
        ["add-secret", "-n", "n", "--value", "v", "--mek-name", "  application_mek  "]
    )
    assert args.mek_name == "application_mek"


@pytest.mark.parametrize("mek_name", ["", "   "])
def test_add_secret_rejects_empty_mek_name(mv, mek_name):
    """Blank key names fail argument parsing before any OCI request."""
    with pytest.raises(SystemExit) as exc:
        mv.parse_args(["add-secret", "-n", "n", "--value", "v", "--mek-name", mek_name])
    assert exc.value.code == 2


def test_delete_secret_canonical_flag(mv):
    """``--secret-name`` is accepted on delete-secret."""
    args = mv.parse_args(["delete-secret", "--secret-name", "s"])
    assert args.secret_name == "s"


def test_delete_secret_long_alias(mv):
    """``--name`` is an accepted alias for ``--secret-name`` on delete-secret."""
    args = mv.parse_args(["delete-secret", "--name", "s"])
    assert args.secret_name == "s"


def test_delete_secret_short_alias_n(mv):
    """``-n`` is an accepted short alias for ``--secret-name`` on delete-secret."""
    args = mv.parse_args(["delete-secret", "-n", "s"])
    assert args.secret_name == "s"


def test_v_flag_still_means_verbose_not_value(mv):
    """``-v`` increments ``verbose`` (not ``secret_value``) on add-secret."""
    args = mv.parse_args(["add-secret", "-v", "-n", "foo", "--value", "bar"])
    assert args.verbose == 1


def test_vv_flag_increases_verbose(mv):
    """``-vv`` sets ``verbose`` to 2 on add-secret."""
    args = mv.parse_args(["add-secret", "-vv", "-n", "foo", "--value", "bar"])
    assert args.verbose == 2
