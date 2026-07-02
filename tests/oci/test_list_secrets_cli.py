import argparse
import pytest

def test_list_secrets_no_args(mv):
    """list-secrets accepts no required args."""
    args = mv.parse_args(["list-secrets"])
    assert args.subcommand == "list-secrets"
    assert args.name_prefix is None
    assert args.output_format == "table"
    assert args.verbose == 0
    assert args.dry_run is False

def test_list_secrets_name_prefix(mv):
    """--name-prefix foo sets args.name_prefix == 'foo'."""
    args = mv.parse_args(["list-secrets", "--name-prefix", "foo"])
    assert args.name_prefix == "foo"

def test_list_secrets_output_format(mv):
    """--output-format defaults 'table'; accepts 'json'; rejects others."""
    args = mv.parse_args(["list-secrets", "--output-format", "json"])
    assert args.output_format == "json"

    with pytest.raises(SystemExit):
        mv.parse_args(["list-secrets", "--output-format", "yaml"])

def test_list_secrets_verbose(mv):
    """-v increments verbose."""
    args = mv.parse_args(["list-secrets", "-vv"])
    assert args.verbose == 2

def test_list_secrets_inherited_flags(mv):
    """Inherited --vault-name, --vault-compartment-name, --dry-run all parse."""
    args = mv.parse_args([
        "list-secrets",
        "--vault-name", "my-vault",
        "--vault-compartment-name", "my-comp",
        "--dry-run"
    ])
    assert args.vault_name == "my-vault"
    assert args.vault_compartment_name == "my-comp"
    assert args.dry_run is True

def test_list_secrets_removed_flags_rejected(mv):
    """Removed flags raise argparse error."""
    removed_flags = [
        "--lifecycle-state",
        "--tags-format",
        "--include-system-tags",
        "--no-version-counts"
    ]
    for flag in removed_flags:
        with pytest.raises(SystemExit):
            mv.parse_args(["list-secrets", flag])
