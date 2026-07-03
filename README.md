# gywadmin-oci

OCI-side automation for `gywadmin-homelab`, packaged as a standalone, installable Python distribution (`gywadmin-oci`).

## Package layout

| Component | Purpose |
|---|---|
| [`initialize-oci`](#initialize-oci) (console script → `gywadmin_oci.initialize_oci:main`) | One-shot provisioner for the OCI Always Free Tier baseline (compartment, bucket, vault, MEK, IAM service account, group, policy). |
| [`manage-vault`](#manage-vault) (console script → `gywadmin_oci.manage_vault:main`) | Multi-subcommand CLI for day-2 secret operations: `add-secret`, `delete-secret`, `list-secrets`. |
| [`update-github-secrets`](#update-github-secrets) (console script → `gywadmin_oci.update_github_secrets:main`) | Synchronizes the output from `initialize-oci` into GitHub Actions repository secrets using the `gh` CLI. |
| `gywadmin_oci.common` | Shared helpers (logging, dependency check, OCI config loader, lifecycle-state poller, dry-run sentinels, freeform-tag merge, resource lookups, time helpers, confirmation gate, summary data model). Imported by all entry points; not run directly. |

## Install

### Install from the main branch (latest)

```
pip install "git+https://github.com/initialgyw/gywadmin-oci.git@main"

# Or install a specific version tag (e.g., 0.1.0)
pip install "git+https://github.com/initialgyw/gywadmin-oci.git@0.1.0"
```

For development:

```
pip install -e . -r py-requirements-dev.txt
```

### Docker

A pre-built minimal Docker image is available via the GitHub Container Registry. This avoids installing Python or dependencies on your host.

```bash
# Pull a specific version (replace 0.1.1 with the desired version)
docker pull ghcr.io/initialgyw/gywadmin-oci:0.1.1
```

## General Usage & Configuration

### Authentication

Before running the container, you must have a valid OCI configuration and API key on your host machine. If you do not have one, you can generate it using the official OCI CLI Docker image:

```bash
# Generate a new config and key pair
docker run -it --rm -v ~/.oci:/root/.oci ghcr.io/initialgyw/gywadmin-oci:0.1.1 oci setup config

# Or authenticate via browser session
docker run -it --rm -v ~/.oci:/root/.oci ghcr.io/initialgyw/gywadmin-oci:0.1.1 session authenticate --region <your-region>
```

This typically creates a `~/.oci/config` file and an associated RSA key pair on your host machine.

### Running the container

When running the container, you must mount your OCI configuration directory (and GitHub configuration if using `update-github-secrets`) so the scripts can authenticate:

```bash
# Example: running initialize-oci
docker run -it --rm \
  -v ~/.oci:/root/.oci:ro \
  ghcr.io/initialgyw/gywadmin-oci:0.1.1 \
  initialize-oci --help

# Example: running manage-vault
docker run -it --rm \
  -v ~/.oci:/root/.oci:ro \
  ghcr.io/initialgyw/gywadmin-oci:0.1.1 \
  manage-vault list-secrets
```

The image defaults to a standard Python shell, so you must specify which script to run as the command (`initialize-oci`, `manage-vault`, or `update-github-secrets`).

### Verbosity

| Flag | Root level | `urllib3` / `oci.circuit_breaker` / `oci.config` |
|---|---|---|
| (none) | WARNING | WARNING |
| `-v` | INFO | WARNING |
| `-vv` | DEBUG | INFO |
| `-vvv` | DEBUG | DEBUG (full HTTP trace) |

---

## Tools & Commands

### initialize-oci

Idempotent provisioner for the OCI Always Free Tier baseline used by `gywadmin-homelab`: compartment + bucket + vault + MEK + IAM service account (with RSA-4096 API key) + group + membership + policy.

#### Usage

Show the full flag set:

```
initialize-oci --help
```

Preview what would happen (no API mutations):

```
initialize-oci -v --dry-run
```

Provision for real:

```
initialize-oci -v
```

The script is idempotent — re-running with the same arguments reuses
existing resources rather than creating duplicates.

#### Common flag overrides

| Flag | Default | Purpose |
|---|---|---|
| `--compartment` | `cpm_automation` | Compartment name at tenancy root. |
| `--bucket` | `bucket_automation` | Object Storage bucket inside the compartment. |
| `--vault` | `vault_automation` | KMS Vault display name. |
| `--mek` | `mek_automation` | Master Encryption Key inside the vault. |
| `--service-account` | `sa_automation` | IAM user for automation. |
| `--group` | `grp_automation` | IAM group the SA is added to. |
| `--policy` | `policy_grp_automation` | IAM policy granting the group access. |
| `--output-dir` | `./output` | Where generated key/credentials are written. |
| `--tag-key` / `--tag-value` | `created_by` / `initialize-oci.py` | Freeform tag stamped on every resource. |
| `--region` | (from `~/.oci/config`) | Override the OCI region. |
| `--oci-config-file` / `--oci-profile` | `~/.oci/config` / `DEFAULT` | Auth source. |
| `--wait-seconds` / `--interval-seconds` | `1800` / `30` | Polling ceiling and cadence. |

#### Output artifacts

Written to `--output-dir` (default `./output`, directory mode `0o700`):

| File | Mode | Contents |
|---|---|---|
| `<sa>.pem` | `0o600` | RSA-4096 private key, PKCS#8, encrypted with a random passphrase. |
| `<sa>_public.pem` | `0o644` | Public half of the API key. |
| `<sa>_credentials.json` | `0o600` | `user_ocid`, `tenancy_ocid`, `region`, `fingerprint`, `key_file`, `passphrase`. |
| `<sa>_oci_config.ini` | `0o600` | Drop-in OCI CLI profile section for the SA. |
| `initialize-oci-summary.json` | `0o600` | OCIDs/names of every resource the run created or detected. |

Treat everything in this directory as a secret. Add `output/` to
`.gitignore`.

##### Mount output on docker

```
docker run -it --rm \
  -v ~/.oci:/root/.oci:ro \
  -v <local_path>:/output \
  ghcr.io/initialgyw/gywadmin-oci:0.1.1 \
  initialize-oci --output-dir /output ...
```

#### Resources provisioned

- **Compartment** (`cpm_automation`) — at the tenancy root.
- **Object Storage bucket** (`bucket_automation`) — versioning enabled,
  `NoPublicAccess`.
- **KMS Vault** (`vault_automation`) — `DEFAULT` (free) vault type.
- **Master Encryption Key** (`mek_automation`) — AES‑256, software
  protection. Required for any future secret stored in the vault.
- **IAM user** (`sa_automation`) — service account, with a freshly
  generated RSA‑4096 API key uploaded.
- **IAM group** (`grp_automation`) — with `sa_automation` added as a
  member.
- **IAM policy** (`policy_grp_automation`) — at the tenancy root, with:
  - `Allow group <grp> to manage objects in compartment <cpm> where target.bucket.name='<bucket>'`
  - `Allow group <grp> to read secret-bundles in compartment <cpm>`
  - `Allow group <grp> to read vaults in compartment <cpm>`

Every resource is tagged `created_by=initialize-oci.py` (configurable via
`--tag-key` / `--tag-value`).

#### Idempotency

Every `ensure_*` step looks up the resource by name (and lifecycle state) before creating it. Safe to re-run after a failure or on a different machine — the script will detect existing resources and reuse them. The local output directory is the only place where secret material lives, so guard it accordingly.

If the IAM user already exists but the local `<sa>.pem` /`<sa>_credentials.json` are missing, the script generates a fresh RSA‑4096 key and uploads it to OCI. OCI users can hold up to 3 API keys; if 3 are already present the script exits with code `5` and asks you to remove one first.

#### Troubleshooting

- **`NotAuthorizedOrNotFound` 404 right after a create.** Expected: OCI's IAM control plane is eventually consistent and a freshly-created compartment / user / group can be invisible for a few seconds. The script's `_wait_for_state` poller treats 404 (and 5xx) as transient and retries with a fast 5 s sleep until `--wait-seconds` elapses.
- **`InvalidParameter: The compartmentId must be an ocid` during dry-run.** Should not happen on the current code; if it does, you're running an old copy. The dry-run path uses `ocid1.dryrun.<kind>` placeholders that every downstream `ensure_*` recognises and short-circuits on.
- **Vault is stuck in `CREATING`.** Default vaults can take 5–15 minutes to become `ACTIVE`. The script polls every 30 s up to 30 min and emits a heartbeat log line at least every 2 min. Bump `--wait-seconds` if your tenancy is slower.
- **`oci` CLI binary not on PATH warning.** Cosmetic — the script uses the `oci` Python SDK, not the CLI shell-out. Install the CLI only if you want it for ad-hoc operations.

---

### manage-vault

Multi-subcommand CLI for day-2 OCI Vault secret operations. All subcommands share a common set of flags (vault name, compartment, auth, verbosity, dry-run, polling) and are admin-only by design.

This script does **not** provision the vault. Run `initialize-oci` first (or have a vault and at least one MEK in place by some other means).

#### Universal flags

All subcommands inherit these flags:

| Flag | Default | Purpose |
|---|---|---|
| `--vault-name` | `vault_automation` | Display name of the target KMS Vault. |
| `--vault-compartment-name` | `cpm_automation` | Compartment containing the vault (looked up at tenancy root). |
| `--oci-config-file` / `--oci-profile` | `~/.oci/config` / `DEFAULT` | Auth source. |
| `--region` | (from config) | Override the OCI region. |
| `-v` / `--verbose` | off | Verbosity ladder (see below). |
| `--dry-run` | off | Look up everything; skip mutations. |
| `--wait-seconds` / `--interval-seconds` | `600` / `10` | Polling ceiling and cadence. |

> **Note:** `--yes` is a per-subcommand flag, available only on `delete-secret`
> (the only destructive subcommand that requires confirmation).
> Other subcommands do not accept it. `--dry-run` is accepted by all
> subcommands but is a no-op for `list-secrets` (which is read-only).

The secret value is never written to logs at any verbosity.

#### Operator workflow example

The short aliases `-n` / `--name` (for `--secret-name`) and `--value` (for
`--secret-value`) are accepted by both subcommands; the canonical long
forms work identically.

```bash
# Dry-run: preview what would be created (no mutations).
manage-vault add-secret \
    -n pi_root_password \
    --value 'correct horse battery staple' \
    --dry-run

# Create or update a secret for real.
pass show homelab/pi-root | manage-vault add-secret \
    -n pi_root_password \
    --value -

# Interactive: prompt for the value (hidden input + confirmation).
manage-vault add-secret \
    -n pi_root_password

# Dry-run: preview the scheduled deletion.
manage-vault delete-secret \
    -n pi_root_password \
    --days 7 \
    --dry-run

# Schedule deletion for real (non-interactive with --yes).
manage-vault delete-secret \
    -n pi_root_password \
    --days 7 \
    --yes
```

#### add-secret

Create or update a secret in an OCI Vault. If the secret does not exist it is created; if it already exists, a new version is pushed (always create-or-update). The master encryption key is auto-discovered: the vault must contain exactly one `ENABLED` key.

##### Usage

```
manage-vault add-secret \
    --secret-name pi_root_password \
    --secret-value 'correct horse battery staple'

# Pipe via stdin (recommended for sensitive values).
pass show homelab/pi-root | manage-vault add-secret \
    --secret-name pi_root_password \
    --secret-value -

# Omit --secret-value to be prompted interactively (hidden + confirmed).
manage-vault add-secret \
    --secret-name pi_root_password
```

##### Flags

| Flag | Default | Purpose |
|---|---|---|
| `--secret-name` / `--name` / `-n` | (required) | Display name of the secret. |
| `--secret-value` / `--value` | _(prompt)_ | Literal value, `-` to read from stdin until EOF, or omit to be prompted interactively (hidden input + confirmation). Non-TTY stdin without this flag is rejected (exit 9). |

##### IAM policy

```
Allow group <grp> to manage secret-family in compartment <cpm>
```

#### delete-secret

Schedule a vault secret for deletion. The secret enters `PENDING_DELETION` state and is permanently deleted after the retention window (1–30 days).
Idempotent: already-deleting secrets exit 0.

##### Usage

```
manage-vault delete-secret \
    --secret-name pi_root_password \
    --days 7

# Explicit timestamp.
manage-vault delete-secret \
    --secret-name pi_root_password \
    --time-of-deletion 2026-06-15T00:00:00Z

# Dry-run (shows computed time_of_deletion, no mutations).
manage-vault delete-secret \
    --secret-name pi_root_password \
    --dry-run
```

##### Flags

| Flag | Default | Purpose |
|---|---|---|
| `--secret-name` / `--name` / `-n` | (required) | Display name of the secret to delete. |
| `--days` | `0` (OCI minimum = 1 day) | Days from now until deletion (1–30). |
| `--time-of-deletion` | — | Explicit RFC 3339 timestamp. Overrides `--days`. |

##### IAM policy

```
Allow group <grp> to manage secret-family in compartment <cpm>
```

#### list-secrets

List the secrets in an OCI Vault as a four-column table (Name, Versions,
Lifecycle, Tags). `Versions` is rendered as `current/total`. `Lifecycle`
is blank for `ACTIVE` secrets and shows the state otherwise. `Tags` shows
freeform tags only as `key=value` pairs.

##### Usage

```
manage-vault list-secrets

manage-vault list-secrets --output-format json | jq
```

##### Flags

| Flag | Default | Purpose |
|---|---|---|
| `--name-prefix` | — | Optional secret-name prefix filter (server-side, prefix match). |
| `--output-format` | `table` | Output format: `table` or `json`. |

> **Note:** Tags column shows freeform tags only; use `--output-format json` for `defined_tags` and `system_tags`.

##### IAM policy

```
Allow group <grp> to read secret-family in compartment <cpm>
```

---

### update-github-secrets

Pushes the seven GitHub Actions secrets produced by `initialize-oci` into a GitHub repository using the `gh` CLI.

#### Secrets set

| Secret name | Source in summary JSON |
|---|---|
| `AWS_ACCESS_KEY_ID` | `service_account.customer_secret_key.access_key` |
| `AWS_SECRET_ACCESS_KEY` | `service_account.customer_secret_key.secret_key` |
| `OCI_CLI_TENANCY` | `tenancy_ocid` |
| `OCI_CLI_USER` | `service_account.ocid` |
| `OCI_CLI_FINGERPRINT` | `service_account.api_key.fingerprint` |
| `OCI_CLI_KEY_CONTENT` | `service_account.api_key.private_pem` |
| `TF_VAR_private_key_password` | `service_account.api_key.passphrase` |

#### Flags

| Flag | Default | Required | Purpose |
|---|---|---|---|
| `--repo` / `-R` | — | **Yes** | Target GitHub repository in `OWNER/REPO` format. |
| `--summary-file` / `-f` | `script_outputs/initialize-oci-summary.json` | No | Path to the `initialize-oci-summary.json` file. |
| `--dry-run` | `false` | No | Log the plan without contacting GitHub (skips preflight and confirmation). |
| `--yes` / `-y` | `false` | No | Skip the interactive confirmation prompt. |
| `--fail-fast` | `false` | No | Abort on the first failed secret instead of best-effort (default: continue and report all failures). |
| `--verbose` / `-v` | `0` | No | Increase log verbosity. Repeat for more detail: `-v`=INFO, `-vv`=DEBUG, `-vvv`=TRACE. |

#### Usage

Dry run (no GitHub calls, no confirmation required):

```bash
update-github-secrets \
  --repo myorg/myrepo \
  --dry-run
```

Real run with a custom summary path and non-interactive confirmation:

```bash
update-github-secrets \
  --repo myorg/myrepo \
  --summary-file path/to/initialize-oci-summary.json \
  --yes
```

Abort on the first failure instead of best-effort:

```bash
update-github-secrets \
  --repo myorg/myrepo \
  --fail-fast \
  --yes
```

---

## Exit codes

| Code | Meaning | Entry points |
|---|---|---|
| `0` | Success (or clean dry-run, or idempotent no-op). | All |
| `1` | Generic OCI / polling failure; or one or more secrets failed to set. | All |
| `2` | Required Python deps missing (`initialize-oci`, `manage-vault`); `gh` CLI not found (`update-github-secrets`). | All |
| `3` | OCI config file missing or invalid (`initialize-oci`, `manage-vault`); summary file missing/unreadable/invalid (`update-github-secrets`). | All |
| `4` | OCI authentication preflight failed (`initialize-oci`, `manage-vault`); `gh` auth or repo preflight failed (`update-github-secrets`). | All |
| `5` | IAM user already has the OCI maximum (3) API keys (`initialize-oci`); compartment, vault, or secret not found (`manage-vault`). | `initialize-oci`, `manage-vault` |
| `6` | Vault has zero or multiple `ENABLED` master encryption keys (auto-pick failed). | `add-secret` |
| `7` | Permission denied on secret create/update. | `add-secret` |
| `8` | Secret name held by a `*_DELETION`-state resource. | `add-secret` |
| `9` | Bad value-source argument: empty stdin with `--secret-value -`, non-TTY stdin without `--secret-value`, interactive entry aborted, mismatched confirmations after 3 attempts, or empty interactive value. | `add-secret` |
| `10` | Bad `--time-of-deletion` or `--days` argument. | `delete-secret` |
| `11` | Destructive operation refused (non-TTY without `--yes`, or user declined). | `delete-secret`, `update-github-secrets` |
