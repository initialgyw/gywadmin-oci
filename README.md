# gywadmin-oci

OCI-side automation for `gywadmin-homelab`, packaged as a standalone, installable Python distribution (`gywadmin-oci`) and published as container image for ad-hoc use.

## Table of Contents

- [Installation](#installation)
  - [Install from the main branch (latest)](#install-from-the-main-branch-latest)
  - [Docker](#docker)
- [General Usage & Configuration](#general-usage--configuration)
  - [Verbosity](#verbosity)
  - [Authentication](#authentication)
  - [Commands](#commands)
    - [initialize-oci](#initialize-oci)
      - [Usage](#usage)
      - [Resources provisioned](#resources-provisioned)
    - [manage-vault](#manage-vault)
      - [list-secrets](#list-secrets)
      - [add-secret](#add-secret)
      - [delete-secret](#delete-secret)
  - [update-github-secrets](#update-github-secrets)
    - [Usage](#usage)
- [Development](#development)
- [Exit codes](#exit-codes)

## Installation

### Install from the main branch (latest)

```
pip install "git+https://github.com/initialgyw/gywadmin-oci.git@main"

# Or install a specific version tag (e.g., 0.1.0)
pip install "git+https://github.com/initialgyw/gywadmin-oci.git@0.1.0"
```

### Docker

A pre-built minimal Docker image is available via the GitHub Container Registry. This avoids installing Python or dependencies on your host.

```bash
# Pull a specific version (replace 0.1.1 with the desired version)
docker pull ghcr.io/initialgyw/gywadmin-oci:0.1.1
```

## General Usage & Configuration

### Verbosity

| Flag | Root level | `urllib3` / `oci.circuit_breaker` / `oci.config` |
|---|---|---|
| (none) | WARNING | WARNING |
| `-v` | INFO | WARNING |
| `-vv` | DEBUG | INFO |
| `-vvv` | DEBUG | DEBUG (full HTTP trace) |

### Authentication

Before running the container, you must have a valid OCI configuration and API key on your host machine. If you do not have one, you can generate it using the official OCI CLI Docker image:

```bash
docker run -it --rm \
  -u root \
  -p 8181:8181 \
  -v ${HOME}/.oci:/root/.oci \
  ghcr.io/oracle/oci-cli:latest session authenticate --region <region>
```

If docker engine is on a remote host, you may have to forward local port 8181 to the server:

```bash
ssh -L 8181:localhost:8181 <server>
```

This creates a `~/.oci/config` file and an associated RSA key pair on your host machine.

### Commands

#### initialize-oci

Idempotent provisioner for the OCI Always Free Tier baseline used by `gywadmin-homelab`: compartment + bucket + vault + MEK + IAM service account (with RSA-4096 API key) + group + membership + policy.

##### Usage

Setup the necessary resources and permissions in OCI

```bash

% initialize-oci -v

# generate the file using docker image
% # docker run --rm -v "$HOME/.oci:/root/.oci" -v ${PWD}/output:/output ghcr.io/initialgyw/gywadmin-oci:<version> initialize-oci -v --output-dir /output
```

These files will be generated:

```bash

% ls -l output
total 40
-rw-------@ ... initialize-oci-summary.json
-rw-------@ ... sa_automation_credentials.json
-rw-------@ ... sa_automation_oci_config.ini
-rw-r--r--@ ... sa_automation_public.pem
-rw-------@ ... sa_automation.pem
```

##### Resources provisioned

- **Compartment** (`cpm_automation`) — at the tenancy root.
- **Object Storage bucket** (`bucket_automation`) — versioning enabled, `NoPublicAccess`.
- **KMS Vault** (`vault_automation`) — `DEFAULT` (free) vault type.
- **Master Encryption Key** (`mek_automation`) — AES‑256, software protection. Required for any future secret stored in the vault.
- **IAM user** (`sa_automation`) — service account, with a freshly generated RSA‑4096 API key uploaded.
- **IAM group** (`grp_automation`) — with `sa_automation` added as a member.
- **IAM policy** (`policy_grp_automation`) — at the tenancy root, with:
  - `Allow group <grp> to manage objects in compartment <cpm> where target.bucket.name='<bucket>'`
  - `Allow group <grp> to read secret-bundles in compartment <cpm>`
  - `Allow group <grp> to read vaults in compartment <cpm>`

Every resource is tagged `created_by=initialize-oci.py` (configurable via `--tag-key` / `--tag-value`).

---

#### manage-vault

Multi-subcommand CLI for day-2 OCI Vault secret operations. All subcommands share a common set of flags (vault name, compartment, auth, verbosity, dry-run, polling) and are admin-only by design.

This script does **not** provision the vault. Run `initialize-oci` first (or have a vault and at least one MEK in place by some other means).

##### list-secrets

```bash

% manage-vault list-secrets
Name                       Lifecycle  Tags
-------------------------  ---------  ----
...
```

##### add-secret

```bash

manage-vault add-secret -n test
Secret value:
Confirm secret value:
```

Pass content from start
```bash

echo testpassword | manage-vault add-secret -n test --value -
# echo testpass | docker run --rm -v "$HOME/.oci:/root/.oci" -i ghcr.io/initialgyw/gywadmin-oci:0.2.0 manage-vault add-secret -n test --value -
```

Add multiline content:

```bash

% manage-vault add-secret -n test3 --value - <<'EOF'
This is line one
This is line two
Special characters like $ & % are safe here
EOF

#docker run --rm -i -v "$HOME/.oci:/root/.oci" ghcr.io/initialgyw/gywadmin-oci:0.2.0 manage-vault add-secret -n test3 --value - <<'EOF'
#This is line one
#This is line two
#Special characters like $ & % are safe here
#EOF
```

##### delete-secret

```bash

% manage-vault delete-secret -n pi_root_password --days 7
```

### update-github-secrets

**Note:** You must pass your GitHub token to the container as an environment variable using `-e GH_TOKEN=<your_token>`.

OR auth and pass in the config to the container:

```bash
% docker run -it --rm \
  -v "$HOME/.config/gh:/root/.config/gh" \
  ghcr.io/initialgyw/gywadmin-oci:0.2.0 \
  gh auth login
```

#### Usage

Dry run (no GitHub calls, no confirmation required):

```bash
update-github-secrets \
  --repo myorg/myrepo \
  --dry-run

# docker run --rm \
#   -v "$HOME/.oci:/root/.oci" \
#   -v "$HOME/.config/gh:/root/.config/gh" \
#   -v "${PWD}/output:/output" \
#   ghcr.io/initialgyw/gywadmin-oci:0.2.0 update-github-secrets \
#     --repo initialgyw/gywadmin-homelab \
#     -f /output/initialize-oci-summary.json \
#     -vvv \
#     --yes
```

---

## Development

```bash

pip install -e . -r py-requirements-dev.txt
```

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
