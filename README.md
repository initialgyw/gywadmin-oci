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
    - [manage-unseal](#manage-unseal)
      - [Resource naming convention](#resource-naming-convention)
      - [create](#create)
      - [rotate](#rotate)
      - [show](#show)
    - [update-github-secrets](#update-github-secrets)
      - [Usage](#usage-1)
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
  - `Allow group <grp> to manage secret-family in compartment <cpm>`
  - `Allow group <grp> to read vaults in compartment <cpm>`

Every resource is tagged `created_by=initialize-oci.py` (configurable via `--tag-key` / `--tag-value`).

---

#### manage-vault

Multi-subcommand CLI for day-2 OCI Vault secret operations. All subcommands share a common set of flags (vault name, compartment, auth, verbosity, dry-run, polling) and are admin-only by design.

This script does **not** provision the vault. Run `initialize-oci` first (or have a vault and at least one MEK in place by some other means).

##### Authentication (`--summary-file`)

By default every subcommand authenticates using `--oci-config-file` (default `~/.oci/config`). Alternatively, pass `--summary-file` / `-f` pointing at the `initialize-oci-summary.json` produced by `initialize-oci` to authenticate as the service account (`sa_automation`) using the API key embedded in that summary — no `~/.oci/config` required. The private key is read in-memory, so no key file has to exist on disk.

```bash

% manage-vault list-secrets -f output/initialize-oci-summary.json

# via docker, mounting the output dir instead of ~/.oci
# docker run --rm -v "${PWD}/output:/output" ghcr.io/initialgyw/gywadmin-oci:<version> \
#   manage-vault list-secrets -f /output/initialize-oci-summary.json
```

When `--summary-file` is omitted, `manage-vault` falls back to `--oci-config-file`. When it **is** provided but is missing, unreadable, or lacks the required service-account fields, the command hard-fails (exit code 3) rather than silently falling back.

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

#### manage-unseal

Manages the per-cluster OCI resources that allow an OpenBao instance to auto-unseal using OCI KMS. **Authentication is always via the admin OCI config** (`--oci-config-file`); the optional `--summary-file` / `-f` flag is only used for shared-resource discovery (compartment name/OCID and vault OCID/endpoint) and never for authentication.

All subcommands require `--cluster-name`.

##### Resource naming convention

The raw `--cluster-name` is normalised deterministically (whitespace trimmed → lowercase → `-` replaced by `_` → consecutive `_` collapsed → leading/trailing `_` stripped) before use. Multiple inputs normalising to the same ID target the same OCI resources.

For `--cluster-name k8s-01` (normalises to `k8s_01`):

| Resource type | Derived name |
|---|---|
| KMS key | `k8s_01_openbao_unseal` |
| IAM user | `sa_k8s_01_openbao_unseal` |
| IAM group | `grp_k8s_01_openbao_unseal` |
| IAM policy | `policy_k8s_01_openbao_unseal` |
| Vault credential secret (JSON) | `k8s_01_openbao_unseal_credential` |

The credential secret is one UTF-8 JSON object with `private_key`,
`fingerprint`, and `user_ocid` fields. OCI Vault stores the JSON as ordinary
secret content; the private key is never printed or logged by this command.

The IAM policy contains **exactly one** statement, scoped to the per-cluster KMS key only:

```
Allow group grp_<id>_openbao_unseal to use keys in compartment <compartment>
  where target.key.id = '<key_ocid>'
```

##### create

Provisions all per-cluster resources and credentials. Idempotent: if the JSON
credential secret is ACTIVE, the stored private key derives the stored
fingerprint, that fingerprint matches a live API key, and the stored user OCID
matches the derived user, the command exits 0 with no mutations.

```bash
manage-unseal create --cluster-name k8s-01

# Docker run:
docker run --rm \
  -v "$HOME/.oci:/root/.oci" \
  ghcr.io/initialgyw/gywadmin-oci:0.3.0 \
  manage-unseal create --cluster-name k8s-01

# With an existing summary for faster OCID discovery (no compartment/vault lookup):
manage-unseal create --cluster-name k8s-01 -f output/initialize-oci-summary.json

# Docker run with summary file:
docker run --rm \
  -v "$HOME/.oci:/root/.oci" \
  -v "${PWD}/output:/output" \
  ghcr.io/initialgyw/gywadmin-oci:0.3.0 \
  manage-unseal create --cluster-name k8s-01 -f /output/initialize-oci-summary.json

# Dry run (no mutations):
manage-unseal create --cluster-name k8s-01 --dry-run -v
```

If the unseal user already has 3 API keys (OCI maximum), the command exits with code 5. Pass `--delete-old-api-key` to delete the oldest non-active spare key and make room. The currently registered fingerprint is never deleted automatically.

If the former three-secret contract (`*_private_key`, `*_fingerprint`, and
`*_user_ocid`) exists and is valid, `create` consolidates it into the JSON
credential without generating a new API key. The legacy secrets are retained
for a safe consumer rollout; delete them only after OpenBao has been updated to
read the JSON credential and has restarted successfully.

##### rotate

Always generates fresh RSA-4096 key material and pushes a new version of the
single JSON credential secret. IAM infrastructure is verified first (same as
`create`).

```bash
manage-unseal rotate --cluster-name k8s-01

# Docker run:
docker run --rm \
  -v "$HOME/.oci:/root/.oci" \
  ghcr.io/initialgyw/gywadmin-oci:0.3.0 \
  manage-unseal rotate --cluster-name k8s-01

# Make room at the 3-key cap by removing the oldest non-active spare:
manage-unseal rotate --cluster-name k8s-01 --delete-old-api-key
```

> **Key-rotation lifecycle note:** The credential JSON is updated as one Vault
> secret version. After a successful `rotate`, the **previous API key is
> retained** in OCI IAM — it is intentionally not deleted automatically because
> consumers (e.g. OpenBao instances) may still hold active sessions using it.
> The recommended workflow is:
>
> 1. Run `manage-unseal rotate`.
> 2. Roll out the new secret generation to all consumers and confirm they are using the new credential.
> 3. Once all consumers have rolled over, manually remove the old API key via `oci iam user api-key delete` or the OCI Console.
>
> Use `manage-unseal show | jq .provisioning_complete` to confirm all conditions (valid private key, matching fingerprint, live API key, active resources) before and after a rotation.

##### show

Read-only JSON status report. Contains derived names, discovered OCIDs/lifecycle
states, the registered fingerprint (never the private key), JSON-shape and
private-key/fingerprint validation booleans, membership state, and an overall
`provisioning_complete` flag.

`provisioning_complete` is `true` only when: the unseal KMS key is ENABLED with
the expected AES-256 SOFTWARE shape, the IAM user, group, membership, and
policy are ACTIVE, the policy is exactly correctly scoped (using the
authoritative compartment name from `--summary-file` or `--compartment`), the
credential secret is ACTIVE with valid JSON, the stored user OCID matches, the
stored fingerprint is a live API key, and the private key derives the same
fingerprint.

```bash
manage-unseal show --cluster-name k8s-01

# Docker run:
docker run --rm \
  -v "$HOME/.oci:/root/.oci" \
  ghcr.io/initialgyw/gywadmin-oci:0.3.0 \
  manage-unseal show --cluster-name k8s-01

manage-unseal show --cluster-name k8s-01 | jq .provisioning_complete
```

---

#### update-github-secrets

**Note:** You must pass your GitHub token to the container as an environment variable using `-e GH_TOKEN=<your_token>`.

OR auth and pass in the config to the container:

```bash
% docker run -it --rm \
  -v "$HOME/.config/gh:/root/.config/gh" \
  ghcr.io/initialgyw/gywadmin-oci:0.2.0 \
  gh auth login
```

##### Usage

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
| `2` | Required Python deps missing (`initialize-oci`, `manage-vault`, `manage-unseal`); `gh` CLI not found (`update-github-secrets`). | All |
| `3` | OCI config file missing or invalid (`initialize-oci`, `manage-vault`, `manage-unseal`); summary file missing/unreadable/invalid (`manage-vault` with `--summary-file`, `manage-unseal` with `--summary-file`, `update-github-secrets`). | All |
| `4` | OCI authentication preflight failed (`initialize-oci`, `manage-vault`, `manage-unseal`); `gh` auth or repo preflight failed (`update-github-secrets`). | All |
| `5` | IAM user already has the OCI maximum (3) API keys (`initialize-oci`, `manage-unseal`); compartment, vault, or secret not found (`manage-vault`, `manage-unseal`). | `initialize-oci`, `manage-vault`, `manage-unseal` |
| `6` | Vault has zero or multiple `ENABLED` master encryption keys (auto-pick failed) (`add-secret`); invalid `--cluster-name` after normalisation (`manage-unseal`). | `add-secret`, `manage-unseal` |
| `7` | Permission denied on secret create/update. | `add-secret` |
| `8` | Secret name held by a `*_DELETION`-state resource. | `add-secret` |
| `9` | Bad value-source argument: empty stdin with `--secret-value -`, non-TTY stdin without `--secret-value`, interactive entry aborted, mismatched confirmations after 3 attempts, or empty interactive value. | `add-secret` |
| `10` | Bad `--time-of-deletion` or `--days` argument. | `delete-secret` |
| `11` | Destructive operation refused (non-TTY without `--yes`, or user declined). | `delete-secret`, `update-github-secrets` |
