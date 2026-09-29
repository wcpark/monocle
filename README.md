# `monocle`
[![CI Pipeline](https://github.com/wcpark/monocle/actions/workflows/ci.yml/badge.svg)](https://github.com/wcpark/monocle/actions/workflows/ci.yml)  

Monocle is an MCP server that exposes tools and skills that agents can use to review and validate proposed vulnerability mitigation statements.

It reads the mitigations in a tenant repository's cDSO config (`cdso_config.yml`) and serves the `review-mitigation-statement` skill, which tells an agent how to decide whether each mitigation is true and how to correct the ones that are not. It covers Grype and ZAP mitigations, semgrep exclusions, hadolint ignores, and `container_spec` base-image exceptions.

## Usage

### 1. Clone the repository to review

```sh
git clone <tenant-repo-url> ~/repos/tenant-app
```

### 2. Start monocle against that repository

From this repository:

```sh
MCP_SERVER_WORKSPACE=~/repos/tenant-app docker compose --profile all up -d --build
```

The server listens at `http://localhost:8002/mcp` and mounts the tenant repository read-only. It serves one repository at a time. To switch, run `docker compose --profile all down` and start it again with the new path.

To run the full scan chain before starting the server, use `make WORKSPACE=~/repos/tenant-app start-container` instead. This requires uv, Ruff, TruffleHog, Hadolint, Semgrep, Syft, Grype, and yq.

### 3. Connect an agent

Run the agent from inside the tenant repository, so it can search the code and run checks.

For Codex, add the server to your user-level `~/.codex/config.toml`. The copy in this repository's `.codex/config.toml` applies only when Codex runs inside this repository.

```toml
[mcp_servers.monocle]
url = "http://localhost:8002/mcp"
```

Any other MCP client that supports streamable HTTP can connect to the same URL.

### 4. Ask for a review

```text
Read the monocle review-mitigation-statement skill and follow it. Review the
mitigations in cdso_config.yml.
```

By default, the agent reviews every component in the config and every mitigation type: Grype, ZAP, semgrep, hadolint, and container_spec. To narrow the review, name what you want, for example "only the Grype mitigations for the backend component".

The agent reports a verdict for each mitigation (`supported`, `needs revision`, `not supported`, or `unverified`), the evidence behind it, and corrected statements in cDSO format that can be pasted back into the config. Build the component's container image first so the agent can check what is installed in it. Otherwise, it writes `check-<finding>.sh` scripts for you to run.

To try monocle without a tenant repository, start it against this repository and review `tests/fixtures/cdso_config.yml`.

### 5. Stop monocle

```sh
docker compose --profile all down
```

## Tools

| Tool | Purpose |
|---|---|
| `find_cdso_configs` | Finds cDSO config files in the mounted repository. |
| `list_components` | Lists each component's deployment context, mitigated findings by scanner, and skipped scans. |
| `get_mitigations` | Returns a component's mitigations for one scanner, with any formatting problems. |

## Policies

Every tool call passes through two Agent Governance Toolkit (AGT) layers:

- `src/gateway-policy.yaml` allows only the listed tools and blocks config paths that leave the workspace or do not name a cDSO config. The tools also resolve each path and reject symlinks that leave the workspace.
- `src/policy.yaml` limits each config tool to 600 calls per hour, and contains rules for a future tool that writes corrected statements back to a config.
