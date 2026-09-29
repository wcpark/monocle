# `monocle`
[![CI Pipeline](https://github.com/wcpark/monocle/actions/workflows/ci.yml/badge.svg)](https://github.com/wcpark/monocle/actions/workflows/ci.yml)  

Monocle is a Python MCP server with Microsoft's [Agent Governance Toolkit (AGT)](https://github.com/microsoft/agent-governance-toolkit) built in. It exposes tools and a skill that agents use to review the vulnerability mitigation statements in a tenant repository's cDSO config (`cdso_config.yml`) and correct the ones that are not true. It covers Grype and ZAP mitigations, semgrep exclusions, hadolint ignores, and `container_spec` base-image exceptions.

Monocle was created from the [cookiecutter-fastmcp](https://github.com/deathlabs/cookiecutter-fastmcp) template.

## Prerequisites

The instructions below assume you are using VS Code and OpenAI's Codex agent, and that you have the following software installed:

- [Make](https://www.gnu.org/software/make/)
- [Docker](https://docs.docker.com/get-started/get-docker/)
- [uv](https://docs.astral.sh/uv/)
- [Ruff](https://docs.astral.sh/ruff/)
- [Semgrep](https://semgrep.dev/)
- [TruffleHog](https://github.com/trufflesecurity/trufflehog)
- [Hadolint](https://github.com/hadolint/hadolint)
- [Syft](https://github.com/anchore/syft#installation)
- [Grype](https://github.com/anchore/grype#installation)
- [yq](https://github.com/mikefarah/yq)
- [VS Code](https://code.visualstudio.com/)
- [VS Code Extension for Codex](https://marketplace.visualstudio.com/items?itemName=openai.chatgpt)

## Quickstart

### 1. Clone monocle

```bash
git clone https://github.com/wcpark/monocle.git
cd monocle
```

### 2. Clone the repository to review

```bash
git clone <tenant-repo-url> ~/repos/tenant-app
```

### 3. Start monocle against that repository

From the monocle folder, build, scan, and start monocle against the repository you cloned.

```bash
make WORKSPACE=$HOME/repos/tenant-app start-container
```

To review a different repository later, run this again with its path.

### 4. Watch the logs (optional)

Watch the MCP server's logs to see each tool call and any policy denials.

```bash
docker logs monocle_mcp -f
```

### 5. Install the agent

From the monocle folder, copy the `mitigation-reviewer` agent to your personal Codex agents folder, so you can use it from any repository. You only need to do this once.

```bash
mkdir -p ~/.codex/agents
cp .codex/agents/mitigation-reviewer.toml ~/.codex/agents/
```

### 6. Open the repository in VS Code

```bash
code ~/repos/tenant-app
```

### 7. Ask for a review

Enter this prompt into the Codex extension.

> Have @mitigation-reviewer review the mitigations in cdso_config.yml.

By default, the agent reviews every component in the config and every mitigation type. To narrow the review, name what you want, for example "only the Grype mitigations for the backend component".

The agent reports a verdict for each mitigation (`supported`, `needs revision`, `not supported`, or `unverified`), the evidence behind it, and corrected statements in cDSO format that can be pasted back into the config. Build the component's container image first so the agent can check what is installed in it. Otherwise, it writes `check-<finding>.sh` scripts for you to run.

### Try It Without a Tenant Repository

Run `make` in the monocle folder to build, scan, start, and test monocle against its own sample config. Then open the monocle folder in VS Code and enter this prompt.

> Have @mitigation-reviewer review the mitigations in tests/fixtures/cdso_config.yml.

## Cleaning Up

To stop the MCP server and remove its container and network, enter the command below. This keeps the container image, so monocle starts faster next time. Add `--rmi all` to delete the image too.

```bash
docker compose --profile all down
```

Alternatively, to stop the MCP server and delete its container image with the Makefile, enter the commands below.

```bash
make stop-container
make remove-container
make remove-container-image
```

## Tools

| Tool | Purpose |
|---|---|
| `find_cdso_configs` | Finds cDSO config files in the mounted repository. |
| `list_components` | Lists each component's deployment context, mitigated findings by scanner, and skipped scans. |
| `get_mitigations` | Returns a component's mitigations for one scanner, with any formatting problems. |

## Guardrails

Enforced by monocle:

- **Read-only access.** The tools cannot write, run commands, or reach the network. The container runs as a non-root user and mounts only the reviewed repository, read-only.
- **Path checks.** The tools resolve each path and reject files outside the repository, files that are not cDSO configs, and symlinks that leave the repository. Configs are parsed with `yaml.safe_load`.
- **`src/gateway-policy.yaml`** (Agent Governance Toolkit MCP gateway) allows only the listed tools and blocks `..`, absolute, and non-config paths in tool arguments.
- **`src/policy.yaml`** (Agent Governance Toolkit) limits each config tool to 600 calls per hour. It also denies removals and requires human approval for a future tool that writes corrected statements back to a config.

Not enforced:

- **The agent's own actions.** Commands the agent runs in its shell are governed by the agent's sandbox and approval settings, not by monocle.
- **Audit history.** Tool calls are audited in memory only, and the record is lost when the container restarts.
