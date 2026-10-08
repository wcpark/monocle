# `monocle`
[![CI Pipeline](https://github.com/wcpark/monocle/actions/workflows/ci.yml/badge.svg)](https://github.com/wcpark/monocle/actions/workflows/ci.yml)  

Monocle is a Python MCP server with Microsoft's [Agent Governance Toolkit (AGT)](https://github.com/microsoft/agent-governance-toolkit) built in. It exposes tools and a skill that agents use to review the vulnerability mitigation statements in a tenant repository's cDSO config (`cdso_config.yml`) and correct the ones that are not true. It covers Grype and ZAP mitigations, semgrep rule exclusions and path ignores, hadolint ignores, and `container_spec` base-image exceptions.

Monocle was created from the [cookiecutter-fastmcp](https://github.com/deathlabs/cookiecutter-fastmcp) template.

## Prerequisites

The instructions below assume you are using VS Code and OpenAI's Codex agent, and that you have the following software installed:

- [Make](https://www.gnu.org/software/make/)
- [Docker](https://docs.docker.com/get-started/get-docker/)
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

From the monocle folder, build and start monocle against the repository you cloned.

```bash
make run WORKSPACE=$HOME/repos/tenant-app
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

By default, the agent triages the whole config. It groups mitigations that make the same claim, checks each claim once, and examines in depth only the groups that look wrong or weak. You can ask for a different review instead.

| To review | Add to the prompt |
|---|---|
| Only what changed on your branch | "Review only the mitigations that changed since main." |
| Everything, in depth (slow on a large config) | "Do a full review." |
| Part of the config | "Only the Grype mitigations for the backend component." |

The agent writes its full report to `mitigation-review.md` in the root of the reviewed repository and replies with a summary. The report gives a verdict for each mitigation, the evidence behind it, and corrected statements in cDSO format that can be pasted back into the config.

| Verdict | Meaning |
|---|---|
| `supported` | Examined in depth, and the evidence backs it. |
| `passed triage` | Quick checks agree with it, but it was not examined in depth. |
| `needs revision` | The conclusion holds, but the statement is wrong or incomplete. |
| `not supported` | The evidence contradicts it, or there is no justification. |
| `unverified` | It could not be checked; the report says what would settle it. |
The report file is not meant to be committed. Build the component's container image first so the agent can check what is installed in it. Otherwise, it writes `check-<group>.sh` scripts for you to run.

### Try It Without a Tenant Repository

Run `make run` in the monocle folder to start monocle against its own sample config. Then open the monocle folder in VS Code and enter this prompt.

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

## Development

`make run` starts monocle without checking it. When you change monocle, use the full pipeline instead. It lints and formats the code, scans it and the container image, then starts monocle and tests it. CI runs the same pipeline.

The pipeline also needs [uv](https://docs.astral.sh/uv/), [Ruff](https://docs.astral.sh/ruff/), [Semgrep](https://semgrep.dev/), [TruffleHog](https://github.com/trufflesecurity/trufflehog), [Hadolint](https://github.com/hadolint/hadolint), [Syft](https://github.com/anchore/syft), [Grype](https://github.com/anchore/grype), and [yq](https://github.com/mikefarah/yq). Install uv yourself, then install the rest to `~/.local/bin` at the versions CI uses. This verifies each download against its published checksum, and runs on Linux x86_64 only.

```bash
make install-tools
```

If `~/.local/bin` is not on your `PATH`, add it. Then run the pipeline against monocle's own sample config.

```bash
make
```

To run the scans and then start monocle against another repository, without the tests, enter the command below.

```bash
make WORKSPACE=$HOME/repos/tenant-app start-container
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
