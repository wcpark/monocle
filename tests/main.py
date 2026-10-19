"""Integration tests for a running Monocle MCP server."""

# Standard library imports.
from asyncio import run, sleep
from os import getenv
from pathlib import Path

# Third party imports.
from fastmcp import Client
from fastmcp.utilities.skills import list_skills

# Constants.
SERVER = "Monocle MCP Server"
URL = getenv("MCP_URL", "http://localhost:8002/mcp")
HEALTH_ATTEMPTS = 30
HEALTH_RETRY_DELAY = 1
FIXTURE_CONFIG = "tests/fixtures/cdso_config.yml"
FIXTURE_COMPONENT = "sample_service"
FIXTURE_DIRECTORY = Path(__file__).parent / "fixtures"
LINKED_CONFIG = "tests/fixtures/linked_cdso_config.yml"
GATEWAY_BLOCKED_PATHS = (
    "../etc/cdso_config.yml",
    "/etc/cdso_config.yml",
    "src/pyproject.toml",
)
GREEN = "\033[32m"
RESET = "\033[0m"


async def main() -> None:
    """Run the integration tests against the Monocle MCP server.

    Raises:
        RuntimeError: If the server does not become available.
        AssertionError: If a test fails.
    """
    # Wait for the MCP server to become available.
    for attempt in range(1, HEALTH_ATTEMPTS + 1):
        try:
            async with Client(URL) as client:
                await list_skills(client)
            break
        except Exception as error:
            if attempt == HEALTH_ATTEMPTS:
                raise RuntimeError(f"The {SERVER} is not up.") from error
            await sleep(HEALTH_RETRY_DELAY)

    async with Client(URL) as client:
        # Test 1: the server must expose at least one skill.
        skill_list = await list_skills(client)
        skill_exposure_error = f"The {SERVER} is not exposing any skills."
        assert len(skill_list) > 0, skill_exposure_error
        skills = ", ".join([skill.name for skill in skill_list])
        print(f" {GREEN}✔{RESET} The {SERVER} is exposing: {skills}")

        for skill in skill_list:
            mcp_resource = f"skill://{skill.name}/SKILL.md"
            mcp_resource_contents = await client.read_resource(mcp_resource)

            # Test 2: the skill must be readable.
            skill_read_error = f"The '{skill.name}' skill cannot be read."
            assert mcp_resource_contents, skill_read_error
            print(f" {GREEN}✔{RESET} The {skill.name} skill can be read")

            # Test 3: the skill cannot be empty.
            empty_skill_error = f"The {skill.name} skill is empty."
            assert mcp_resource_contents[0].text, empty_skill_error
            print(f" {GREEN}✔{RESET} The {skill.name} skill is not empty")

        # Test 4: the server must find the fixture cDSO config.
        result = await client.call_tool("find_cdso_configs")
        config_error = f"The {SERVER} did not find {FIXTURE_CONFIG}."
        assert FIXTURE_CONFIG in result.data, config_error
        print(f" {GREEN}✔{RESET} The {SERVER} found {FIXTURE_CONFIG}")

        # Test 5: the server must list the fixture's component and findings.
        result = await client.call_tool(
            "list_components",
            {"config_path": FIXTURE_CONFIG},
        )
        component = result.data["components"][0]
        component_error = f"The {SERVER} listed the wrong component: {component}"
        assert component["name"] == FIXTURE_COMPONENT, component_error
        finding_counts = {
            scanner: len(finding_ids)
            for scanner, finding_ids in component["findings"].items()
        }
        expected_counts = {
            "grype": 4,
            "zap": 1,
            "semgrep": 2,
            "semgrep_ignore": 2,
            "hadolint": 1,
            "container_spec": 2,
        }
        assert finding_counts == expected_counts, component_error
        print(f" {GREEN}✔{RESET} The {SERVER} listed {FIXTURE_COMPONENT}")

        # Test 6: the server must split statements and flag malformed ones.
        result = await client.call_tool(
            "get_mitigations",
            {"config_path": FIXTURE_CONFIG, "component": FIXTURE_COMPONENT},
        )
        mitigations = {entry["finding_id"]: entry for entry in result.data}
        parse_error = f"The {SERVER} parsed mitigations wrongly: {mitigations}"
        assert mitigations["CVE-0000-0001"]["format_issues"] == [], parse_error
        assert mitigations["CVE-0000-0002"]["mitigation"].startswith("The"), parse_error
        assert mitigations["CVE-0000-0002"]["format_issues"], parse_error
        assert mitigations["CVE-0000-0003"]["format_issues"], parse_error
        mixed_case = mitigations["CVE-0000-0004"]
        assert mixed_case["format_issues"] == [], parse_error
        assert mixed_case["description"].endswith("mitigation available."), parse_error
        assert mixed_case["mitigation"] == "The vulnerable parser is not installed.", (
            parse_error
        )
        print(f" {GREEN}✔{RESET} The {SERVER} parsed and checked mitigations")

        # Test 7: the gateway policy must refuse paths that leave the workspace
        # or do not name a cDSO config.
        for config_path in GATEWAY_BLOCKED_PATHS:
            for tool in ("list_components", "sample_mitigations"):
                result = await client.call_tool(
                    tool,
                    {"config_path": config_path},
                    raise_on_error=False,
                )
                gateway_error = (
                    f"The {SERVER} gateway allowed {config_path!r} in {tool}."
                )
                assert result.is_error, gateway_error
                assert "gateway policy" in result.content[0].text, gateway_error
        print(f" {GREEN}✔{RESET} The {SERVER} gateway refused unsafe config paths")

        # Test 8: the tools must refuse a symlink that leaves the workspace,
        # which the gateway's text patterns cannot detect.
        linked_config = FIXTURE_DIRECTORY / "linked_cdso_config.yml"
        linked_config.symlink_to("/etc/hostname")
        try:
            result = await client.call_tool(
                "list_components",
                {"config_path": LINKED_CONFIG},
                raise_on_error=False,
            )
        finally:
            linked_config.unlink()
        symlink_error = f"The {SERVER} followed a symlink outside the workspace."
        assert result.is_error, symlink_error
        assert "outside the workspace" in result.content[0].text, symlink_error
        print(f" {GREEN}✔{RESET} The {SERVER} refused a symlink outside the workspace")

        # Test 9: the server must strip stray quotes from ZAP statements.
        result = await client.call_tool(
            "get_mitigations",
            {
                "config_path": FIXTURE_CONFIG,
                "component": FIXTURE_COMPONENT,
                "scanner": "zap",
            },
        )
        zap_mitigation = result.data[0]
        zap_error = f"The {SERVER} parsed a ZAP statement wrongly: {zap_mitigation}"
        assert zap_mitigation["mitigation"].endswith("gateway."), zap_error
        assert zap_mitigation["format_issues"], zap_error
        print(f" {GREEN}✔{RESET} The {SERVER} parsed ZAP mitigations")

        # Test 10: the server must read justifications from semgrep comments.
        result = await client.call_tool(
            "get_mitigations",
            {
                "config_path": FIXTURE_CONFIG,
                "component": FIXTURE_COMPONENT,
                "scanner": "semgrep",
            },
        )
        exclusions = {entry["finding_id"]: entry for entry in result.data}
        semgrep_error = f"The {SERVER} parsed semgrep exclusions wrongly: {exclusions}"
        shared_rule = (
            "app.rules.community.yaml.docker-compose.security.no-new-privileges"
        )
        file_rule = (
            "app.rules.community.python.lang.maintainability."
            "is-function-without-parentheses"
        )
        shared_justification = exclusions[shared_rule]["justifications"][0]
        file_justification = exclusions[file_rule]["justifications"][0]
        assert shared_justification["mitigation"].startswith("Compose"), semgrep_error
        assert file_justification["files"] == ["services/sample/tools/gen.py:12"], (
            semgrep_error
        )
        assert file_justification["mitigation"].startswith("The command"), semgrep_error
        assert file_justification["commented_rules"], semgrep_error
        print(f" {GREEN}✔{RESET} The {SERVER} parsed semgrep exclusions")

        # Test 11: the server must read hadolint and base-image justifications.
        for scanner, finding_id, prefix in (
            ("semgrep_ignore", "services/sample/migrations/**", "Generated"),
            ("hadolint", "DL3008", "Pinned"),
            ("container_spec", "registry.example/sample/builder:v1.0.0", "The builder"),
            ("container_spec", "non_minimized", "The service"),
        ):
            result = await client.call_tool(
                "get_mitigations",
                {
                    "config_path": FIXTURE_CONFIG,
                    "component": FIXTURE_COMPONENT,
                    "scanner": scanner,
                    "finding_ids": [finding_id],
                },
            )
            justification = result.data[0]["justifications"][0]["mitigation"]
            comment_error = f"The {SERVER} misread {finding_id}: {justification!r}"
            assert justification.startswith(prefix), comment_error
        print(
            f" {GREEN}✔{RESET} The {SERVER} parsed hadolint and base-image exceptions"
        )

        # Test 12: the server must refuse to return too many findings at once.
        result = await client.call_tool(
            "get_mitigations",
            {
                "config_path": FIXTURE_CONFIG,
                "component": FIXTURE_COMPONENT,
                "finding_ids": [f"CVE-0000-{number:04}" for number in range(51)],
            },
            raise_on_error=False,
        )
        batch_error = f"The {SERVER} returned more than 50 findings in one call."
        assert result.is_error, batch_error
        assert "batches of at most 50" in result.content[0].text, batch_error
        print(f" {GREEN}✔{RESET} The {SERVER} refused an oversized batch")

        # Test 13: a seeded sample must be reproducible and match
        # get_mitigations.
        sample_arguments = {
            "config_path": FIXTURE_CONFIG,
            "sample_size": 3,
            "seed": "audit-seed-1",
            "scanner": "grype",
        }
        result = await client.call_tool("sample_mitigations", sample_arguments)
        sample = result.data
        repeat = await client.call_tool("sample_mitigations", sample_arguments)
        sample_error = f"The {SERVER} sampled mitigations wrongly: {sample}"
        assert sample["seed"] == "audit-seed-1", sample_error
        assert sample["pool_size"] == 5, sample_error
        assert len(sample["entries"]) == 3, sample_error
        assert sample["entries"] == repeat.data["entries"], sample_error
        entry = sample["entries"][0]
        detailed = await client.call_tool(
            "get_mitigations",
            {
                "config_path": FIXTURE_CONFIG,
                "component": entry["component"],
                "scanner": "grype",
                "finding_ids": [entry["finding_id"]],
            },
        )
        assert entry["mitigation"] == detailed.data[0]["mitigation"], sample_error
        assert entry["format_issues"] == detailed.data[0]["format_issues"], sample_error
        print(f" {GREEN}✔{RESET} The {SERVER} drew a reproducible sample")

        # Test 14: a sample drawn without a seed must return a seed that
        # redraws it.
        result = await client.call_tool(
            "sample_mitigations",
            {"config_path": FIXTURE_CONFIG, "sample_size": 5},
        )
        sample = result.data
        seed_error = f"The {SERVER} did not return a usable seed: {sample}"
        assert isinstance(sample["seed"], str) and sample["seed"], seed_error
        assert sample["pool_size"] == 13, seed_error
        assert len(sample["entries"]) == 5, seed_error
        result = await client.call_tool(
            "sample_mitigations",
            {"config_path": FIXTURE_CONFIG, "sample_size": 5, "seed": sample["seed"]},
        )
        assert sample["entries"] == result.data["entries"], seed_error
        print(f" {GREEN}✔{RESET} The {SERVER} returned a seed that redraws the sample")

        # Test 15: the sampler must honor filters and reject unknown names.
        result = await client.call_tool(
            "sample_mitigations",
            {
                "config_path": FIXTURE_CONFIG,
                "sample_size": 2,
                "seed": "audit-seed-2",
                "component": FIXTURE_COMPONENT,
            },
        )
        filter_error = f"The {SERVER} filtered the sample pool wrongly."
        assert result.data["pool_size"] == 12, filter_error
        assert {entry["component"] for entry in result.data["entries"]} == {
            FIXTURE_COMPONENT
        }, filter_error
        result = await client.call_tool(
            "sample_mitigations",
            {
                "config_path": FIXTURE_CONFIG,
                "sample_size": 5,
                "seed": "audit-seed-2",
                "component": "sample_proxy",
            },
        )
        assert result.data["pool_size"] == 1, filter_error
        assert result.data["entries"][0]["finding_id"] == "CVE-0000-0005", filter_error
        result = await client.call_tool(
            "sample_mitigations",
            {"config_path": FIXTURE_CONFIG, "scanner": "nmap"},
            raise_on_error=False,
        )
        assert result.is_error, filter_error
        assert "is not one of" in result.content[0].text, filter_error
        result = await client.call_tool(
            "sample_mitigations",
            {"config_path": FIXTURE_CONFIG, "component": "missing_service"},
            raise_on_error=False,
        )
        assert result.is_error, filter_error
        assert "does not exist in the config" in result.content[0].text, filter_error
        print(f" {GREEN}✔{RESET} The {SERVER} honored filters and rejected bad names")

        # Test 16: the sampler must refuse sizes outside 1 to 50 and draw the
        # whole pool when it is smaller than the size.
        result = await client.call_tool(
            "sample_mitigations",
            {"config_path": FIXTURE_CONFIG, "sample_size": 51},
            raise_on_error=False,
        )
        size_error = f"The {SERVER} allowed an invalid sample size."
        assert result.is_error, size_error
        assert "between 1 and 50" in result.content[0].text, size_error
        result = await client.call_tool(
            "sample_mitigations",
            {"config_path": FIXTURE_CONFIG, "sample_size": 0},
            raise_on_error=False,
        )
        assert result.is_error, size_error
        result = await client.call_tool(
            "sample_mitigations",
            {
                "config_path": FIXTURE_CONFIG,
                "sample_size": 10,
                "seed": "audit-seed-3",
                "scanner": "grype",
            },
        )
        sample = result.data
        assert sample["pool_size"] == 5, size_error
        assert sample["sample_size"] == len(sample["entries"]) == 5, size_error
        print(f" {GREEN}✔{RESET} The {SERVER} capped sizes and drew small pools whole")

    print(f"[+] The {SERVER} is up-up")


if __name__ == "__main__":
    run(main())
