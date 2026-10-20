"""Monocle MCP server for reviewing cDSO mitigation statements."""

# Standard library imports.
from functools import wraps
from json import dumps
from os import environ
from time import time

# Third party imports.
from agent_os.integrations.base import GovernancePolicy
from agent_os.mcp_gateway import MCPGateway, ResponsePolicy
from agentmesh.governance import GovernanceDenied, govern
from fastmcp import FastMCP
from fastmcp.server.providers.skills import SkillsDirectoryProvider
from starlette.requests import Request
from starlette.responses import JSONResponse
from yaml import safe_dump, safe_load

# Local imports.
from tools import TOOLS

POLICY_FILE_PATH = "policy.yaml"
SAMPLE_DRAW_RULE = "limit-sample-draws"
SAMPLE_DRAW_LIMIT_VARIABLE = "MONOCLE_SAMPLE_DRAW_LIMIT"
GATEWAY_POLICY_FILE_PATH = "gateway-policy.yaml"
SKILLS_DIRECTORY = "skills"

# Tool responses carry text written by tenant teams, so the gateway scans them
# for prompt injection. It only logs threats because real mitigation text
# discusses secrets and tokens, which could be blocked by mistake.
RESPONSE_POLICY = ResponsePolicy.LOG

# Prefix for audit lines, so they can be found in `docker logs monocle_mcp`.
AUDIT_LOG_PREFIX = "MONOCLE_AUDIT"


class StdoutAuditSink:
    """Write each audit record as one JSON line to standard output.

    Docker keeps a container's output until the container is removed, so the
    record of tool calls, including the seed of every sample an audit drew,
    survives a server restart. AGT redacts credentials in the gateway's
    records before they reach this sink.
    """

    def record(self, entry: dict) -> None:
        """Write one audit record.

        Args:
            entry: The audit record, such as one the MCP gateway produces.
        """
        print(f"{AUDIT_LOG_PREFIX} {dumps(entry, default=str)}", flush=True)


def get_policy(file_path: str = POLICY_FILE_PATH) -> str:
    """Read the policy from the provided file path.

    When the MONOCLE_SAMPLE_DRAW_LIMIT environment variable is set, such as
    "15/hour", it replaces the limit of the policy's sample draw rule. The
    test suite uses this, because it draws more samples than the real limit
    allows.

    Args:
        file_path: Path to the policy file.

    Returns:
        The policy as a string.

    Raises:
        ValueError: If MONOCLE_SAMPLE_DRAW_LIMIT is set but the policy has no
            sample draw rule.
    """
    with open(file=file_path, encoding="UTF-8", mode="r") as policy_file:
        policy = policy_file.read()

    draw_limit = environ.get(SAMPLE_DRAW_LIMIT_VARIABLE)
    if not draw_limit:
        return policy

    policy_data = safe_load(policy)
    draw_rules = [
        rule for rule in policy_data["rules"] if rule["name"] == SAMPLE_DRAW_RULE
    ]
    if not draw_rules:
        raise ValueError(f"The policy has no {SAMPLE_DRAW_RULE!r} rule to change.")

    draw_rules[0]["limit"] = draw_limit
    return safe_dump(policy_data, sort_keys=False)


def get_gateway(
    audit_sink: StdoutAuditSink,
    file_path: str = GATEWAY_POLICY_FILE_PATH,
) -> MCPGateway:
    """Create an MCP gateway from the gateway policy file.

    Args:
        audit_sink: Where the gateway records each tool call.
        file_path: Path to the gateway policy file.

    Returns:
        A gateway that checks tool calls and scans tool responses.
    """
    with open(file=file_path, encoding="UTF-8", mode="r") as policy_file:
        gateway_policy = GovernancePolicy.from_yaml(policy_file.read())

    return MCPGateway(
        gateway_policy,
        response_policy=RESPONSE_POLICY,
        audit_sink=audit_sink,
    )


def apply_policy(
    fn: callable,
    policy: str,
    gateway: MCPGateway,
    audit_sink: StdoutAuditSink,
    agent_id: str,
) -> callable:
    """Return a policy-protected version of a function.

    Args:
        fn: The function to protect.
        policy: The policy to enforce.
        gateway: The MCP gateway that checks tool arguments and responses.
        audit_sink: Where calls denied by the policy are recorded. The
            gateway records every call it checks itself.
        agent_id: The agent identifier to use when evaluating the policy.

    Returns:
        A function that checks the gateway and the policy before calling `fn`.
        It raises PermissionError when the gateway denies the call or blocks
        the response, and GovernanceDenied when the policy denies it.
    """
    # Create a callable that evaluates the policy before invoking the function.
    governor = govern(fn=fn, policy=policy, agent_id=agent_id)

    # Restore the function's signature so it can be registered as a tool.
    @wraps(fn)
    def protected_function(*args, **kwargs):
        allowed, reason = gateway.intercept_tool_call(agent_id, fn.__name__, kwargs)
        if not allowed:
            raise PermissionError(f"Action denied by gateway policy: {reason}")

        # The gateway has already recorded this call as allowed, so record
        # the policy's denial too, or the audit log would miss it.
        try:
            result = governor(*args, **kwargs)
        except GovernanceDenied as error:
            audit_sink.record(
                {
                    "timestamp": time(),
                    "agent_id": agent_id,
                    "tool_name": fn.__name__,
                    "allowed": False,
                    "reason": f"Denied by policy: {error}",
                }
            )
            raise

        decision = gateway.intercept_tool_response(agent_id, fn.__name__, result)
        if not decision.allowed:
            raise PermissionError(f"Response blocked by gateway: {decision.reason}")

        return result

    return protected_function


def main() -> None:
    """Start the MCP server.

    Raises:
        RuntimeError: If the FASTMCP_PORT environment variable is not set.
    """
    # Check if the FASTMCP_PORT environment variable is set.
    if "FASTMCP_PORT" not in environ:
        raise RuntimeError("The FASTMCP_PORT environment variable is not set.")

    # Get the FASTMCP_PORT environment variable.
    fastmcp_port = int(environ["FASTMCP_PORT"])

    # Init an MCP server.
    mcp = FastMCP(name="monocle")

    # Read the policy file and create the MCP gateway.
    policy = get_policy()
    audit_sink = StdoutAuditSink()
    gateway = get_gateway(audit_sink)

    # Register tools with the MCP server.
    for tool in TOOLS:
        tool_with_policy_applied = apply_policy(
            tool,
            policy=policy,
            gateway=gateway,
            audit_sink=audit_sink,
            agent_id="monocle",
        )
        mcp.add_tool(tool_with_policy_applied)

    # Register skills with the MCP server.
    mcp.add_provider(
        SkillsDirectoryProvider(
            roots=SKILLS_DIRECTORY,
        )
    )

    @mcp.custom_route("/api/v1/health", methods=["GET"])
    async def health(request: Request) -> JSONResponse:
        """Respond to health checks.

        Args:
            request: The health check request.

        Returns:
            A JSON-based response that indicates the service is running.
        """
        return JSONResponse(content={"status": "ok"})

    # Start the MCP server.
    mcp.run(
        transport="streamable-http",
        host="0.0.0.0",
        port=fastmcp_port,
    )


if __name__ == "__main__":
    main()
