"""Monocle MCP server for reviewing cDSO mitigation statements."""

# Standard library imports.
from functools import wraps
from os import environ

# Third party imports.
from agent_os.integrations.base import GovernancePolicy
from agent_os.mcp_gateway import MCPGateway, ResponsePolicy
from agentmesh.governance import govern
from fastmcp import FastMCP
from fastmcp.server.providers.skills import SkillsDirectoryProvider
from starlette.requests import Request
from starlette.responses import JSONResponse

# Local imports.
from tools import TOOLS

POLICY_FILE_PATH = "policy.yaml"
GATEWAY_POLICY_FILE_PATH = "gateway-policy.yaml"
SKILLS_DIRECTORY = "skills"

# Tool responses carry text written by tenant teams, so the gateway scans them
# for prompt injection. It only logs threats because real mitigation text
# discusses secrets and tokens, which could be blocked by mistake.
RESPONSE_POLICY = ResponsePolicy.LOG


def get_policy(file_path: str = POLICY_FILE_PATH) -> str:
    """Read the policy from the provided file path.

    Args:
        file_path: Path to the policy file.

    Returns:
        The policy as a string.
    """
    with open(file=file_path, encoding="UTF-8", mode="r") as policy_file:
        return policy_file.read()


def get_gateway(file_path: str = GATEWAY_POLICY_FILE_PATH) -> MCPGateway:
    """Create an MCP gateway from the gateway policy file.

    Args:
        file_path: Path to the gateway policy file.

    Returns:
        A gateway that checks tool calls and scans tool responses.
    """
    with open(file=file_path, encoding="UTF-8", mode="r") as policy_file:
        gateway_policy = GovernancePolicy.from_yaml(policy_file.read())

    return MCPGateway(gateway_policy, response_policy=RESPONSE_POLICY)


def apply_policy(
    fn: callable,
    policy: str,
    gateway: MCPGateway,
    agent_id: str,
) -> callable:
    """Return a policy-protected version of a function.

    Args:
        fn: The function to protect.
        policy: The policy to enforce.
        gateway: The MCP gateway that checks tool arguments and responses.
        agent_id: The agent identifier to use when evaluating the policy.

    Returns:
        A function that checks the gateway and the policy before calling `fn`.
        It raises PermissionError when the gateway denies the call or blocks
        the response.
    """
    # Create a callable that evaluates the policy before invoking the function.
    governor = govern(fn=fn, policy=policy, agent_id=agent_id)

    # Restore the function's signature so it can be registered as a tool.
    @wraps(fn)
    def protected_function(*args, **kwargs):
        allowed, reason = gateway.intercept_tool_call(agent_id, fn.__name__, kwargs)
        if not allowed:
            raise PermissionError(f"Action denied by gateway policy: {reason}")

        result = governor(*args, **kwargs)

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
    gateway = get_gateway()

    # Register tools with the MCP server.
    for tool in TOOLS:
        tool_with_policy_applied = apply_policy(
            tool,
            policy=policy,
            gateway=gateway,
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
