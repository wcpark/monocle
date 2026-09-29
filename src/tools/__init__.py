"""Tools registered with the Monocle MCP server."""

from .tools import find_cdso_configs, get_mitigations, list_components

TOOLS = [
    find_cdso_configs,
    get_mitigations,
    list_components,
]
