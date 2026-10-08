"""Read-only MCP tools for reviewing mitigations in cDSO config files."""

# Standard library imports.
from os import environ, walk
from pathlib import Path
from re import IGNORECASE, compile

# Third party imports.
from yaml import MappingNode, Node, ScalarNode, SequenceNode, compose, safe_load

# Constants.
WORKSPACE = Path(environ.get("MONOCLE_WORKSPACE", "/workspace"))
CONFIG_NAME_PATTERN = compile(r"cdso_config[\w.-]*\.ya?ml$", IGNORECASE)
SKIPPED_DIRECTORIES = {".git", ".venv", "node_modules", "vendor", "__pycache__"}
SCANNERS = (
    "grype",
    "zap",
    "semgrep",
    "semgrep_ignore",
    "hadolint",
    "container_spec",
)
MAX_FINDINGS_PER_CALL = 50
COMPONENT_KEYS = {
    "project_type",
    "dockerfile_folder",
    "mitigations",
    "zap",
    "semgrep",
    "hadolint",
    "container_spec",
}
COMPONENT_CONTEXT_KEYS = (
    "project_type",
    "version",
    "dockerfile_folder",
    "build_context",
    "container_lifespan",
    "connection_context",
)
CONFIG_METADATA_KEYS = (
    "organization",
    "security_group",
    "deployment_level",
    "sdd_path",
)
# Labels are matched in any letter case when a colon follows, because configs
# use both "DESCRIPTION:" and "Description:". Without a colon, only uppercase
# counts, so the words "description" and "mitigation" in prose are not labels.
DESCRIPTION_LABEL = compile(r"(?i:\bdescription\s*:)|\bDESCRIPTION\b")
MITIGATION_LABEL = compile(r"(?i:\bmitiga[a-z]*\s*:)|\bMITIGA[A-Z]*\b")
COMMENT_LABEL = compile(r"^(Files?|Rules?|Justification)\s*:\s*(.*)$", IGNORECASE)
DECORATIVE_COMMENT = compile(r"^(#+\s*-{3,}.*|###.*)$")
RULE_ID_PATTERN = compile(r"^[A-Za-z][\w-]*(?:\.[\w-]+){2,}$")


def resolve_config_path(config_path: str) -> Path:
    """Resolve a workspace-relative cDSO config path.

    Args:
        config_path: Path to the config, relative to the workspace.

    Returns:
        The absolute, symlink-resolved path to the config.

    Raises:
        ValueError: If the path leaves the workspace, is not a cDSO config
            file name, or does not exist.
    """
    workspace = WORKSPACE.resolve()
    path = (workspace / config_path).resolve()

    # Only cDSO config files inside the mounted repository may be read.
    if not path.is_relative_to(workspace):
        raise ValueError(f"Config path {config_path!r} is outside the workspace.")
    if not CONFIG_NAME_PATTERN.search(path.name):
        raise ValueError(f"Config path {config_path!r} is not a cDSO config file.")
    if not path.is_file():
        raise ValueError(f"Config path {config_path!r} does not exist.")

    return path


def load_config(config_path: str) -> tuple[dict, MappingNode, list[str]]:
    """Load a cDSO config file from the workspace.

    Args:
        config_path: Path to the config, relative to the workspace.

    Returns:
        The parsed config, its YAML node tree, and its raw lines. The node
        tree and lines are needed because cDSO configs record semgrep,
        hadolint, and base-image justifications in comments.

    Raises:
        TypeError: If the config is not a YAML mapping.
    """
    text = resolve_config_path(config_path).read_text(encoding="UTF-8")
    config = safe_load(text)
    root = compose(text)

    if not isinstance(config, dict) or not isinstance(root, MappingNode):
        raise TypeError(f"Config {config_path!r} is not a YAML mapping.")

    return config, root, text.splitlines()


def is_component(section: object) -> bool:
    """Return whether a top-level config value describes a component.

    Args:
        section: A top-level value from a cDSO config.

    Returns:
        True if the value is a mapping with at least one component key.
    """
    return isinstance(section, dict) and bool(COMPONENT_KEYS & section.keys())


def get_node(node: Node | None, *keys: str) -> Node | None:
    """Follow mapping keys through a YAML node tree.

    Args:
        node: The node to start from.
        *keys: The mapping keys to follow, in order.

    Returns:
        The node at the end of the keys, or None if any key is missing.
    """
    for key in keys:
        if not isinstance(node, MappingNode):
            return None
        node = next(
            (value for key_node, value in node.value if key_node.value == key),
            None,
        )

    return node


def get_raw_mitigations(section: dict, scanner: str) -> dict[str, str]:
    """Return a component's Grype or ZAP mitigation texts.

    Args:
        section: The component's parsed config section.
        scanner: Either "grype" or "zap".

    Returns:
        The raw mitigation texts, keyed by finding ID.
    """
    if scanner == "zap":
        entries = (section.get("zap") or {}).get("mitigations") or {}
    else:
        entries = section.get("mitigations") or {}

    # Grype mitigations are a list of single-key mappings, and ZAP mitigations
    # are one mapping, so normalize both shapes.
    if isinstance(entries, dict):
        entries = [entries]

    return {
        str(finding_id): str(text)
        for entry in entries
        for finding_id, text in entry.items()
    }


def parse_mitigation(finding_id: str, text: str) -> dict:
    """Split a mitigation text into its DESCRIPTION and MITIGATION parts.

    Labels may be in any letter case. A misspelled label or one without its
    colon is reported as a format issue, but letter case is not.

    Args:
        finding_id: The finding the mitigation covers.
        text: The raw mitigation text from the config.

    Returns:
        The finding ID, description, mitigation, and any format issues.
    """
    format_issues = []
    cleaned = text.strip()

    # Folded ZAP entries often keep the quotes that were meant for YAML.
    if cleaned.startswith('"') or cleaned.endswith('"'):
        format_issues.append("Text is wrapped in literal quote characters.")
        cleaned = cleaned.strip('"').strip()

    description_match = DESCRIPTION_LABEL.search(cleaned)
    mitigation_match = MITIGATION_LABEL.search(cleaned)

    if not description_match:
        format_issues.append("Missing the 'DESCRIPTION:' label.")
    if not mitigation_match:
        format_issues.append("Missing the 'MITIGATION:' label.")
    elif mitigation_match.group().replace(" ", "").upper() != "MITIGATION:":
        label = mitigation_match.group().strip()
        format_issues.append(f"Malformed label {label!r}; expected 'MITIGATION:'.")

    description_start = description_match.end() if description_match else 0
    description_end = mitigation_match.start() if mitigation_match else len(cleaned)
    description = cleaned[description_start:description_end].strip()
    mitigation = cleaned[mitigation_match.end() :].strip() if mitigation_match else ""

    return {
        "finding_id": finding_id,
        "description": description,
        "mitigation": mitigation,
        "format_issues": format_issues,
    }


def new_comment_block() -> dict:
    """Return an empty group of sequence items and their comments.

    Returns:
        A block with no items, files, justification, or commented rules.
    """
    return {
        "items": [],
        "files": [],
        "justification": [],
        "commented_rules": [],
        "labeled": False,
    }


def close_comment_block(blocks: list[dict], block: dict) -> dict:
    """Keep a block that justifies at least one item and start a new one.

    Args:
        blocks: The completed blocks, which the block is appended to if it
            has items.
        block: The block to close.

    Returns:
        A new, empty block.
    """
    if block["items"]:
        blocks.append(block)

    return new_comment_block()


def parse_commented_sequence(lines: list[str], node: SequenceNode) -> list[dict]:
    """Group a YAML sequence's items with the comments that justify them.

    Handles the comment styles found in cDSO configs: a free-text comment
    above its items, labeled "File:", "Rule:", and "Justification:" comments
    around their items, and inline comments after an item.

    Args:
        lines: The config's raw lines.
        node: The sequence node to read.

    Returns:
        Blocks of items, each with the files, justification, and
        commented-out rules from its comments.
    """
    items = {
        item.start_mark.line: item
        for item in node.value
        if isinstance(item, ScalarNode)
    }
    if not items:
        return []

    # Include comments between the sequence's key and its first item.
    start = min(node.start_mark.line, min(items))
    while start > 0 and lines[start - 1].strip().startswith("#"):
        start -= 1

    blocks: list[dict] = []
    block = new_comment_block()
    label = ""
    previous_line = ""

    for index in range(start, min(node.end_mark.line + 1, len(lines))):
        line = lines[index]
        stripped = line.strip()

        if index in items:
            item = items[index]
            inline_comment = ""
            if item.end_mark.line == index:
                inline_comment = line[item.end_mark.column :].partition("#")[2]

            # An inline comment justifies only its own item.
            if inline_comment.strip():
                block = close_comment_block(blocks, block)
                block["items"].append(item.value)
                block["justification"].append(inline_comment.strip())
                block = close_comment_block(blocks, block)
            else:
                block["items"].append(item.value)

            label = ""
            previous_line = "item"
            continue

        # Blank lines, section headers, and YAML keys end a block.
        if not stripped.startswith("#") or DECORATIVE_COMMENT.match(stripped):
            block = close_comment_block(blocks, block)
            label = ""
            previous_line = ""
            continue

        content = stripped.lstrip("#").strip()

        # A commented-out rule is documented but not excluded.
        rule_candidate = content.removeprefix("-").strip().strip("\"'")
        if RULE_ID_PATTERN.match(rule_candidate):
            block["commented_rules"].append(rule_candidate)
            previous_line = "comment"
            continue

        label_match = COMMENT_LABEL.match(content)
        if label_match:
            label = label_match.group(1).lower().removesuffix("s")
            content = label_match.group(2).strip()
            block["labeled"] = True
        elif previous_line == "item" and not block["labeled"]:
            # An unlabeled comment after items introduces the next group.
            block = close_comment_block(blocks, block)

        previous_line = "comment"
        if not content:
            continue
        if label == "file":
            block["files"].append(content)
        elif label == "rule" and RULE_ID_PATTERN.match(content):
            block["commented_rules"].append(content)
        else:
            block["justification"].append(content)

    close_comment_block(blocks, block)
    return blocks


def read_commented_mitigations(lines: list[str], node: Node | None) -> dict[str, dict]:
    """Return the justifications for each item in a commented sequence.

    Args:
        lines: The config's raw lines.
        node: The sequence node to read, or None if it is missing.

    Returns:
        Each item's justifications and format issues, keyed by item.
    """
    if not isinstance(node, SequenceNode):
        return {}

    mitigations: dict[str, dict] = {}
    for block in parse_commented_sequence(lines, node):
        for item in block["items"]:
            entry = mitigations.setdefault(
                item,
                {"finding_id": item, "justifications": [], "format_issues": []},
            )
            entry["justifications"].append(
                {
                    "mitigation": " ".join(block["justification"]),
                    "files": block["files"],
                    "commented_rules": block["commented_rules"],
                }
            )

    for entry in mitigations.values():
        if not any(item["mitigation"] for item in entry["justifications"]):
            entry["format_issues"].append("No justification comment was found.")

    return mitigations


def read_container_spec_mitigations(
    lines: list[str],
    node: Node | None,
) -> dict[str, dict]:
    """Return the base-image exceptions and their justifications.

    Args:
        lines: The config's raw lines.
        node: The component's node, or None if it is missing.

    Returns:
        Each exception's justifications and format issues, keyed by the image
        or container_spec key.
    """
    container_spec = get_node(node, "container_spec")
    if not isinstance(container_spec, MappingNode):
        return {}

    mitigations: dict[str, dict] = {}
    for key_node, value_node in container_spec.value:
        if isinstance(value_node, SequenceNode):
            mitigations.update(read_commented_mitigations(lines, value_node))
        elif isinstance(value_node, ScalarNode):
            justification = value_node.value.strip()
            mitigations[key_node.value] = {
                "finding_id": key_node.value,
                "justifications": [
                    {"mitigation": justification, "files": [], "commented_rules": []}
                ],
                "format_issues": [] if justification else ["No justification."],
            }

    return mitigations


def read_mitigations(
    section: dict,
    node: Node | None,
    lines: list[str],
    scanner: str,
) -> dict[str, dict]:
    """Return a component's mitigations for one scanner.

    Args:
        section: The component's parsed config section.
        node: The component's node, or None if it is missing.
        lines: The config's raw lines.
        scanner: One of the names in SCANNERS.

    Returns:
        The component's mitigations for the scanner, keyed by finding ID.
    """
    if scanner in ("grype", "zap"):
        return {
            finding_id: parse_mitigation(finding_id, text)
            for finding_id, text in get_raw_mitigations(section, scanner).items()
        }
    if scanner == "semgrep":
        return read_commented_mitigations(
            lines,
            get_node(node, "semgrep", "exclusions"),
        )
    if scanner == "semgrep_ignore":
        return read_commented_mitigations(lines, get_node(node, "semgrep", "ignore"))
    if scanner == "hadolint":
        return read_commented_mitigations(lines, get_node(node, "hadolint", "ignores"))

    return read_container_spec_mitigations(lines, node)


def find_cdso_configs() -> list[str]:
    """Find cDSO config files in the mounted repository.

    Returns:
        Workspace-relative paths of files such as cdso_config.yml,
        pipelines/cdso_config.yml, or oasis_cdso_config.yml.
    """
    workspace = WORKSPACE.resolve()
    config_paths = []

    for directory, subdirectories, file_names in walk(workspace):
        subdirectories[:] = [
            name for name in subdirectories if name not in SKIPPED_DIRECTORIES
        ]
        for file_name in file_names:
            if CONFIG_NAME_PATTERN.search(file_name):
                path = Path(directory) / file_name
                config_paths.append(str(path.relative_to(workspace)))

    return sorted(config_paths)


def list_components(config_path: str) -> dict:
    """List the components in a cDSO config and the findings each one mitigates.

    Args:
        config_path: Workspace-relative path returned by find_cdso_configs.

    Returns:
        The config's metadata and, for each component, its deployment context
        (such as connection_context and container_lifespan), the IDs of its
        mitigated findings for each scanner, and the reasons given for any
        skipped scans.

    Raises:
        TypeError: If the config is not a YAML mapping.
        ValueError: If the config path is not a cDSO config in the workspace.
    """
    config, root, lines = load_config(config_path)
    components = []

    for name, section in config.items():
        if not is_component(section):
            continue

        node = get_node(root, name)
        component = {"name": name}
        for key in COMPONENT_CONTEXT_KEYS:
            if key in section:
                component[key] = section[key]
        component["findings"] = {
            scanner: list(read_mitigations(section, node, lines, scanner))
            for scanner in SCANNERS
        }
        component["skip_reasons"] = {
            scanner: section[scanner]["skip_reason"]
            for scanner in SCANNERS
            if isinstance(section.get(scanner), dict)
            and section[scanner].get("skip_reason")
        }
        components.append(component)

    metadata = {key: config[key] for key in CONFIG_METADATA_KEYS if key in config}
    return {**metadata, "components": components}


def get_mitigations(
    config_path: str,
    component: str,
    finding_ids: list[str] | None = None,
    scanner: str = "grype",
) -> list[dict]:
    """Read a component's mitigation statements from a cDSO config.

    Grype and ZAP statements are split into the advisory DESCRIPTION and the
    team's MITIGATION. Semgrep rule exclusions, semgrep path ignores,
    hadolint ignores, and container_spec entries return
    the justifications recorded next to each exclusion, including comments,
    with the files they name. Every entry lists formatting problems that
    would affect pasting a corrected statement back into the config.

    One call returns at most 50 findings, which keeps each response small
    enough for the agent's model limits. When a component has more, pass
    finding_ids in batches of up to 50, using the IDs from list_components.

    Args:
        config_path: Workspace-relative path returned by find_cdso_configs.
        component: Component name returned by list_components.
        finding_ids: Finding IDs to read, such as CVE-2025-59375, a semgrep
            rule ID, or a hadolint code. At most 50 per call. Reads every
            finding when omitted, if the component has 50 or fewer.
        scanner: One of "grype", "zap", "semgrep" (excluded rules),
            "semgrep_ignore" (paths semgrep does not scan), "hadolint", or
            "container_spec" (base-image exceptions).

    Returns:
        One entry per finding with its mitigation text or justifications and
        any format issues.

    Raises:
        TypeError: If the config is not a YAML mapping.
        ValueError: If the config path is not a cDSO config in the workspace,
            the scanner or component does not exist, a finding ID has no
            mitigation, or the call would return more than 50 findings.
    """
    if scanner not in SCANNERS:
        raise ValueError(f"Scanner {scanner!r} is not one of {SCANNERS}.")

    config, root, lines = load_config(config_path)
    section = config.get(component)
    if not is_component(section):
        raise ValueError(f"Component {component!r} does not exist in the config.")

    mitigations = read_mitigations(section, get_node(root, component), lines, scanner)

    requested_count = len(mitigations if finding_ids is None else finding_ids)
    if requested_count > MAX_FINDINGS_PER_CALL:
        raise ValueError(
            f"This call would return {requested_count} {scanner} findings. Pass "
            f"finding_ids in batches of at most {MAX_FINDINGS_PER_CALL}, using "
            "the IDs from list_components."
        )

    if finding_ids is None:
        return list(mitigations.values())

    missing_ids = [
        finding_id for finding_id in finding_ids if finding_id not in mitigations
    ]
    if missing_ids:
        raise ValueError(
            f"Findings {missing_ids} have no {scanner} mitigation in {component!r}."
        )

    return [mitigations[finding_id] for finding_id in finding_ids]
