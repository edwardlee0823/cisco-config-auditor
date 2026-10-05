def parse_config(text: str) -> dict:
    """
    Parse a Cisco IOS-style configuration into:
      - global_lines
      - interfaces
      - line_sections

    This intentionally uses a small, readable parser rather than trying
    to support every IOS syntax variation.
    """
    raw_lines = [line.rstrip() for line in text.splitlines()]
    global_lines = []
    interfaces = {}
    line_sections = {}

    current_type = None
    current_name = None

    for raw in raw_lines:
        stripped = raw.strip()

        if not stripped or stripped == "!":
            continue

        # New top-level sections.
        if not raw.startswith((" ", "\t")):
            if stripped.startswith("interface "):
                current_type = "interface"
                current_name = stripped
                interfaces[current_name] = []
                continue

            if stripped.startswith("line "):
                current_type = "line"
                current_name = stripped
                line_sections[current_name] = []
                continue

            # Any other top-level command returns us to global context.
            current_type = None
            current_name = None
            global_lines.append(stripped)
            continue

        # Indented subcommands belong to the active section.
        if current_type == "interface" and current_name:
            interfaces[current_name].append(stripped)
        elif current_type == "line" and current_name:
            line_sections[current_name].append(stripped)
        else:
            # Keep unusual indented lines so we do not silently drop them.
            global_lines.append(stripped)

    return {
        "global_lines": global_lines,
        "interfaces": interfaces,
        "line_sections": line_sections,
    }
