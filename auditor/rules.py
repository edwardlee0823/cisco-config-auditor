import re


SEVERITY_ORDER = {"High": 0, "Medium": 1, "Low": 2}


def finding(rule_id, title, severity, evidence, explanation, recommendation):
    return {
        "rule_id": rule_id,
        "title": title,
        "severity": severity,
        "evidence": evidence,
        "explanation": explanation,
        "recommendation": recommendation,
    }


def _has_command(lines, command):
    return any(line == command or line.startswith(command + " ") for line in lines)


def check_telnet(parsed):
    results = []
    for section, lines in parsed["line_sections"].items():
        if not section.startswith("line vty"):
            continue
        for line in lines:
            if line.startswith("transport input"):
                methods = line.split()[2:]
                if "telnet" in methods or "all" in methods:
                    results.append(
                        finding(
                            "NET-001",
                            "Telnet enabled for remote management",
                            "High",
                            f"{section}: {line}",
                            "Telnet does not protect management traffic with encryption.",
                            "Restrict remote management to SSH where operationally appropriate.",
                        )
                    )
    return results


def check_ssh_version(parsed):
    lines = parsed["global_lines"]
    ssh_lines = [line for line in lines if line.startswith("ip ssh version")]

    if not ssh_lines:
        return [
            finding(
                "NET-002",
                "SSH version 2 is not explicitly configured",
                "Medium",
                "No 'ip ssh version 2' command found",
                "The configuration does not explicitly require SSH version 2.",
                "Configure SSH version 2 after validating device and environment requirements.",
            )
        ]

    if any(line == "ip ssh version 1" for line in ssh_lines):
        return [
            finding(
                "NET-002",
                "SSH version 1 configured",
                "High",
                "ip ssh version 1",
                "SSH version 1 is obsolete and should not be used for modern remote administration.",
                "Use SSH version 2.",
            )
        ]

    return []


def check_snmp_communities(parsed):
    results = []
    weak_names = {"public", "private"}

    for line in parsed["global_lines"]:
        if not line.startswith("snmp-server community "):
            continue
        parts = line.split()
        if len(parts) >= 3 and parts[2].lower() in weak_names:
            results.append(
                finding(
                    "NET-003",
                    "Default SNMP community string detected",
                    "High",
                    line,
                    "Default community strings are widely known and are poor choices for access control.",
                    "Replace default community strings and prefer stronger SNMP security options where supported.",
                )
            )
    return results


def check_reversible_passwords(parsed):
    results = []
    patterns = [
        re.compile(r"(^|\s)password 7\s+\S+", re.IGNORECASE),
        re.compile(r"(^|\s)secret 7\s+\S+", re.IGNORECASE),
    ]

    all_lines = list(parsed["global_lines"])
    for section, lines in parsed["line_sections"].items():
        all_lines.extend(f"{section}: {line}" for line in lines)
    for section, lines in parsed["interfaces"].items():
        all_lines.extend(f"{section}: {line}" for line in lines)

    for line in all_lines:
        if any(pattern.search(line) for pattern in patterns):
            results.append(
                finding(
                    "NET-004",
                    "Reversible Type 7 credential detected",
                    "High",
                    line,
                    "Cisco Type 7 encoding is reversible and should not be treated as secure password protection.",
                    "Use stronger secret storage supported by the platform and remove reversible credentials.",
                )
            )
    return results


def check_default_native_vlan(parsed):
    results = []
    for interface, lines in parsed["interfaces"].items():
        if "switchport mode trunk" not in lines:
            continue

        native_lines = [line for line in lines if line.startswith("switchport trunk native vlan ")]
        if not native_lines:
            evidence = f"{interface}: switchport mode trunk (no explicit native VLAN configured)"
            results.append(
                finding(
                    "NET-005",
                    "Trunk uses default native VLAN behavior",
                    "Medium",
                    evidence,
                    "A trunk without an explicit native VLAN uses the platform default, commonly VLAN 1.",
                    "Assign an appropriate dedicated native VLAN according to the network design.",
                )
            )
        elif any(line.endswith(" 1") for line in native_lines):
            results.append(
                finding(
                    "NET-005",
                    "Native VLAN 1 configured on trunk",
                    "Medium",
                    f"{interface}: " + "; ".join(native_lines),
                    "Using VLAN 1 as the native VLAN increases reliance on a default VLAN for trunk traffic.",
                    "Use a dedicated non-default native VLAN when consistent with the network design.",
                )
            )
    return results


def check_http_server(parsed):
    results = []
    if "ip http server" in parsed["global_lines"]:
        results.append(
            finding(
                "NET-006",
                "Unencrypted HTTP management service enabled",
                "Medium",
                "ip http server",
                "The HTTP management service does not provide encrypted transport.",
                "Disable plain HTTP if it is not required and use a secure management method.",
            )
        )
    return results


def check_vty_access_class(parsed):
    results = []
    for section, lines in parsed["line_sections"].items():
        if not section.startswith("line vty"):
            continue

        has_remote_transport = any(line.startswith("transport input") for line in lines)
        has_access_class = any(line.startswith("access-class ") and line.endswith(" in") for line in lines)

        if has_remote_transport and not has_access_class:
            results.append(
                finding(
                    "NET-007",
                    "VTY lines have no inbound access-class restriction",
                    "Medium",
                    f"{section}: no inbound access-class found",
                    "Remote management access is not restricted by an inbound VTY access-class in this configuration.",
                    "Consider restricting management-source networks with an appropriate access control policy.",
                )
            )
    return results


def check_access_port_security(parsed):
    results = []
    for interface, lines in parsed["interfaces"].items():
        if "switchport mode access" not in lines:
            continue

        if not any(line == "switchport port-security" or line.startswith("switchport port-security ") for line in lines):
            results.append(
                finding(
                    "NET-008",
                    "Access port has no port-security configuration",
                    "Low",
                    f"{interface}: switchport mode access",
                    "This access interface does not show port-security configuration.",
                    "Evaluate whether port-security is appropriate for this access port and environment.",
                )
            )
    return results


CHECKS = [
    check_telnet,
    check_ssh_version,
    check_snmp_communities,
    check_reversible_passwords,
    check_default_native_vlan,
    check_http_server,
    check_vty_access_class,
    check_access_port_security,
]


def run_checks(parsed):
    findings = []
    for check in CHECKS:
        findings.extend(check(parsed))

    findings.sort(
        key=lambda item: (
            SEVERITY_ORDER[item["severity"]],
            item["rule_id"],
            item["evidence"],
        )
    )
    return findings
