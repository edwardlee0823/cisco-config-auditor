import unittest

from auditor.parser import parse_config
from auditor.rules import run_checks


VULNERABLE = """
hostname TEST-SW
ip http server
ip ssh version 1
snmp-server community public RO
!
interface GigabitEthernet0/1
 switchport mode access
!
interface GigabitEthernet0/24
 switchport mode trunk
!
line vty 0 4
 password 7 02050D480809
 login
 transport input telnet ssh
"""


class RuleTests(unittest.TestCase):
    def test_expected_rules_are_found(self):
        parsed = parse_config(VULNERABLE)
        findings = run_checks(parsed)
        rule_ids = {f["rule_id"] for f in findings}

        expected = {
            "NET-001",
            "NET-002",
            "NET-003",
            "NET-004",
            "NET-005",
            "NET-006",
            "NET-007",
            "NET-008",
        }

        self.assertTrue(expected.issubset(rule_ids))


if __name__ == "__main__":
    unittest.main()
