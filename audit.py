from pathlib import Path
import argparse

from auditor.parser import parse_config
from auditor.rules import run_checks
from auditor.report import write_html_report


def main():
    parser = argparse.ArgumentParser(
        description="Audit a Cisco IOS-style running configuration for common security issues."
    )
    parser.add_argument("config", help="Path to the Cisco running-config text file")
    parser.add_argument(
        "-o",
        "--output",
        default="audit-report.html",
        help="Output HTML report path (default: audit-report.html)",
    )
    args = parser.parse_args()

    config_path = Path(args.config)
    if not config_path.exists():
        raise SystemExit(f"Config file not found: {config_path}")

    parsed = parse_config(config_path.read_text(encoding="utf-8"))
    findings = run_checks(parsed)
    report_path = write_html_report(config_path.name, findings, args.output)

    print(f"Audit complete: {len(findings)} finding(s)")
    print(f"Report: {report_path}")

    high = sum(1 for f in findings if f["severity"] == "High")
    medium = sum(1 for f in findings if f["severity"] == "Medium")
    low = sum(1 for f in findings if f["severity"] == "Low")
    print(f"High: {high} | Medium: {medium} | Low: {low}")


if __name__ == "__main__":
    main()
