"""
CLI entry point for SmartContractAuditTool.

Usage:
    audit-contract --file contract.sol
    audit-contract --file contract.sol --format json --output report.json
    audit-contract --file contract.sol --no-ai
    audit-contract --file contract.sol --model claude-sonnet-4-6
"""
import argparse
import os
import sys

from .analyzer.static import StaticAnalyzer
from .reporter.html_report import HTMLReporter
from .reporter.json_report import JSONReporter


def _print_severity(severity: str, msg: str) -> None:
    colors = {
        "CRITICAL": "\033[91m",
        "HIGH": "\033[33m",
        "MEDIUM": "\033[93m",
        "LOW": "\033[94m",
        "INFO": "\033[37m",
    }
    reset = "\033[0m"
    color = colors.get(severity, reset)
    print(f"  {color}[{severity:8s}]{reset} {msg}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="audit-contract",
        description="Solidity/EVM smart contract security auditor (static + AI)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  audit-contract --file token.sol
  audit-contract --file token.sol --format json --output report.json
  audit-contract --file token.sol --no-ai
  audit-contract --file token.sol --model claude-sonnet-4-6
        """,
    )
    parser.add_argument(
        "--file", "-f", required=True, metavar="FILE", help="Path to the .sol file"
    )
    parser.add_argument(
        "--format",
        choices=["html", "json", "console"],
        default="html",
        help="Output format (default: html)",
    )
    parser.add_argument(
        "--output", "-o", metavar="PATH", help="Output file path (default: auto)"
    )
    parser.add_argument(
        "--no-ai",
        action="store_true",
        help="Skip AI analysis (static analysis only)",
    )
    parser.add_argument(
        "--model",
        default="claude-opus-4-7",
        metavar="MODEL",
        help="Claude model ID (default: claude-opus-4-7)",
    )
    parser.add_argument(
        "--api-key",
        metavar="KEY",
        help="Anthropic API key (or set ANTHROPIC_API_KEY env var)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # ── Load contract ──────────────────────────────────────────────────────
    if not os.path.isfile(args.file):
        print(f"Error: file not found: {args.file}", file=sys.stderr)
        return 1

    with open(args.file, encoding="utf-8") as fh:
        source_code = fh.read()

    contract_name = os.path.basename(args.file)
    print(f"\n{'=' * 60}")
    print(f"  SmartContractAuditTool  —  {contract_name}")
    print(f"{'=' * 60}")

    # ── Static analysis ────────────────────────────────────────────────────
    print("\n[1/2] Running static analysis …")
    static_findings = StaticAnalyzer().analyze(source_code)
    print(f"      → {len(static_findings)} static finding(s)")

    # ── AI analysis ────────────────────────────────────────────────────────
    ai_findings = []
    if not args.no_ai:
        api_key = args.api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            print(
                "Warning: ANTHROPIC_API_KEY not set — skipping AI analysis.\n"
                "         Set the env var or use --api-key.",
                file=sys.stderr,
            )
        else:
            print("[2/2] Running AI analysis via Claude …")
            from .analyzer.ai_auditor import AIAuditor
            ai_findings, _ = AIAuditor(api_key=api_key, model=args.model).analyze(source_code)
            print(f"      → {len(ai_findings)} AI finding(s)")
    else:
        print("[2/2] AI analysis skipped (--no-ai)")

    all_findings = static_findings + ai_findings

    # ── Console summary ────────────────────────────────────────────────────
    print(f"\nFindings ({len(all_findings)} total):")
    for f in all_findings:
        line = f" (line {f.line})" if f.line else ""
        _print_severity(f.severity, f"{f.title}{line}")

    # ── Generate report ────────────────────────────────────────────────────
    stem = os.path.splitext(args.file)[0]

    if args.format == "console":
        print("\nDone. (console-only mode, no file written)")
        return 0

    if args.format == "json":
        out = args.output or f"{stem}_audit.json"
        JSONReporter().generate(contract_name, source_code, static_findings, ai_findings, out)
        print(f"\nJSON report: {out}")
    else:  # html
        out = args.output or f"{stem}_audit.html"
        HTMLReporter().generate(contract_name, source_code, static_findings, ai_findings, out)
        print(f"\nHTML report: {out}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
