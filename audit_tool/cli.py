"""
CLI entry point for SmartContractAuditTool.

Usage:
    audit-contract --file contract.sol
    audit-contract --file contract.sol --format json --output report.json
    audit-contract --file contract.sol --no-ai --min-severity HIGH
    audit-contract --dir ./contracts --no-ai        # batch mode
    audit-contract demo                              # generate demo report
"""
import argparse
import glob
import os
import sys
import webbrowser
from pathlib import Path

from .analyzer.static import StaticAnalyzer
from .config import AuditConfig
from .reporter.html_report import HTMLReporter
from .reporter.json_report import JSONReporter

# ANSI colours
_C = {
    "CRITICAL": "\033[91m",
    "HIGH":     "\033[33m",
    "MEDIUM":   "\033[93m",
    "LOW":      "\033[94m",
    "INFO":     "\033[37m",
    "RESET":    "\033[0m",
    "BOLD":     "\033[1m",
    "DIM":      "\033[2m",
}


def _cprint(severity: str, msg: str) -> None:
    c = _C.get(severity, _C["RESET"])
    print(f"  {c}[{severity:8s}]{_C['RESET']} {msg}")


def _banner(text: str) -> None:
    w = 62
    print(f"\n{_C['BOLD']}{'=' * w}{_C['RESET']}")
    print(f"  {text}")
    print(f"{_C['BOLD']}{'=' * w}{_C['RESET']}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="audit-contract",
        description="Solidity/EVM smart contract security auditor (static + AI)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  # Single file — HTML report (default)
  audit-contract --file token.sol

  # Single file — JSON, no AI
  audit-contract --file token.sol --no-ai --format json

  # Batch — all .sol in a directory
  audit-contract --dir ./contracts --no-ai

  # Filter to HIGH+ only
  audit-contract --file token.sol --min-severity HIGH

  # Generate demo report without API key
  audit-contract demo
        """,
    )

    sub = parser.add_subparsers(dest="command")

    # demo sub-command
    sub.add_parser("demo", help="Generate a demo HTML report from the bundled vulnerable contract")

    # web sub-command
    web_p = sub.add_parser("web", help="Start the web interface")
    web_p.add_argument("--port", type=int, default=AuditConfig.web_port)
    web_p.add_argument("--host", default=AuditConfig.web_host)
    web_p.add_argument("--debug", action="store_true", default=AuditConfig.web_debug)

    # Main audit arguments (also used as defaults when no sub-command)
    parser.add_argument("--file", "-f", metavar="FILE", help="Path to a single .sol file")
    parser.add_argument(
        "--dir", "-d", metavar="DIR", help="Directory to batch-audit all .sol files"
    )
    parser.add_argument(
        "--format",
        choices=["html", "json", "console"],
        default="html",
        help="Output format (default: html)",
    )
    parser.add_argument("--output", "-o", metavar="PATH", help="Output path (auto if omitted)")
    parser.add_argument("--no-ai", action="store_true", help="Skip AI analysis")
    parser.add_argument(
        "--min-severity",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        default="INFO",
        metavar="LEVEL",
        help="Minimum severity to report (default: INFO)",
    )
    parser.add_argument(
        "--model",
        default=AuditConfig.model,
        metavar="MODEL",
        help=f"Claude model ID (default: {AuditConfig.model})",
    )
    parser.add_argument("--api-key", metavar="KEY", help="Anthropic API key")
    parser.add_argument(
        "--open", action="store_true", dest="open_browser",
        help="Open the HTML report in the default browser after generation",
    )
    return parser


def _audit_file(
    path: str,
    use_ai: bool,
    fmt: str,
    output_path: str | None,
    min_severity: str,
    api_key: str | None,
    model: str,
    open_browser: bool,
) -> int:
    with open(path, encoding="utf-8") as fh:
        source = fh.read()

    contract_name = os.path.basename(path)
    _banner(f"SmartContractAuditTool  —  {contract_name}")

    # Static
    print(f"\n{_C['BOLD']}[1/2] Static analysis …{_C['RESET']}")
    static_findings = StaticAnalyzer().analyze(source, min_severity=min_severity)
    static_findings = AuditConfig.filter_by_min_severity(static_findings, min_severity)
    print(f"      → {len(static_findings)} finding(s)")

    # AI
    ai_findings: list = []
    if use_ai:
        resolved_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not resolved_key:
            print(
                f"{_C['MEDIUM']}Warning:{_C['RESET']} ANTHROPIC_API_KEY not set — "
                "skipping AI analysis.\n"
                "         Set the env var or pass --api-key.",
                file=sys.stderr,
            )
        else:
            print(f"{_C['BOLD']}[2/2] AI analysis (Claude) …{_C['RESET']}")
            from .analyzer.ai_auditor import AIAuditor
            ai_findings, _ = AIAuditor(api_key=resolved_key, model=model).analyze(source)
            ai_findings = AuditConfig.filter_by_min_severity(ai_findings, min_severity)
            print(f"      → {len(ai_findings)} finding(s)")
    else:
        print(f"{_C['DIM']}[2/2] AI analysis skipped (--no-ai){_C['RESET']}")

    all_findings = static_findings + ai_findings

    # Console summary
    print(f"\n{_C['BOLD']}Findings ({len(all_findings)} total):{_C['RESET']}")
    if all_findings:
        for f in all_findings:
            line_info = f" (line {f.line})" if f.line else ""
            _cprint(f.severity, f"{f.title}{line_info}")
    else:
        print("  No findings detected.")

    if fmt == "console":
        print()
        return 0

    stem = str(Path(path).with_suffix(""))
    if fmt == "json":
        out = output_path or f"{stem}_audit.json"
        JSONReporter().generate(contract_name, source, static_findings, ai_findings, out)
        print(f"\n{_C['BOLD']}JSON report:{_C['RESET']} {out}")
    else:
        out = output_path or f"{stem}_audit.html"
        HTMLReporter().generate(contract_name, source, static_findings, ai_findings, out)
        print(f"\n{_C['BOLD']}HTML report:{_C['RESET']} {out}")
        if open_browser:
            webbrowser.open(f"file://{os.path.abspath(out)}")

    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # ── Sub-commands ──────────────────────────────────────────────────────────
    if args.command == "web":
        from .web.app import run
        print(f"Starting web server on http://{args.host}:{args.port}")
        run(host=args.host, port=args.port, debug=args.debug)
        return 0

    if args.command == "demo":
        here = Path(__file__).parent.parent
        demo_contract = here / "contracts" / "vulnerable.sol"
        if not demo_contract.exists():
            print("Demo contract not found.", file=sys.stderr)
            return 1
        return _audit_file(
            str(demo_contract),
            use_ai=False,
            fmt="html",
            output_path="demo_audit_report.html",
            min_severity="INFO",
            api_key=None,
            model=AuditConfig.model,
            open_browser=True,
        )

    # ── Batch mode ────────────────────────────────────────────────────────────
    if args.dir:
        sol_files = glob.glob(os.path.join(args.dir, "**", "*.sol"), recursive=True)
        if not sol_files:
            print(f"No .sol files found in {args.dir}", file=sys.stderr)
            return 1
        rc = 0
        for f in sorted(sol_files):
            rc |= _audit_file(
                f,
                use_ai=not args.no_ai,
                fmt=args.format,
                output_path=None,
                min_severity=args.min_severity,
                api_key=args.api_key,
                model=args.model,
                open_browser=False,
            )
        return rc

    # ── Single file ───────────────────────────────────────────────────────────
    if not args.file:
        parser.print_help()
        return 1

    if not os.path.isfile(args.file):
        print(f"Error: file not found: {args.file}", file=sys.stderr)
        return 1

    return _audit_file(
        args.file,
        use_ai=not args.no_ai,
        fmt=args.format,
        output_path=args.output,
        min_severity=args.min_severity,
        api_key=args.api_key,
        model=args.model,
        open_browser=args.open_browser,
    )


if __name__ == "__main__":
    sys.exit(main())
