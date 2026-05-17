"""
SmartContractAuditTool — convenience launcher.

    python main.py --file contract.sol          # CLI audit
    python main.py web                          # web server
    python main.py demo                         # demo HTML report
    python main.py --dir ./contracts --no-ai    # batch audit
"""
import sys


def main() -> int:
    from audit_tool.cli import main as cli_main
    return cli_main(sys.argv[1:] or ["--help"])


if __name__ == "__main__":
    sys.exit(main())
