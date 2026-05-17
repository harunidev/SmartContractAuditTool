"""Convenience entry point: `python main.py [cli|web] ...`"""
import sys


def main():
    if len(sys.argv) < 2 or sys.argv[1] == "web":
        from audit_tool.web.app import run
        port = int(sys.argv[2]) if len(sys.argv) > 2 else 5000
        print(f"Starting web server on http://localhost:{port}")
        run(debug=True, port=port)
    elif sys.argv[1] == "cli":
        from audit_tool.cli import main as cli_main
        sys.exit(cli_main(sys.argv[2:]))
    else:
        # Treat as CLI args directly: python main.py --file contract.sol
        from audit_tool.cli import main as cli_main
        sys.exit(cli_main(sys.argv[1:]))


if __name__ == "__main__":
    main()
