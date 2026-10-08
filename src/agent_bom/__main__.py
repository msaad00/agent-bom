"""Allow ``python -m agent_bom`` to run the CLI."""

from agent_bom.entrypoint import cli_main

if __name__ == "__main__":
    cli_main()
