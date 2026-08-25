import rich


def emit_status(message: str) -> int:
    rich.print(message)
    return 0


def exported_but_unused() -> str:
    return "not an application root"


def main() -> int:
    return emit_status("ordinary application ready")


if __name__ == "__main__":
    raise SystemExit(main())
