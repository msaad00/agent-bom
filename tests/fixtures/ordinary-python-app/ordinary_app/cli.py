import requests


def emit_status(message: str) -> int:
    return requests.get(message, timeout=5).status_code


def exported_but_unused() -> str:
    return "not an application root"


def main() -> int:
    return emit_status("https://example.com/health")


if __name__ == "__main__":
    raise SystemExit(main())
