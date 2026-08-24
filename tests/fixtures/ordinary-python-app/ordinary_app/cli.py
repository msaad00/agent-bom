import requests


def fetch_status(url: str) -> int:
    return requests.get(url, timeout=5).status_code


def exported_but_unused() -> str:
    return "not an application root"


def main() -> int:
    return fetch_status("https://example.com")


if __name__ == "__main__":
    raise SystemExit(main())
