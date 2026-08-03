#!/usr/bin/env python3
"""Apply bounded Docker Hub tag retention after a successful release."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Iterable

_SEMVER_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")
_ALLOWED_FLOATING_TAGS = frozenset({"latest"})
_STALE_FLOATING_TAGS = frozenset({"0"})


@dataclass(frozen=True)
class CleanupPlan:
    repository: str
    keep: tuple[str, ...]
    delete: tuple[str, ...]


def _semver_key(tag: str) -> tuple[int, int, int]:
    match = _SEMVER_RE.fullmatch(tag)
    if match is None:
        raise ValueError(f"not a stable semantic-version tag: {tag!r}")
    return (int(match.group(1)), int(match.group(2)), int(match.group(3)))


def plan_cleanup(repository: str, tags: Iterable[str], keep_count: int) -> CleanupPlan:
    """Return a fail-closed retention plan without changing Docker Hub."""
    if not 1 <= keep_count <= 50:
        raise ValueError("keep_count must be between 1 and 50")

    unique_tags = sorted(set(tags))
    if "latest" not in unique_tags:
        raise ValueError(f"{repository}: required floating tag 'latest' is missing")

    unexpected = sorted(
        tag
        for tag in unique_tags
        if tag not in _ALLOWED_FLOATING_TAGS and tag not in _STALE_FLOATING_TAGS and _SEMVER_RE.fullmatch(tag) is None
    )
    if unexpected:
        raise ValueError(f"{repository}: refusing to delete unexpected tags: {unexpected}")

    semver_tags = sorted(
        (tag for tag in unique_tags if _SEMVER_RE.fullmatch(tag)),
        key=_semver_key,
        reverse=True,
    )
    keep_semver = tuple(semver_tags[:keep_count])
    old_semver = tuple(semver_tags[keep_count:])
    stale_floating = tuple(tag for tag in sorted(_STALE_FLOATING_TAGS) if tag in unique_tags)

    return CleanupPlan(
        repository=repository,
        keep=("latest", *keep_semver),
        delete=(*stale_floating, *old_semver),
    )


class DockerHubClient:
    def __init__(self, username: str, password: str) -> None:
        payload = json.dumps({"username": username, "password": password}).encode()
        request = urllib.request.Request(
            "https://hub.docker.com/v2/users/login",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                body = json.load(response)
        except (OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
            raise RuntimeError("Docker Hub authentication failed") from exc
        token = body.get("token")
        if not isinstance(token, str) or not token:
            raise RuntimeError("Docker Hub authentication returned no token")
        self._token = token

    def _request(self, url: str, *, method: str = "GET") -> urllib.request.Request:
        return urllib.request.Request(
            url,
            headers={"Authorization": f"Bearer {self._token}", "Accept": "application/json"},
            method=method,
        )

    def list_tags(self, repository: str) -> list[str]:
        encoded_repository = urllib.parse.quote(repository, safe="/")
        url = f"https://hub.docker.com/v2/repositories/{encoded_repository}/tags/?page_size=100&ordering=-last_updated"
        tags: list[str] = []
        while url:
            try:
                with urllib.request.urlopen(self._request(url), timeout=30) as response:
                    body = json.load(response)
            except (OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
                raise RuntimeError(f"{repository}: could not list Docker Hub tags") from exc
            results = body.get("results")
            if not isinstance(results, list):
                raise RuntimeError(f"{repository}: Docker Hub tag response is malformed")
            for result in results:
                name = result.get("name") if isinstance(result, dict) else None
                if not isinstance(name, str) or not name:
                    raise RuntimeError(f"{repository}: Docker Hub returned an invalid tag record")
                tags.append(name)
            next_url = body.get("next")
            url = next_url if isinstance(next_url, str) else ""
        return tags

    def delete_tag(self, repository: str, tag: str) -> None:
        encoded_repository = urllib.parse.quote(repository, safe="/")
        encoded_tag = urllib.parse.quote(tag, safe="")
        url = f"https://hub.docker.com/v2/repositories/{encoded_repository}/tags/{encoded_tag}"
        try:
            with urllib.request.urlopen(self._request(url, method="DELETE"), timeout=30) as response:
                status = response.status
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f"{repository}:{tag}: Docker Hub deletion failed (HTTP {exc.code})") from exc
        except (OSError, urllib.error.URLError) as exc:
            raise RuntimeError(f"{repository}:{tag}: Docker Hub deletion failed") from exc
        if status != 204:
            raise RuntimeError(f"{repository}:{tag}: Docker Hub deletion returned HTTP {status}")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", action="append", required=True)
    parser.add_argument("--keep-count", type=int, default=10)
    parser.add_argument("--expected-delete-count", type=int)
    parser.add_argument("--dry-run", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    username = os.environ.get("DOCKERHUB_USERNAME", "")
    password = os.environ.get("DOCKERHUB_TOKEN", "")
    if not username or not password:
        print("Docker Hub credentials are required", file=sys.stderr)
        return 2

    try:
        client = DockerHubClient(username, password)
        plans = [plan_cleanup(repository, client.list_tags(repository), args.keep_count) for repository in args.repository]
        delete_count = sum(len(plan.delete) for plan in plans)

        for plan in plans:
            print(f"{plan.repository}: keep {len(plan.keep)}, delete {len(plan.delete)}")
            for tag in plan.keep:
                print(f"  KEEP   {tag}")
            for tag in plan.delete:
                print(f"  DELETE {tag}")
        print(f"Total tags selected for deletion: {delete_count}")

        if args.expected_delete_count is not None and delete_count != args.expected_delete_count:
            raise RuntimeError(f"refusing cleanup: expected {args.expected_delete_count} deletions but calculated {delete_count}")
        if args.dry_run:
            print("DRY RUN: no tags were deleted")
            return 0

        for plan in plans:
            for tag in plan.delete:
                client.delete_tag(plan.repository, tag)
                print(f"DELETED {plan.repository}:{tag}")

        for plan in plans:
            remaining = set(client.list_tags(plan.repository))
            undeleted = sorted(set(plan.delete) & remaining)
            if undeleted:
                raise RuntimeError(f"{plan.repository}: deletion verification failed: {undeleted}")
        print(f"Verified deletion of {delete_count} Docker Hub tags")
        return 0
    except (RuntimeError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
