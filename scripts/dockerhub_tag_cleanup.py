#!/usr/bin/env python3
"""Apply bounded Docker Hub tag retention after a successful release."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable
from dataclasses import dataclass

_SEMVER_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")
_ALLOWED_FLOATING_TAGS = frozenset({"latest"})
_STALE_FLOATING_TAGS = frozenset({"0"})

# Every request carries the Docker Hub bearer token, so only these origins may
# ever be dialled — including the paginated ``next`` URLs the API hands back.
_API_ORIGIN = "https://hub.docker.com"
# Safety valve for a malformed/cyclic pagination chain.
_MAX_TAG_PAGES = 100
# Docker Hub applies tag deletions asynchronously; re-read a few times before
# calling a deletion failed.
_VERIFY_ATTEMPTS = 5
_VERIFY_BACKOFF_SECONDS = 5.0


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


def plan_cleanup(
    repository: str,
    tags: Iterable[str],
    keep_count: int,
    protect: Iterable[str] = (),
) -> CleanupPlan:
    """Return a fail-closed retention plan without changing Docker Hub.

    *protect* names tags that must survive regardless of their rank — the
    release workflow passes the version it just published so a patch on an
    older line can never delete the image the release just pushed.
    """
    if not 1 <= keep_count <= 50:
        raise ValueError("keep_count must be between 1 and 50")
    protected = frozenset(protect)

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
    ranked = semver_tags[:keep_count]
    kept_extra = [tag for tag in semver_tags[keep_count:] if tag in protected]
    keep_semver = tuple(sorted({*ranked, *kept_extra}, key=_semver_key, reverse=True))
    old_semver = tuple(tag for tag in semver_tags[keep_count:] if tag not in protected)
    stale_floating = tuple(tag for tag in sorted(_STALE_FLOATING_TAGS) if tag in unique_tags and tag not in protected)

    return CleanupPlan(
        repository=repository,
        keep=("latest", *keep_semver),
        delete=(*stale_floating, *old_semver),
    )


class _RejectRegistryRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: urllib.request.Request, fp: object, code: int, msg: str, headers: object, newurl: str) -> None:
        raise RuntimeError("Docker registry verification refused a redirect")


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
        self._pull_tokens: dict[str, str] = {}

    @staticmethod
    def _check_origin(url: str) -> None:
        """Reject any URL that would send the bearer token somewhere else."""
        parts = urllib.parse.urlsplit(url)
        if f"{parts.scheme}://{parts.netloc}" != _API_ORIGIN:
            raise RuntimeError(f"refusing to follow off-origin Docker Hub URL: {url!r}")

    def _request(self, url: str, *, method: str = "GET") -> urllib.request.Request:
        self._check_origin(url)
        return urllib.request.Request(
            url,
            headers={"Authorization": f"Bearer {self._token}", "Accept": "application/json"},
            method=method,
        )

    def list_tags(self, repository: str) -> list[str]:
        encoded_repository = urllib.parse.quote(repository, safe="/")
        url = f"https://hub.docker.com/v2/repositories/{encoded_repository}/tags/?page_size=100&ordering=-last_updated"
        tags: list[str] = []
        for _ in range(_MAX_TAG_PAGES):
            if not url:
                break
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
        if url:
            # Planning against a truncated tag list would delete on partial
            # registry state, so stop rather than guess.
            raise RuntimeError(f"{repository}: tag listing exceeded {_MAX_TAG_PAGES} pages")
        return tags

    def tag_exists_in_registry(self, repository: str, tag: str) -> bool:
        """Read a public manifest without sending Hub credentials to the registry.

        Hub's tag metadata can outlive the pullable manifest. Only an explicit
        MANIFEST_UNKNOWN response is absence; auth, transport and malformed
        responses fail closed. Private repositories cannot use this fallback.
        """
        opener = urllib.request.build_opener(_RejectRegistryRedirects())
        try:
            if repository not in self._pull_tokens:
                query = urllib.parse.urlencode({"service": "registry.docker.io", "scope": f"repository:{repository}:pull"})
                with opener.open(f"https://auth.docker.io/token?{query}", timeout=30) as response:
                    body = json.load(response)
                token = body.get("token") if isinstance(body, dict) else None
                if not isinstance(token, str) or not token:
                    raise RuntimeError("Docker registry returned no public pull token")
                self._pull_tokens[repository] = token
            encoded_repository = urllib.parse.quote(repository, safe="/")
            encoded_tag = urllib.parse.quote(tag, safe="")
            request = urllib.request.Request(
                f"https://registry-1.docker.io/v2/{encoded_repository}/manifests/{encoded_tag}",
                headers={
                    "Authorization": f"Bearer {self._pull_tokens[repository]}",
                    "Accept": "application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, "
                    "application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json",
                },
            )
            try:
                with opener.open(request, timeout=30) as response:
                    if response.status != 200:
                        raise RuntimeError(f"{repository}:{tag}: unexpected registry verification status")
                    return True
            except urllib.error.HTTPError as exc:
                if exc.code == 404:
                    body = json.load(exc)
                    errors = body.get("errors") if isinstance(body, dict) else None
                    if (
                        isinstance(errors, list)
                        and errors
                        and all(isinstance(error, dict) and error.get("code") == "MANIFEST_UNKNOWN" for error in errors)
                    ):
                        return False
                raise RuntimeError(f"{repository}:{tag}: registry verification failed (HTTP {exc.code})") from exc
        except (OSError, urllib.error.URLError, ValueError) as exc:
            raise RuntimeError(f"{repository}:{tag}: could not verify registry manifest") from exc

    def delete_tag(self, repository: str, tag: str) -> None:
        encoded_repository = urllib.parse.quote(repository, safe="/")
        encoded_tag = urllib.parse.quote(tag, safe="")
        url = f"https://hub.docker.com/v2/repositories/{encoded_repository}/tags/{encoded_tag}"
        try:
            with urllib.request.urlopen(self._request(url, method="DELETE"), timeout=30) as response:
                status = response.status
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return
            raise RuntimeError(f"{repository}:{tag}: Docker Hub deletion failed (HTTP {exc.code})") from exc
        except (OSError, urllib.error.URLError) as exc:
            raise RuntimeError(f"{repository}:{tag}: Docker Hub deletion failed") from exc
        if status != 204:
            raise RuntimeError(f"{repository}:{tag}: Docker Hub deletion returned HTTP {status}")


def settle_deletions(
    client: DockerHubClient,
    plan: CleanupPlan,
    *,
    attempts: int = _VERIFY_ATTEMPTS,
    sleep: Callable[[float], None] = time.sleep,
) -> None:
    """Confirm *plan*'s deletions actually took, retrying the ones that did not.

    Hub metadata can still list tags whose manifests are gone. Corroborate
    lingering records against the registry, with a readable retained tag as a
    positive control. Retry only tags that remain pullable. This verifies tag
    removal, not deletion of shared image layers or reclaimed storage.
    """
    outstanding = set(plan.delete)
    for attempt in range(1, attempts + 1):
        outstanding &= set(client.list_tags(plan.repository))
        if not outstanding:
            return
        # A positive control prevents repository/access failures from looking
        # like successful deletion. Never re-delete a metadata-only tag.
        if not plan.keep or not client.tag_exists_in_registry(plan.repository, plan.keep[0]):
            raise RuntimeError(f"{plan.repository}: retained tag is not readable in the registry")
        metadata_only = {tag for tag in outstanding if not client.tag_exists_in_registry(plan.repository, tag)}
        if metadata_only:
            print(f"{plan.repository}: registry confirms absent tags still listed by Hub: {sorted(metadata_only)}")
            outstanding -= metadata_only
        if not outstanding:
            return
        if attempt == attempts:
            break
        print(f"{plan.repository}: {len(outstanding)} tag(s) not settled yet, retrying")
        sleep(_VERIFY_BACKOFF_SECONDS * attempt)
        for tag in sorted(outstanding):
            client.delete_tag(plan.repository, tag)
    raise RuntimeError(f"{plan.repository}: deletion verification failed: {sorted(outstanding)}")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", action="append", required=True)
    parser.add_argument("--keep-count", type=int, default=10)
    parser.add_argument(
        "--protect-tag",
        action="append",
        default=[],
        help="tag that must survive retention regardless of rank (repeatable)",
    )
    parser.add_argument("--expected-delete-count", type=int)
    parser.add_argument("--dry-run", action="store_true")
    return parser


def main(argv: list[str] | None = None, *, sleep: Callable[[float], None] = time.sleep) -> int:
    args = _parser().parse_args(argv)
    username = os.environ.get("DOCKERHUB_USERNAME", "")
    password = os.environ.get("DOCKERHUB_TOKEN", "")
    if not username or not password:
        print("Docker Hub credentials are required", file=sys.stderr)
        return 2

    try:
        client = DockerHubClient(username, password)
        plans = [
            plan_cleanup(repository, client.list_tags(repository), args.keep_count, protect=args.protect_tag)
            for repository in args.repository
        ]
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
                print(f"requested deletion of {plan.repository}:{tag}")

        for plan in plans:
            settle_deletions(client, plan, sleep=sleep)
        print(f"Verified deletion of {delete_count} Docker Hub tags")
        return 0
    except (RuntimeError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
