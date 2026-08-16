#!/usr/bin/env python3
"""Require a release tag to point at the exact, green main commit."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.request
from collections.abc import Callable, Mapping
from typing import Any
from urllib.parse import quote, urlencode

FetchJSON = Callable[[str], Mapping[str, Any]]


class ReleaseProofError(RuntimeError):
    """A release candidate lacks the required source or CI proof."""


def _validate_inputs(repo: str, sha: str, branch: str, workflow: str) -> None:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
        raise ReleaseProofError("repository must use the owner/name form")
    if not re.fullmatch(r"[0-9a-fA-F]{40}", sha):
        raise ReleaseProofError("candidate SHA must be a full 40-character commit SHA")
    if not re.fullmatch(r"[A-Za-z0-9._/-]+", branch) or branch.startswith("/") or ".." in branch:
        raise ReleaseProofError("branch contains unsupported characters")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", workflow):
        raise ReleaseProofError("workflow must be a workflow filename")


def _fetch_safely(fetch_json: FetchJSON, endpoint: str) -> Mapping[str, Any]:
    try:
        return fetch_json(endpoint)
    except Exception as exc:
        raise ReleaseProofError(f"release proof lookup failed ({type(exc).__name__})") from None


def verify_release_candidate(
    *,
    repo: str,
    sha: str,
    branch: str = "main",
    workflow: str = "ci.yml",
    fetch_json: FetchJSON,
) -> dict[str, str | int]:
    """Return the exact successful CI run or fail closed."""
    _validate_inputs(repo, sha, branch, workflow)
    expected_sha = sha.lower()

    ref_endpoint = f"/repos/{repo}/git/ref/heads/{quote(branch, safe='')}"
    ref_payload = _fetch_safely(fetch_json, ref_endpoint)
    ref_object = ref_payload.get("object")
    main_sha = ref_object.get("sha") if isinstance(ref_object, Mapping) else None
    if not isinstance(main_sha, str) or main_sha.lower() != expected_sha:
        raise ReleaseProofError(f"candidate {expected_sha} does not equal current {branch}")

    query = urlencode({"branch": branch, "event": "push", "per_page": 100})
    runs_endpoint = f"/repos/{repo}/actions/workflows/{quote(workflow, safe='')}/runs?{query}"
    runs_payload = _fetch_safely(fetch_json, runs_endpoint)
    runs = runs_payload.get("workflow_runs")
    if not isinstance(runs, list):
        raise ReleaseProofError("release proof lookup returned an invalid workflow-run payload")

    expected_path = f".github/workflows/{workflow}"
    for run in runs:
        if not isinstance(run, Mapping):
            continue
        if (
            str(run.get("head_sha", "")).lower() == expected_sha
            and run.get("head_branch") == branch
            and run.get("event") == "push"
            and run.get("path") == expected_path
            and run.get("status") == "completed"
            and run.get("conclusion") == "success"
        ):
            run_id = run.get("id")
            run_url = run.get("html_url")
            if isinstance(run_id, int) and isinstance(run_url, str) and run_url.startswith("https://"):
                return {"sha": expected_sha, "run_id": run_id, "run_url": run_url}

    raise ReleaseProofError(f"candidate {expected_sha} has no completed successful main push for {expected_path}")


def _github_fetch(endpoint: str) -> Mapping[str, Any]:
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        request = urllib.request.Request(
            f"https://api.github.com{endpoint}",
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {token}",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
            payload = json.load(response)
    else:
        result = subprocess.run(
            ["gh", "api", endpoint.removeprefix("/")],
            capture_output=True,
            check=False,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            raise RuntimeError("GitHub CLI request failed")
        payload = json.loads(result.stdout)
    if not isinstance(payload, dict):
        raise RuntimeError("GitHub API returned a non-object payload")
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, help="GitHub owner/repository")
    parser.add_argument("--sha", required=True, help="Full release candidate commit SHA")
    parser.add_argument("--branch", default="main")
    parser.add_argument("--workflow", default="ci.yml")
    args = parser.parse_args(argv)
    try:
        proof = verify_release_candidate(
            repo=args.repo,
            sha=args.sha,
            branch=args.branch,
            workflow=args.workflow,
            fetch_json=_github_fetch,
        )
    except ReleaseProofError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(f"release source proof: OK sha={proof['sha']} run_id={proof['run_id']} run_url={proof['run_url']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
