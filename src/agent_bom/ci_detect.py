"""CI/CD environment detection for agent-bom.

Detects the current CI/CD provider from standard environment variables so
agent-bom can apply sensible defaults (e.g. quiet mode, non-TTY output)
when running inside a pipeline.
"""

from __future__ import annotations

import os


def detect_ci_environment() -> dict:
    """Detect CI/CD environment from standard env vars.

    Returns a dict with keys:
      - ``provider``: name of the detected CI provider (str or None)
      - ``is_ci``: True if any CI environment was detected (bool)
    """
    ci_vars = {
        "github_actions": "GITHUB_ACTIONS",
        "gitlab_ci": "GITLAB_CI",
        "jenkins": "JENKINS_URL",
        "circleci": "CIRCLECI",
        "travis": "TRAVIS",
        "azure_devops": "TF_BUILD",
        "bitbucket": "BITBUCKET_PIPELINE_UUID",
    }
    for name, env_var in ci_vars.items():
        if os.environ.get(env_var):
            return {"provider": name, "is_ci": True}
    # Generic CI fallback
    return {"provider": None, "is_ci": bool(os.environ.get("CI"))}


def is_ci() -> bool:
    """Return True if running inside any known CI/CD environment."""
    return detect_ci_environment()["is_ci"]
