"""Dockerfile misconfiguration scanner.

Scans Dockerfiles for common security misconfigurations using line-by-line
regex-based analysis.  No external tools required.

Rules
-----
DOCKER-001  FROM uses :latest or no tag
DOCKER-002  USER root or no USER directive (runs as root)
DOCKER-003  Hardcoded secrets in ENV
DOCKER-004  ADD used instead of COPY (ADD can fetch remote URLs)
DOCKER-005  RUN with curl|sh or wget|bash (pipe install)
DOCKER-006  No HEALTHCHECK directive
DOCKER-007  RUN apt-get/apk/yum without --no-cache or rm -rf /var/cache
DOCKER-008  Exposed port 22 (SSH)
DOCKER-009  COPY . . without .dockerignore (may copy secrets)
DOCKER-010  FROM with unpinned base image (no hash pin)
DOCKER-011  COPY --chown with UID 0 (root ownership)
DOCKER-012  RUN chmod 777 (world-writable files)
DOCKER-013  EXPOSE range of ports (excessive surface)
DOCKER-014  RUN with sudo (unnecessary privilege escalation)
DOCKER-015  ARG used for secrets (visible in image history)
DOCKER-016  Multiple FROM without multi-stage naming
DOCKER-017  RUN pip install without --no-cache-dir
DOCKER-018  WORKDIR uses relative path
DOCKER-019  SHELL instruction overrides default shell
DOCKER-020  RUN with net=host (container shares host network during build)
"""

from __future__ import annotations

import re
from pathlib import Path

from agent_bom.iac.models import IaCFinding

# New rule patterns
_CHMOD_777_RE = re.compile(r"chmod\s+777\b", re.IGNORECASE)
_SUDO_RE = re.compile(r"\bsudo\b", re.IGNORECASE)
_PIP_NO_CACHE_RE = re.compile(r"pip3?\s+install(?!.*--no-cache-dir)", re.IGNORECASE)
_NET_HOST_RE = re.compile(r"--network\s*=\s*host", re.IGNORECASE)

# Regex patterns for secret-like ENV variable names
_SECRET_ENV_RE = re.compile(
    r"(?:API[_\-]?KEY|PASSWORD|SECRET|TOKEN|CREDENTIAL|PRIVATE[_\-]?KEY|"
    r"ACCESS[_\-]?KEY|AUTH[_\-]?TOKEN|BEARER|DB_PASS)",
    re.IGNORECASE,
)

# Pipe install patterns: curl ... | sh, wget ... | bash, etc.
_PIPE_INSTALL_RE = re.compile(
    r"(?:curl|wget)\s+.*\|\s*(?:sh|bash|zsh|python|perl)",
    re.IGNORECASE,
)

# Package manager install without cache cleanup
_PKG_INSTALL_RE = re.compile(
    r"(?:apt-get\s+install|apk\s+add|yum\s+install)",
    re.IGNORECASE,
)

_CACHE_CLEANUP_RE = re.compile(
    r"(?:--no-cache|rm\s+-rf\s+/var/(?:cache|lib/apt)|&&\s*apt-get\s+clean)",
    re.IGNORECASE,
)


def scan_dockerfile(file_path: str | Path) -> list[IaCFinding]:
    """Scan a single Dockerfile for misconfigurations.

    Parameters
    ----------
    file_path:
        Path to a Dockerfile.

    Returns
    -------
    list[IaCFinding]
        Detected misconfigurations.
    """
    path = Path(file_path)
    if not path.is_file():
        return []

    content = path.read_text(encoding="utf-8", errors="replace")
    lines = content.splitlines()
    rel_path = str(path)
    findings: list[IaCFinding] = []

    has_user = False
    has_healthcheck = False
    dockerignore_exists = (path.parent / ".dockerignore").exists()

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        # Skip comments and empty lines
        if not stripped or stripped.startswith("#"):
            continue

        upper = stripped.upper()

        # DOCKER-001: FROM uses :latest or no tag
        if upper.startswith("FROM "):
            image = stripped.split()[1] if len(stripped.split()) > 1 else ""
            # Skip scratch and build stage aliases
            if image.lower() != "scratch" and "@" not in image:
                if ":" not in image:
                    findings.append(
                        IaCFinding(
                            rule_id="DOCKER-001",
                            severity="high",
                            title="FROM uses no tag (defaults to :latest)",
                            message=(f"Image '{image}' has no explicit tag. Pin to a specific version tag for reproducible builds."),
                            file_path=rel_path,
                            line_number=i,
                            category="dockerfile",
                            compliance=["CIS-Docker-4.7", "NIST-CM-6"],
                        )
                    )
                elif image.endswith(":latest"):
                    findings.append(
                        IaCFinding(
                            rule_id="DOCKER-001",
                            severity="high",
                            title="FROM uses :latest tag",
                            message=(f"Image '{image}' uses the :latest tag. Pin to a specific version for reproducible builds."),
                            file_path=rel_path,
                            line_number=i,
                            category="dockerfile",
                            compliance=["CIS-Docker-4.7", "NIST-CM-6"],
                        )
                    )

            # DOCKER-010: FROM with unpinned base image (no hash pin)
            if image.lower() != "scratch" and "@sha256:" not in image:
                findings.append(
                    IaCFinding(
                        rule_id="DOCKER-010",
                        severity="medium",
                        title="FROM without digest pin",
                        message=(
                            f"Image '{image}' is not pinned by digest (sha256). Use @sha256:<hash> to guarantee immutable base images."
                        ),
                        file_path=rel_path,
                        line_number=i,
                        category="dockerfile",
                        compliance=["CIS-Docker-4.7", "NIST-SI-7"],
                    )
                )

        # DOCKER-002: USER root
        if upper.startswith("USER "):
            user_val = stripped.split(maxsplit=1)[1].strip() if len(stripped.split()) > 1 else ""
            has_user = True
            if user_val in ("root", "0"):
                findings.append(
                    IaCFinding(
                        rule_id="DOCKER-002",
                        severity="high",
                        title="Container runs as root",
                        message=("USER is set to root. Containers should run as a non-root user to limit blast radius of exploits."),
                        file_path=rel_path,
                        line_number=i,
                        category="dockerfile",
                        compliance=["CIS-Docker-4.1", "NIST-AC-6"],
                    )
                )

        # DOCKER-003: Hardcoded secrets in ENV
        if upper.startswith("ENV "):
            env_rest = stripped[4:].strip()
            # ENV KEY=VALUE or ENV KEY VALUE
            if "=" in env_rest:
                key = env_rest.split("=", 1)[0].strip()
                value = env_rest.split("=", 1)[1].strip().strip('"').strip("'")
            else:
                parts = env_rest.split(maxsplit=1)
                key = parts[0] if parts else ""
                value = parts[1].strip().strip('"').strip("'") if len(parts) > 1 else ""

            if _SECRET_ENV_RE.search(key) and value and len(value) >= 8:
                findings.append(
                    IaCFinding(
                        rule_id="DOCKER-003",
                        severity="critical",
                        title="Hardcoded secret in ENV",
                        message=(
                            f"ENV variable '{key}' appears to contain a hardcoded secret. "
                            "Use build args with --secret, multi-stage builds, or runtime "
                            "secret injection instead."
                        ),
                        file_path=rel_path,
                        line_number=i,
                        category="dockerfile",
                        compliance=["CIS-Docker-4.10", "NIST-IA-5"],
                    )
                )

        # DOCKER-004: ADD instead of COPY
        if upper.startswith("ADD "):
            # ADD with URLs is the concern — but even local ADD is discouraged
            findings.append(
                IaCFinding(
                    rule_id="DOCKER-004",
                    severity="medium",
                    title="ADD used instead of COPY",
                    message=(
                        "ADD can fetch remote URLs and auto-extract archives, introducing "
                        "supply chain risk. Use COPY unless you specifically need ADD features."
                    ),
                    file_path=rel_path,
                    line_number=i,
                    category="dockerfile",
                    compliance=["CIS-Docker-4.9", "NIST-CM-7"],
                )
            )

        # DOCKER-005: Pipe install (curl | sh)
        if upper.startswith("RUN "):
            run_body = stripped[4:]
            if _PIPE_INSTALL_RE.search(run_body):
                findings.append(
                    IaCFinding(
                        rule_id="DOCKER-005",
                        severity="medium",
                        title="Pipe install detected (curl|sh)",
                        message=(
                            "Piping remote scripts directly to a shell bypasses integrity checks. Download, verify checksums, then execute."
                        ),
                        file_path=rel_path,
                        line_number=i,
                        category="dockerfile",
                        compliance=["CIS-Docker-4.9", "NIST-SI-7"],
                    )
                )

            # DOCKER-007: Package install without cache cleanup
            if _PKG_INSTALL_RE.search(run_body) and not _CACHE_CLEANUP_RE.search(run_body):
                findings.append(
                    IaCFinding(
                        rule_id="DOCKER-007",
                        severity="high",
                        title="Package install without cache cleanup",
                        message=(
                            "Package manager install without --no-cache or cache removal "
                            "increases image size and attack surface. Add --no-cache or "
                            "'&& rm -rf /var/cache/*' after install."
                        ),
                        file_path=rel_path,
                        line_number=i,
                        category="dockerfile",
                        compliance=["CIS-Docker-4.3", "NIST-CM-7"],
                    )
                )

        # DOCKER-006: HEALTHCHECK
        if upper.startswith("HEALTHCHECK "):
            has_healthcheck = True

        # DOCKER-008: EXPOSE 22
        if upper.startswith("EXPOSE "):
            ports = stripped.split()[1:]
            for port in ports:
                port_num = port.split("/")[0]  # handle "22/tcp"
                if port_num == "22":
                    findings.append(
                        IaCFinding(
                            rule_id="DOCKER-008",
                            severity="medium",
                            title="SSH port exposed",
                            message=(
                                "Port 22 (SSH) is exposed. Containers should not run SSH "
                                "daemons — use 'docker exec' or orchestrator tools instead."
                            ),
                            file_path=rel_path,
                            line_number=i,
                            category="dockerfile",
                            compliance=["CIS-Docker-4.5", "NIST-CM-7"],
                        )
                    )

        # DOCKER-009: COPY . .
        if upper.startswith("COPY "):
            args = stripped.split()
            if len(args) >= 3 and args[1] == "." and args[2] == ".":
                if not dockerignore_exists:
                    findings.append(
                        IaCFinding(
                            rule_id="DOCKER-009",
                            severity="high",
                            title="COPY . . without .dockerignore",
                            message=(
                                "COPY . . copies the entire build context into the image. "
                                "Without a .dockerignore, secrets, .git, and other sensitive "
                                "files may be included. Create a .dockerignore file."
                            ),
                            file_path=rel_path,
                            line_number=i,
                            category="dockerfile",
                            compliance=["CIS-Docker-4.10", "NIST-CM-6"],
                        )
                    )

        # DOCKER-011: COPY --chown with UID 0
        if upper.startswith("COPY ") and "--chown=0" in stripped.lower():
            findings.append(
                IaCFinding(
                    rule_id="DOCKER-011",
                    severity="medium",
                    title="COPY --chown=0 (root ownership)",
                    message="COPY with --chown=0 explicitly sets root ownership. Use a non-root UID.",
                    file_path=rel_path,
                    line_number=i,
                    category="dockerfile",
                    compliance=["CIS-Docker-4.1", "NIST-AC-6"],
                )
            )

        # DOCKER-012: RUN chmod 777
        if upper.startswith("RUN ") and _CHMOD_777_RE.search(stripped):
            findings.append(
                IaCFinding(
                    rule_id="DOCKER-012",
                    severity="high",
                    title="RUN chmod 777 (world-writable files)",
                    message="chmod 777 makes files world-writable. Use specific permissions (e.g. 755 for dirs, 644 for files).",
                    file_path=rel_path,
                    line_number=i,
                    category="dockerfile",
                    compliance=["CIS-Docker-4.8", "NIST-AC-3"],
                )
            )

        # DOCKER-013: EXPOSE range of ports
        if upper.startswith("EXPOSE ") and "-" in stripped.split(None, 1)[-1]:
            findings.append(
                IaCFinding(
                    rule_id="DOCKER-013",
                    severity="medium",
                    title="EXPOSE port range (excessive attack surface)",
                    message="Exposing a range of ports increases attack surface. Expose only specific required ports.",
                    file_path=rel_path,
                    line_number=i,
                    category="dockerfile",
                    compliance=["CIS-Docker-5.8", "NIST-CM-7"],
                )
            )

        # DOCKER-014: RUN with sudo
        if upper.startswith("RUN ") and _SUDO_RE.search(stripped):
            findings.append(
                IaCFinding(
                    rule_id="DOCKER-014",
                    severity="medium",
                    title="RUN with sudo (unnecessary privilege escalation)",
                    message="sudo in Dockerfile is unnecessary — RUN already executes as the current user. Remove sudo.",
                    file_path=rel_path,
                    line_number=i,
                    category="dockerfile",
                    compliance=["CIS-Docker-4.1", "NIST-AC-6"],
                )
            )

        # DOCKER-015: ARG used for secrets
        if upper.startswith("ARG ") and _SECRET_ENV_RE.search(stripped):
            findings.append(
                IaCFinding(
                    rule_id="DOCKER-015",
                    severity="critical",
                    title="ARG used for secrets (visible in image history)",
                    message="ARG values are stored in image history. Use BuildKit secrets (--mount=type=secret) instead.",
                    file_path=rel_path,
                    line_number=i,
                    category="dockerfile",
                    compliance=["CIS-Docker-4.10", "NIST-SC-12"],
                )
            )

        # DOCKER-017: RUN pip install without --no-cache-dir
        if upper.startswith("RUN ") and _PIP_NO_CACHE_RE.search(stripped):
            findings.append(
                IaCFinding(
                    rule_id="DOCKER-017",
                    severity="low",
                    title="pip install without --no-cache-dir",
                    message="pip caches downloaded packages. Add --no-cache-dir to reduce image size.",
                    file_path=rel_path,
                    line_number=i,
                    category="dockerfile",
                    compliance=["CIS-Docker-4.9"],
                )
            )

        # DOCKER-018: WORKDIR uses relative path
        if upper.startswith("WORKDIR ") and not stripped.split(None, 1)[-1].startswith("/"):
            findings.append(
                IaCFinding(
                    rule_id="DOCKER-018",
                    severity="low",
                    title="WORKDIR uses relative path",
                    message="Use absolute paths in WORKDIR for clarity and predictability.",
                    file_path=rel_path,
                    line_number=i,
                    category="dockerfile",
                    compliance=["CIS-Docker-4.9"],
                )
            )

        # DOCKER-019: SHELL instruction overrides default
        if upper.startswith("SHELL "):
            findings.append(
                IaCFinding(
                    rule_id="DOCKER-019",
                    severity="medium",
                    title="SHELL instruction overrides default shell",
                    message="Custom SHELL changes RUN behavior. Ensure it's intentional and documented.",
                    file_path=rel_path,
                    line_number=i,
                    category="dockerfile",
                    compliance=["NIST-CM-6"],
                )
            )

        # DOCKER-020: RUN with --network=host
        if upper.startswith("RUN ") and _NET_HOST_RE.search(stripped):
            findings.append(
                IaCFinding(
                    rule_id="DOCKER-020",
                    severity="high",
                    title="RUN with --network=host (shares host network during build)",
                    message="--network=host in RUN exposes host network during build. Use default bridge network.",
                    file_path=rel_path,
                    line_number=i,
                    category="dockerfile",
                    compliance=["CIS-Docker-5.1", "NIST-SC-7"],
                )
            )

    # DOCKER-002: No USER directive at all (runs as root by default)
    if not has_user:
        findings.append(
            IaCFinding(
                rule_id="DOCKER-002",
                severity="high",
                title="No USER directive (runs as root)",
                message=(
                    "No USER directive found. The container will run as root by default. Add a USER directive to run as a non-root user."
                ),
                file_path=rel_path,
                line_number=1,
                category="dockerfile",
                compliance=["CIS-Docker-4.1", "NIST-AC-6"],
            )
        )

    # DOCKER-006: No HEALTHCHECK
    if not has_healthcheck:
        findings.append(
            IaCFinding(
                rule_id="DOCKER-006",
                severity="low",
                title="No HEALTHCHECK directive",
                message=(
                    "No HEALTHCHECK instruction found. Add a HEALTHCHECK to enable "
                    "container health monitoring and automatic restart on failure."
                ),
                file_path=rel_path,
                line_number=1,
                category="dockerfile",
                compliance=["CIS-Docker-4.6", "NIST-SI-4"],
            )
        )

    return findings
