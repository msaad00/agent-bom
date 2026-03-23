"""Data models for IaC misconfiguration findings."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class IaCFinding:
    """A single IaC misconfiguration finding."""

    rule_id: str  # e.g. "DOCKER-001", "K8S-001", "TF-SEC-001"
    severity: str  # critical, high, medium, low
    title: str  # Short description
    message: str  # Detailed explanation with fix guidance
    file_path: str  # Relative path to the file
    line_number: int  # Line where the issue was found
    category: str  # "dockerfile", "kubernetes", "terraform"
    compliance: list[str] = field(default_factory=list)  # e.g. ["CIS-5.1", "NIST-CM-6"]
    attack_techniques: list[str] = field(default_factory=list)  # MITRE ATT&CK IDs, e.g. ["T1552.001"]
    remediation: str = ""  # Fix guidance
