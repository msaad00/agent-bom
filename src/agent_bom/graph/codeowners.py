"""Compatibility path for CODEOWNERS ingestion, which lives in ``agent_bom.codeowners``."""

from agent_bom.codeowners import CodeOwnerRule as CodeOwnerRule
from agent_bom.codeowners import apply_codeowners as apply_codeowners
from agent_bom.codeowners import load_codeowners as load_codeowners
from agent_bom.codeowners import normalize_codeowners as normalize_codeowners
from agent_bom.codeowners import owner_for_path as owner_for_path
