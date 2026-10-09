"""Compatibility path for CODEOWNERS ingestion, which lives in ``agent_bom.domain.codeowners``."""

from agent_bom.domain.codeowners import CodeOwnerRule as CodeOwnerRule
from agent_bom.domain.codeowners import apply_codeowners as apply_codeowners
from agent_bom.domain.codeowners import load_codeowners as load_codeowners
from agent_bom.domain.codeowners import normalize_codeowners as normalize_codeowners
from agent_bom.domain.codeowners import owner_for_path as owner_for_path
