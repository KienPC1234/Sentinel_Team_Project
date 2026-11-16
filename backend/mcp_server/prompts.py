"""
ShieldCall VN - MCP System Prompts
Re-exports canonical Trust Guardrail prompts defined in scripts.shieldcall_mcp
so local and remote MCP servers stay synchronized without duplicated prompt text.
"""
from scripts.shieldcall_mcp import (
    SHIELDCALL_EMERGENCY_PROMPT,
    SHIELDCALL_INVESTIGATOR_PROMPT,
    SHIELDCALL_SENTRY_PROMPT,
)

__all__ = [
    "SHIELDCALL_SENTRY_PROMPT",
    "SHIELDCALL_EMERGENCY_PROMPT",
    "SHIELDCALL_INVESTIGATOR_PROMPT",
]
