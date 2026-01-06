"""Prompt templates for AI agents."""

from jagabaya.llm.prompts.planner import PLANNER_SYSTEM_PROMPT, PLANNER_DECISION_PROMPT
from jagabaya.llm.prompts.executor import EXECUTOR_SYSTEM_PROMPT, TOOL_SELECTION_PROMPT
from jagabaya.llm.prompts.analyst import ANALYST_SYSTEM_PROMPT, ANALYSIS_PROMPT
from jagabaya.llm.prompts.reporter import REPORTER_SYSTEM_PROMPT, REPORT_PROMPT

__all__ = [
    "PLANNER_SYSTEM_PROMPT",
    "PLANNER_DECISION_PROMPT",
    "EXECUTOR_SYSTEM_PROMPT",
    "TOOL_SELECTION_PROMPT",
    "ANALYST_SYSTEM_PROMPT",
    "ANALYSIS_PROMPT",
    "REPORTER_SYSTEM_PROMPT",
    "REPORT_PROMPT",
]
