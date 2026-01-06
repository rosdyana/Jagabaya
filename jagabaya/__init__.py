"""
Jagabaya - AI-Powered Penetration Testing Automation CLI

A next-generation security assessment tool that leverages multiple LLM providers
(OpenAI, Anthropic, Google, Azure, Ollama, and 100+ more) to orchestrate
intelligent, step-by-step penetration testing workflows.
"""

__version__ = "0.1.0"
__author__ = "Jagabaya Team"
__license__ = "MIT"

from jagabaya.models.config import JagabayaConfig

__all__ = [
    "__version__",
    "JagabayaConfig",
]
