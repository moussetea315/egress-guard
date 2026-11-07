"""Egress Guard core engine (Hermes-independent).

Pure-Python checks that decide what to do with text leaving the agent.
The Hermes hook adapter lives in the plugin's top-level __init__.py and
is intentionally thin, so everything here is unit-testable on its own.
"""
from .engine import Decision, inspect_text
from .policy import Policy, load_policy

__all__ = ["Decision", "inspect_text", "Policy", "load_policy"]
