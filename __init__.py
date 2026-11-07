"""Egress Guard: policy-driven guard for what leaves a Hermes agent.

Registers three hooks and the /guard command; keep plugin.yaml `provides_hooks` in sync with
this file (Hermes v0.22.2 has no manifest field for commands; its validator does not check them).
"""
import os

# pytest's package collector imports this file without a parent package; skip the
# relative imports in that case. Hermes always loads it as a package.
if __package__:
    from . import adapter
    from .guard.policy import PolicyError, load_policy

_HERE = os.path.dirname(os.path.abspath(__file__))


def _policy_path() -> str:
    for p in (os.environ.get("EGRESS_GUARD_POLICY", ""),
              os.path.expanduser("~/.hermes/egress-guard.yaml"),
              os.path.join(_HERE, "egress-guard.yaml")):
        if p and os.path.exists(p):
            return p
    return ""


def register(ctx):
    path = _policy_path()
    try:
        policy = load_policy(path or None)
    except PolicyError as e:
        # Bad policy file: fall back to safe defaults rather than disabling protection.
        policy = load_policy(None)
        print(f"[egress-guard] invalid policy file ({e}); using built-in defaults")
        path = f"{path} (INVALID, using built-in defaults)"

    def pre_tool_call(tool_name=None, args=None, **kwargs):
        return adapter.pre_tool_call(policy, tool_name=tool_name, args=args, **kwargs)

    def transform_tool_result(tool_name=None, args=None, result=None, **kwargs):
        return adapter.transform_tool_result(policy, tool_name=tool_name, args=args, result=result, **kwargs)

    def transform_llm_output(response_text=None, **kwargs):
        return adapter.transform_llm_output(policy, response_text=response_text, **kwargs)

    ctx.register_hook("pre_tool_call", pre_tool_call)
    ctx.register_hook("transform_tool_result", transform_tool_result)
    ctx.register_hook("transform_llm_output", transform_llm_output)

    def guard_command(raw_args=""):
        return adapter.guard_command(policy, policy_path=path, raw_args=raw_args)

    if hasattr(ctx, "register_command"):     # hooks still work on a host without commands
        ctx.register_command("guard", handler=guard_command,
                             description="Egress Guard: status, report, or check <text> (dry run)",
                             args_hint="[status|report|check <text>]")
