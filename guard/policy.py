"""Policy model: what to do when a detector fires."""
import copy
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional

MODES = ("off", "warn", "redact", "approve", "block")   # ascending strictness
_RANK = {m: i for i, m in enumerate(MODES)}
SCOPES = ("args", "result", "reply")

DEFAULTS = {
    "fail_mode": "open",          # what to do if a check itself errors: open | closed
    "max_scan_bytes": 1048576,    # larger strings are not parsed; fail_mode decides (pass+audit | block)
    "audit": {"enabled": True, "path": "~/.hermes/egress-guard/audit.jsonl"},
    "allowlist": [],              # regexes; a match on the flagged text suppresses the finding
    "rules": {
        "secrets": {"mode": "redact", "entropy_threshold": 3.5,
                    "scopes": ["args", "result", "reply"]},
        "smallcell": {"mode": "redact", "threshold": 5, "min_value": 1, "method": "suppress",
                      "complementary": True, "scopes": ["args", "reply"]},
        "microdata": {"mode": "warn", "max_rows": 20, "scopes": ["args", "reply"]},
        "network": {"mode": "approve", "scopes": ["args"], "match": "uploads",
                    "allowed_hosts": ["localhost", "127.0.0.1", "::1"]},
    },
}


# Named starting points. They merge UNDER the user's own settings: DEFAULTS < preset < user.
PRESETS = {
    # Statistical outputs from record-level data: stricter small-cell rule everywhere,
    # and uploads to non-allowlisted hosts are blocked rather than sent for approval.
    "research-data": {
        "rules": {
            "smallcell": {"mode": "redact", "threshold": 10, "scopes": ["args", "result", "reply"]},
            "network": {"mode": "block"},
        },
    },
    # Everyday coding: secrets protection only.
    "dev": {
        "rules": {
            "smallcell": {"mode": "off"},
            "microdata": {"mode": "off"},
            "network": {"mode": "off"},
        },
    },
}


class PolicyError(ValueError):
    pass


@dataclass
class Policy:
    fail_mode: str = "open"
    preset: Optional[str] = None
    max_scan_bytes: int = DEFAULTS["max_scan_bytes"]
    audit_enabled: bool = True
    audit_path: str = DEFAULTS["audit"]["path"]
    allowlist: List[str] = field(default_factory=list)
    rules: Dict[str, dict] = field(default_factory=dict)

    def mode_for(self, rule: str) -> str:
        """Rule names look like 'secret.aws_access_key' or 'smallcell.count'."""
        group = {"secret": "secrets", "smallcell": "smallcell", "microdata": "microdata",
                 "network": "network"}.get(rule.split(".")[0])
        return self.rules.get(group, {}).get("mode", "off")

    def applies(self, group: str, scope: Optional[str]) -> bool:
        """Is this rule group active for 'args' | 'result' | 'reply'? scope=None means any."""
        r = self.rules.get(group, {})
        if r.get("mode", "off") == "off":
            return False
        return scope is None or scope in r.get("scopes", SCOPES)

    @staticmethod
    def stricter(a: str, b: str) -> str:
        return a if _RANK[a] >= _RANK[b] else b


def _merge(base: dict, over: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in (over or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out


def policy_from_dict(data: Optional[dict]) -> Policy:
    data = dict(data or {})
    preset = data.pop("preset", None)
    if preset is not None and (not isinstance(preset, str) or preset not in PRESETS):
        raise PolicyError(f"preset must be one of {sorted(PRESETS)}, got {preset!r}")
    cfg = _merge(_merge(DEFAULTS, PRESETS.get(preset, {})), data)
    if cfg["fail_mode"] not in ("open", "closed"):
        raise PolicyError("fail_mode must be 'open' or 'closed'")
    for group, r in cfg["rules"].items():
        if r.get("mode") not in MODES:
            raise PolicyError(f"rules.{group}.mode must be one of {MODES}, got {r.get('mode')!r}")
    for group, r in cfg["rules"].items():
        bad = [x for x in r.get("scopes", SCOPES) if x not in SCOPES]
        if bad:
            raise PolicyError(f"rules.{group}.scopes has unknown entries {bad}; use {SCOPES}")
    if cfg["rules"]["network"].get("match") not in ("uploads", "any_host"):
        raise PolicyError("rules.network.match must be 'uploads' or 'any_host'")
    mx = cfg["max_scan_bytes"]
    if not isinstance(mx, int) or isinstance(mx, bool) or mx < 1:
        raise PolicyError("max_scan_bytes must be a positive integer (bytes)")
    if cfg["rules"]["smallcell"].get("method") not in ("suppress", "round"):
        raise PolicyError("rules.smallcell.method must be 'suppress' or 'round'")
    mr = cfg["rules"]["microdata"].get("max_rows")
    if not isinstance(mr, int) or isinstance(mr, bool) or mr < 1:
        raise PolicyError("rules.microdata.max_rows must be a positive integer")
    th = cfg["rules"]["smallcell"]["threshold"]
    if not isinstance(th, int) or th < 2:
        raise PolicyError("rules.smallcell.threshold must be an integer >= 2")
    return Policy(fail_mode=cfg["fail_mode"], preset=preset, max_scan_bytes=mx, audit_enabled=bool(cfg["audit"]["enabled"]),
                  audit_path=os.path.expanduser(cfg["audit"]["path"]),
                  allowlist=list(cfg["allowlist"]), rules=cfg["rules"])


def load_policy(path: Optional[str] = None) -> Policy:
    """Load YAML policy if present; otherwise return safe defaults."""
    if path and os.path.exists(path):
        try:
            import yaml
        except ImportError as e:   # pragma: no cover
            raise PolicyError("PyYAML is required to read a policy file") from e
        with open(path, "r", encoding="utf-8") as fh:
            return policy_from_dict(yaml.safe_load(fh) or {})
    return policy_from_dict({})
