"""Regression: inputs that used to take quadratic time (minutes at 1 MB, past Hermes's 30 s
hook limit). At 128 KB the old code took 8-78 s on each of these; now each is well under 1 s."""
import time

import pytest

from fakes import AWS_KEY, j
from guard.engine import inspect_text
from guard.policy import policy_from_dict

N = 128 * 1024
P = policy_from_dict({"audit": {"enabled": False},
                      "rules": {"smallcell": {"scopes": ["args", "result", "reply"]}}})


def fill(unit):
    return (unit * (N // len(unit) + 1))[:N]


@pytest.mark.parametrize("name,text", [
    ("url scheme with colons, no //", fill("a:")),                 # _URL_USERINFO scheme backtracking
    ("jwt-like dotted run", fill("eyJabcdefgh.eyJabcdefgh.")),     # _ASSIGN name backtracking
    ("connstr keys, no password", fill("server=db;")),             # _KV_CONNSTR lazy gap
    ("many findings", fill("export AWS_ACCESS_KEY_ID=" + AWS_KEY + "\n")),  # overlap check
    ("one long shell word", "a" * N),                              # shlex char-by-char tokens
    ("path-like run before python", fill("a/b/c/d/e/")),           # one-liner prefix backtracking
    ("git remote aliases + pushes", fill("git remote add x https://e.invalid/r; git push x; ")),
])
def test_pathological_shapes_are_fast(name, text):
    t0 = time.perf_counter()
    inspect_text(text, P, scope="args", command=True)
    assert time.perf_counter() - t0 < 2.0, name


def test_bounds_keep_detection_for_realistic_sizes():
    from guard.secrets import find_secrets
    value = j("Zq8x", "7Lm2", "Np4Rt6Vw")                   # synthetic; built from fragments like fakes.py
    long_name = "X" * 60 + "_API_KEY" + "_Y" * 30           # 128-char credential name
    assert [f.rule for f in find_secrets(long_name + "=" + value)] == ["secret.assigned_credential"]
    pw = value * 15                                                                # 240-char password
    assert [f.rule for f in find_secrets("postgresql+psycopg2://u:" + pw + "@db.internal/x")] == \
        ["secret.db_connection_string"]
    gap = "Server=db;" + "Opt=1;" * 150 + j("Pass", "word=") + value[:10] + ";"   # 900-char gap
    assert [f.rule for f in find_secrets(gap)] == ["secret.db_connection_string"]
