from fakes import AWS_KEY, BEARER_TOKEN, GITHUB_TOKEN, STRIPE_KEY, j
from guard.secrets import find_secrets


def rules(text):
    return {f.rule for f in find_secrets(text)}


def test_known_formats():
    assert "secret.aws_access_key" in rules("key " + AWS_KEY + " here")
    assert "secret.github_token" in rules(GITHUB_TOKEN)
    assert "secret.stripe_key" in rules(STRIPE_KEY)
    assert "secret.private_key_block" in rules(
        j("-----BEGIN ", "RSA PRIVATE KEY-----\nMIIabc\n-----END ", "RSA PRIVATE KEY-----"))


def test_bearer_keeps_scheme_masks_token():
    f = find_secrets("Authorization: Bearer " + BEARER_TOKEN)[0]
    assert f.rule == "secret.bearer_token"
    assert BEARER_TOKEN not in f.masked


def test_assignment_with_credential_name():
    assert "secret.assigned_credential" in rules(j("db_password=", "Tr0ub4dor&3xQ9"))


def test_placeholders_and_plain_prose_not_flagged():
    assert not find_secrets("api_key=${API_KEY}")
    assert not find_secrets("password=changeme")
    assert not find_secrets("token=xxxxxxxx")
    assert not find_secrets("The token count was reported in the summary table.")
    assert not find_secrets("Meeting notes: discussed secret santa plans for Friday.")


def test_no_raw_value_in_findings():
    text = "GITHUB_TOKEN=" + GITHUB_TOKEN
    raw = GITHUB_TOKEN[4:]
    for f in find_secrets(text):
        assert raw not in f.masked
        assert raw not in (f.reason + (f.replacement or ""))


# ---- formats added in item 3 (all values synthetic) --------------------------------
import pytest


@pytest.mark.parametrize("text,rule,secret", [
    (j("hf", "_abcdefghijklmnopqrstuvwxyzABCD"), "secret.huggingface_token", None),
    (j("npm", "_abcdefghijklmnopqrstuvwxyz0123456789"), "secret.npm_token", None),
    (j("glpat", "-abcdefghij0123456789"), "secret.gitlab_token", None),
    (j("SG", ".abcdefghijklmnop.qrstuvwxyz0123456789"), "secret.sendgrid_key", None),
    (j("bot 123456789:", "AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsawQ ok"), "secret.telegram_bot_token", None),
    (j("https://admin:", "hunter2pass@db.example.com/x"), "secret.url_password", "hunter2pass"),
    (j("git+https://bob:", "tok12345@git.example.com/r.git"), "secret.url_password", "tok12345"),
    (j("postgres://app:", "S3cr3tPassw0rd@db.internal:5432/prod"), "secret.db_connection_string", "S3cr3tPassw0rd"),
    (j("mongodb+srv://u:", "pw12345@c0.example.net/db"), "secret.db_connection_string", "pw12345"),
    (j("postgresql+psycopg2://u:", "abcd1234@h/db"), "secret.db_connection_string", "abcd1234"),
    (j("jdbc:mysql://root:", "Pa55word@10.0.0.2/x"), "secret.db_connection_string", "Pa55word"),
    (j("redis://:", "Sup3rS3cret@cache:6379/0"), "secret.db_connection_string", "Sup3rS3cret"),
    (j("Server=db1;Database=app;User Id=sa;Password=", "Xy7pQ2zz;"), "secret.db_connection_string", "Xy7pQ2zz"),
    (j("Data Source=db1;Initial Catalog=x;Pwd=", "Q9w8e7r6;"), "secret.db_connection_string", "Q9w8e7r6"),
])
def test_new_formats(text, rule, secret):
    fs = find_secrets(text)
    assert [f.rule for f in fs] == [rule]
    f = fs[0]
    if secret:   # only the password is redacted; user and host stay readable
        assert text[f.start:f.end] == secret
    assert text[f.start:f.end] not in f.masked


def test_url_password_keeps_user_and_host_in_redacted_text():
    from guard.engine import inspect_text
    from guard.policy import policy_from_dict
    d = inspect_text(j("psql postgres://app:", "S3cr3tPassw0rd@db.internal:5432/prod"),
                     policy_from_dict({"audit": {"enabled": False}}))
    assert d.redacted_text == "psql postgres://app:[REDACTED:db_connection_string]@db.internal:5432/prod"


@pytest.mark.parametrize("text", [
    "postgres://user:password@localhost/db",       # documentation placeholder
    "postgres://u:${DB_PASS}@h/db",                 # env reference
    "https://user:****@host/x",                     # already masked
    "ssh://git@github.com/org/repo.git",            # user, no password
    "git@github.com:org/repo.git",
    "see http://example.com:8080/path and mail foo@bar.com",
    "http://[::1]:8000/health",
    "SG.Name.Here is a sentence",                   # too short for SendGrid
    "hf_hub_download(repo_id='x')",                 # function name, not a token
    "npm_config_cache=/tmp/npm",
    "time 12:30:45, ratio 16:9, port 127.0.0.1:8080",
    "q8Zr2LmN4pXw7Ty1Vb6Kc3Jd9",                    # bare high-entropy: deliberately not flagged
])
def test_new_rules_no_false_positives(text):
    assert find_secrets(text) == []


@pytest.mark.parametrize("text", [
    'f"http://{self.auth[0]}:{self.auth[1]}@127.0.0.1:{self.port}"',   # f-string template
    '"https://%s:%s@%s" % (u, p, h)',
    "cvs -d cvs://:pserver:anoncvs@sources.example.org:/cvs/src co x",  # CVS pserver syntax
])
def test_url_rule_skips_templates_and_cvs(text):
    assert not [f for f in find_secrets(text) if f.rule in ("secret.url_password",
                                                            "secret.db_connection_string")]


# ---- Hermes's own redaction sentinels (item 1)
# Exact shape of Hermes v0.22.2 read_file output for a synthetic .env (captured 2026-11-07):
# prefix-matched keys come back as «redacted:<prefix>…»; the other two stay raw.
AWS_SECRET = j("wJal", "rXUtnFEMI/K7MDENG/bPxRfiCYFAKEKEY99")
DB_PASSWORD = j("s3cr", "etPa55word!")
READ_FILE_CONTENT = ("1|# synthetic\n2|AWS_ACCESS_KEY_ID=«redacted:AKIA…»\n"
                     "3|AWS_SECRET_ACCESS_KEY=" + AWS_SECRET + "\n4|GITHUB_TOKEN=«redacted:ghp_…»\n"
                     "5|DB_PASSWORD=" + DB_PASSWORD + "\n6|REGION=us-west-2")


def test_hermes_sentinels_not_reflagged_but_raw_values_still_caught():
    fs = find_secrets(READ_FILE_CONTENT)
    flagged = [READ_FILE_CONTENT[f.start:f.end] for f in fs]
    assert flagged == [AWS_SECRET, DB_PASSWORD]
    assert not any("«" in v for v in flagged)


def test_all_hermes_sentinel_shapes_skipped():
    for s in ("«redacted:sk-ant-…»", "«redacted:github_pat_…»", "«redacted-secret»", "«redacted-vault-secret»"):
        assert find_secrets("API_TOKEN=" + s + "\napi_key: " + s) == [], s


def test_full_key_inside_guillemets_is_still_flagged():
    # Only Hermes's exact shapes are skipped; a real key wrapped to look like one is not.
    assert "secret.aws_access_key" in rules("«redacted:" + AWS_KEY + "…»")
    assert "secret.assigned_credential" in rules("TOKEN=«" + DB_PASSWORD + "»")


def test_read_file_payload_through_adapter_keeps_sentinels(adapter):
    import json
    from guard.policy import policy_from_dict
    pol = policy_from_dict({"audit": {"enabled": False}})
    payload = json.dumps({"content": READ_FILE_CONTENT, "total_lines": 6, "file_size": 212,
                          "truncated": False, "is_binary": False, "is_image": False, "not_found": False},
                         ensure_ascii=False)
    out = json.loads(adapter.transform_tool_result(pol, tool_name="read_file", result=payload))
    c = out["content"]
    assert "«redacted:AKIA…»" in c and "«redacted:ghp_…»" in c
    assert AWS_SECRET not in c and DB_PASSWORD not in c
    assert c.count("[REDACTED:credential]") == 2
