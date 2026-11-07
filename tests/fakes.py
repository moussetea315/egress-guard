"""Synthetic, credential-shaped test values.

Every value is assembled at runtime from fragments, so no file in this repository
contains a string that looks like a real credential (secret scanners stay quiet,
and nobody mistakes a fixture for a leak). None of these are valid anywhere.
"""


def j(*parts):
    return "".join(parts)


AWS_KEY = j("AK", "IA", "Q7XEXAMPLE4FAKE9")
GITHUB_TOKEN = j("gh", "p_", "Zk3Qw8Lr2Vn5Xt7Bc9Dm1Fh4Jp6Ys0AaEeUu")
STRIPE_KEY = j("sk", "_live_", "4eC39HqLyjWDarjtT1zdp7dcFAKE")
BEARER_TOKEN = j("9f8e7d6c5b4a3928", "1706f5e4d3c2b1a0xYz")

# Same content as the old static demo_data/fake_env.txt, built on demand instead.
FAKE_ENV = (
    "# synthetic test credentials - not real\n"
    + j("AWS_ACCESS_KEY_ID", "=", AWS_KEY, "\n")
    + j("GITHUB_TOKEN", "=", GITHUB_TOKEN, "\n")
    + j("STRIPE_SECRET", "=", STRIPE_KEY, "\n")
    + j("curl -H 'Authorization: ", "Bearer ", BEARER_TOKEN, "' https://api.example.com/v1/data\n")
)
