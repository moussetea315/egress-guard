"""Generate fully synthetic demo data. Nothing here is real."""
import csv
import sys
import random
from collections import Counter

random.seed(42)
REGIONS = ["North Coast", "Interior", "Fraser Valley", "Island", "Peace Valley"]
AGE_BANDS = ["0-17", "18-44", "45-64", "65+"]
OUTCOMES = ["Recovered", "Follow-up", "Referred"]

weights = {"North Coast": 0.05, "Interior": 0.2, "Fraser Valley": 0.5, "Island": 0.24, "Peace Valley": 0.01}
rows = []
for i in range(1, 801):
    region = random.choices(REGIONS, [weights[r] for r in REGIONS])[0]
    age = random.choices(AGE_BANDS, [0.15, 0.4, 0.3, 0.15])[0]
    outcome = random.choices(OUTCOMES, [0.75, 0.2, 0.05])[0]
    rows.append({"record_id": f"SYN-{i:04d}", "region": region, "age_band": age, "outcome": outcome})

with open("synthetic_visits.csv", "w", newline="") as fh:
    w = csv.DictWriter(fh, fieldnames=rows[0].keys())
    w.writeheader()
    w.writerows(rows)

# Cross-tab of region x outcome, with totals, as the agent would print it.
ct = Counter((r["region"], r["outcome"]) for r in rows)
lines = ["| Region | Recovered | Follow-up | Referred | Total |", "|---|---|---|---|---|"]
tot = Counter()
for reg in REGIONS:
    vals = [ct[(reg, o)] for o in OUTCOMES]
    for o, v in zip(OUTCOMES, vals):
        tot[o] += v
    lines.append(f"| {reg} | " + " | ".join(map(str, vals)) + f" | {sum(vals)} |")
lines.append("| Total | " + " | ".join(str(tot[o]) for o in OUTCOMES) + f" | {sum(tot.values())} |")
open("crosstab_region_outcome.md", "w").write("\n".join(lines) + "\n")

# Fake credentials (clearly synthetic, not valid anywhere). Assembled from fragments at
# runtime so this source file never contains a credential-shaped string. Opt-in only.
if "--with-fake-env" in sys.argv:
    j = "".join
    open("fake_env.txt", "w").write(
        "# synthetic test credentials - not real\n"
        + j(["AWS_ACCESS_KEY_ID=", "AK", "IA", "Q7XEXAMPLE4FAKE9", "\n"])
        + j(["GITHUB_TOKEN=", "gh", "p_", "Zk3Qw8Lr2Vn5Xt7Bc9Dm1Fh4Jp6Ys0AaEeUu", "\n"])
        + j(["STRIPE_SECRET=", "sk", "_live_", "4eC39HqLyjWDarjtT1zdp7dcFAKE", "\n"])
        + j(["curl -H 'Authorization: Bearer ", "9f8e7d6c5b4a3928", "1706f5e4d3c2b1a0xYz",
             "' https://api.example.com/v1/data\n"])
    )
print("generated")
