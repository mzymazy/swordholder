import json, sys, os
sys.stdout.reconfigure(encoding="utf-8")
p = os.path.join("evidence", "poison", "poison_v2_cases.json")
d = json.load(open(p, encoding="utf-8"))
cs = d.get("cases") or []
for c in cs:
    print(c["id"], c["class"], "poison=" + str(bool(c.get("poison"))), str(c.get("poison"))[:90])
print("n =", len(cs))
