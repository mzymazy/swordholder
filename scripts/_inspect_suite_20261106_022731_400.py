import json, os, traceback
log = open("temp/su.txt", "w", encoding="utf-8")
try:
    p = os.path.join("evidence", "poison", "poison_v2_cases.json")
    log.write("path=%s exists=%s\n" % (p, os.path.exists(p)))
    d = json.load(open(p, encoding="utf-8"))
    cs = d.get("cases") or []
    for c in cs:
        log.write("%s | %s | poison=%s | %s\n" % (c["id"], c["class"], bool(c.get("poison")), str(c.get("poison"))[:100]))
    log.write("n = %d\n" % len(cs))
except Exception:
    traceback.print_exc(file=log)
log.close()
