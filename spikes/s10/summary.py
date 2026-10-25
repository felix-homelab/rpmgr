# SPDX-License-Identifier: Apache-2.0
# Summarises the raw results of spike S10 runs (README.md).
import json,sys,statistics,os
for d in sys.argv[1:]:
    j=json.load(open(os.path.join(d,"load.json"))); ev=j["events"]
    drain=[e["t"] for e in ev if e["kind"]=="drain"]; dend=[e["t"] for e in ev if e["kind"]=="session_end" and "drain_end" in e["detail"]]
    t0=min(drain) if drain else None; t1=min(dend) if dend else None
    ph={"before":[],"during":[],"after":[]}
    for e in ev:
        if e["kind"]!="bulk": continue
        mb=float(e["detail"].split("= ")[1].split(" MB/s")[0])
        k="before" if (t0 is None or e["t"]<t0) else ("during" if (t1 is None or e["t"]<t1) else "after")
        ph[k].append(mb)
    t=j["tcp"]["total"]
    print(d, "bulk medians", {k:(round(statistics.median(v),1),len(v)) for k,v in ph.items() if v},
      "tcp ok",t["OK"],"refused",t["Refused"],"reset",t["Reset"],"timeout",t["Timeout"],"eof",t["EOF"],"other",t["Other"],
      "udp lost", j["udp"]["long_sent"]-j["udp"]["long_recv"], j["udp"]["short_sent"]-j["udp"]["short_recv"],
      "rehome ms",[e["detail"].split("after ")[1].split(" ms")[0] for e in ev if e["kind"]=="rehomed"],
      "ends",sorted(set(e["detail"].split(": ")[1].split(" (")[0] for e in ev if e["kind"]=="session_end")))
