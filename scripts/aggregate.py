"""Aggregate raw datasets into sourced, dated CSVs under charts/data/.

Inputs (all in raw/, retrieved 2026-10-25 unless noted):
  nvdcve-2.0-YYYY.json.gz   NVD CVE JSON 2.0 yearly feeds, 2002-2026
                            https://nvd.nist.gov/feeds/json/cve/2.0/  (2026 feed last-modified 2026-10-25 07:15 UTC)
  known_exploited_vulnerabilities.json   CISA KEV, catalogVersion 2026.10.23
                            https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
  osv-{npm,PyPI}-all.zip    OSV bulk exports (MAL-* = OpenSSF malicious-packages)
                            https://osv-vulnerabilities.storage.googleapis.com/<eco>/all.zip
  epss_scores-2026-10-24.csv.gz   FIRST EPSS (model v2026.06.15, score date 2026-10-24)
                            https://epss.empiricalsecurity.com/

Run: python3 scripts/aggregate.py
"""
import csv, glob, gzip, json, zipfile
from collections import Counter, defaultdict

RAW, OUT = "raw", "charts/data"
FIRST_YEAR, LAST_YEAR = 2015, 2026
CUTOFF = "2026-10-25"
RETRIEVED = "2026-10-25"

# CWE -> coarse class (MITRE CWE IDs). Anything else -> "other / unclassified".
CLASS = {
    "memory safety": {"CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-125", "CWE-787", "CWE-416",
                      "CWE-415", "CWE-476", "CWE-190", "CWE-191", "CWE-824", "CWE-843", "CWE-908", "CWE-770"},
    "injection / code exec": {"CWE-77", "CWE-78", "CWE-89", "CWE-94", "CWE-95", "CWE-917", "CWE-1336", "CWE-502",
                              "CWE-434", "CWE-91", "CWE-74"},
    "auth / access control": {"CWE-287", "CWE-288", "CWE-290", "CWE-294", "CWE-306", "CWE-862", "CWE-863",
                              "CWE-284", "CWE-285", "CWE-639", "CWE-269", "CWE-798", "CWE-522", "CWE-521",
                              "CWE-640", "CWE-345", "CWE-347", "CWE-295", "CWE-200"},
    "path traversal / SSRF / file": {"CWE-22", "CWE-23", "CWE-36", "CWE-73", "CWE-918", "CWE-59", "CWE-611"},
    "web client (XSS/CSRF)": {"CWE-79", "CWE-352", "CWE-601"},
}


def cls_of(cwes):
    for name, s in CLASS.items():
        if cwes & s:
            return name
    return "other / unclassified"


def header(f, lines):
    for l in lines:
        f.write(f"# {l}\n")


def best_score(metrics, key):
    """Highest base score across sources (NVD Primary or CNA Secondary) for a CVSS version key list."""
    best = None
    for k in key:
        for m in metrics.get(k, []):
            s = m.get("cvssData", {}).get("baseScore")
            if s is not None and (best is None or s > best):
                best = s
    return best


def nvd():
    yr = defaultdict(Counter)
    qt = defaultdict(Counter)
    cl = defaultdict(Counter)
    for path in sorted(glob.glob(f"{RAW}/nvdcve-2.0-*.json.gz")):
        with gzip.open(path) as f:
            data = json.load(f)
        for item in data["vulnerabilities"]:
            c = item["cve"]
            if c.get("vulnStatus") == "Rejected":
                continue
            pub = c["published"][:10]
            y = int(pub[:4])
            if y < FIRST_YEAR or pub >= CUTOFF:
                continue
            q = (int(pub[5:7]) - 1) // 3 + 1
            m = c.get("metrics", {})
            v3 = best_score(m, ["cvssMetricV31", "cvssMetricV30"])
            v2 = best_score(m, ["cvssMetricV2"])
            v4 = best_score(m, ["cvssMetricV40"])
            any_ = max([s for s in (v4, v3, v2) if s is not None], default=None)
            r = yr[y]
            r["total"] += 1
            qt[(y, q)]["total"] += 1
            if v3 is not None:
                r["v3_scored"] += 1
                r["v3_critical"] += v3 >= 9.0
            if v2 is not None:
                r["v2_scored"] += 1
                r["v2_ge9"] += v2 >= 9.0
            if v4 is not None:
                r["v4_scored"] += 1
                r["v4_critical"] += v4 >= 9.0
            if any_ is None:
                r["unscored"] += 1
            else:
                r["any_ge9"] += any_ >= 9.0
            r["nvd_analyzed"] += c.get("vulnStatus") in ("Analyzed", "Modified")
            cwes = {d["value"] for w in c.get("weaknesses", []) for d in w.get("description", [])
                    if d["value"].startswith("CWE-")}
            cl[y][cls_of(cwes)] += 1
    return yr, qt, cl


def kev():
    d = json.load(open(f"{RAW}/known_exploited_vulnerabilities.json"))
    by = defaultdict(Counter)
    cl = defaultdict(Counter)
    for v in d["vulnerabilities"]:
        y = int(v["dateAdded"][:4])
        by[y]["added"] += 1
        by[y]["ransomware_known"] += v.get("knownRansomwareCampaignUse") == "Known"
        by[y]["cve_year_eq_added_year"] += v["cveID"].split("-")[1] == str(y)
        cl[y][cls_of(set(v.get("cwes", [])))] += 1
    return d["catalogVersion"], d["dateReleased"], by, cl


def osv_mal():
    out = defaultdict(Counter)
    for eco in ("npm", "PyPI"):
        with zipfile.ZipFile(f"{RAW}/osv-{eco}-all.zip") as z:
            for n in z.namelist():
                if not n.startswith("MAL-"):
                    continue
                rec = json.loads(z.read(n))
                p = rec.get("published", "")[:4]
                if p.isdigit():
                    out[int(p)][eco] += 1
    return out


def epss(pub_year):
    by = defaultdict(Counter)
    with gzip.open(f"{RAW}/epss_scores-2026-10-24.csv.gz", "rt") as f:
        next(f)
        for row in csv.DictReader(f):
            y = pub_year.get(row["cve"])
            if y is None:
                continue
            e = float(row["epss"])
            by[y]["scored"] += 1
            by[y]["ge_0_1"] += e >= 0.1
    return by


def pub_dates():
    m = {}
    for path in sorted(glob.glob(f"{RAW}/nvdcve-2.0-*.json.gz")):
        with gzip.open(path) as f:
            for item in json.load(f)["vulnerabilities"]:
                c = item["cve"]
                m[c["id"]] = c["published"][:10]
    return m


def kev_lag(pubd):
    """Days from NVD publication to KEV dateAdded, for CVEs published 2022+ (after KEV's 2021 backfill)."""
    import datetime as dt, statistics
    d = json.load(open(f"{RAW}/known_exploited_vulnerabilities.json"))
    by = defaultdict(list)
    for v in d["vulnerabilities"]:
        p = pubd.get(v["cveID"])
        if not p or int(p[:4]) < 2022:
            continue
        lag = (dt.date.fromisoformat(v["dateAdded"]) - dt.date.fromisoformat(p)).days
        by[int(p[:4])].append(lag)
    rows = []
    for y in sorted(by):
        L = by[y]
        rows.append([y, len(L), statistics.median(L), sum(x <= 0 for x in L), sum(x <= 7 for x in L),
                     round(100 * sum(x <= 7 for x in L) / len(L), 1)])
    return rows


def pub_years():
    m = {}
    for path in sorted(glob.glob(f"{RAW}/nvdcve-2.0-*.json.gz")):
        with gzip.open(path) as f:
            for item in json.load(f)["vulnerabilities"]:
                c = item["cve"]
                if c.get("vulnStatus") != "Rejected":
                    m[c["id"]] = int(c["published"][:4])
    return m


def main():
    yr, qt, ncl = nvd()
    src_nvd = [f"source: NVD CVE JSON 2.0 yearly feeds https://nvd.nist.gov/feeds/json/cve/2.0/ (retrieved {RETRIEVED})",
               "bucketed by 'published' date; Rejected records excluded; 2026 is partial (to 2026-10-24)",
               "scores: highest base score across NVD Primary and CNA Secondary metrics for that CVSS version"]
    with open(f"{OUT}/cves_per_year.csv", "w", newline="") as f:
        header(f, src_nvd)
        w = csv.writer(f)
        cols = ["total", "v3_scored", "v3_critical", "v2_scored", "v2_ge9", "v4_scored", "v4_critical",
                "any_ge9", "unscored", "nvd_analyzed"]
        w.writerow(["year"] + cols + ["v3_critical_share_pct", "v2_ge9_share_pct", "unscored_pct"])
        for y in sorted(yr):
            r = yr[y]
            pct = lambda a, b: round(100 * r[a] / r[b], 1) if r[b] else ""
            w.writerow([y] + [r[c] for c in cols] +
                       [pct("v3_critical", "v3_scored"), pct("v2_ge9", "v2_scored"), pct("unscored", "total")])
    with open(f"{OUT}/cves_per_quarter.csv", "w", newline="") as f:
        header(f, src_nvd)
        w = csv.writer(f)
        w.writerow(["year", "quarter", "total"])
        for (y, q) in sorted(qt):
            w.writerow([y, q, qt[(y, q)]["total"]])
    classes = list(CLASS) + ["other / unclassified"]
    with open(f"{OUT}/cve_class_mix_per_year.csv", "w", newline="") as f:
        header(f, src_nvd + ["class = coarse grouping of NVD/CNA CWE IDs, see CLASS in scripts/aggregate.py"])
        w = csv.writer(f)
        w.writerow(["year"] + classes)
        for y in sorted(ncl):
            w.writerow([y] + [ncl[y][c] for c in classes])

    ver, rel, kby, kcl = kev()
    src_kev = [f"source: CISA KEV catalog JSON catalogVersion {ver} dateReleased {rel} (retrieved {RETRIEVED})",
               "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
               "bucketed by dateAdded; KEV began 2021-11-03 with a backfill of older CVEs; 2026 partial (to 2026-10-23)"]
    with open(f"{OUT}/kev_additions_per_year.csv", "w", newline="") as f:
        header(f, src_kev)
        w = csv.writer(f)
        w.writerow(["year", "added", "ransomware_known", "cve_year_eq_added_year"])
        for y in sorted(kby):
            w.writerow([y, kby[y]["added"], kby[y]["ransomware_known"], kby[y]["cve_year_eq_added_year"]])
    with open(f"{OUT}/kev_class_mix_per_year.csv", "w", newline="") as f:
        header(f, src_kev + ["class = coarse grouping of KEV 'cwes' field, see CLASS in scripts/aggregate.py"])
        w = csv.writer(f)
        w.writerow(["year"] + classes)
        for y in sorted(kcl):
            w.writerow([y] + [kcl[y][c] for c in classes])

    mal = osv_mal()
    with open(f"{OUT}/malicious_packages_per_year.csv", "w", newline="") as f:
        header(f, [f"source: OSV bulk exports, MAL-* records (OpenSSF malicious-packages) (retrieved {RETRIEVED})",
                   "https://osv-vulnerabilities.storage.googleapis.com/{npm,PyPI}/all.zip",
                   "bucketed by OSV 'published'; counts reports not incidents (spam/typosquat floods inflate some years)",
                   "malicious packages normally receive NO CVE, so they are invisible in NVD counts"])
        w = csv.writer(f)
        w.writerow(["year", "npm", "PyPI"])
        for y in sorted(mal):
            w.writerow([y, mal[y]["npm"], mal[y]["PyPI"]])

    with open(f"{OUT}/kev_lag_by_pub_year.csv", "w", newline="") as f:
        header(f, src_kev + [src_nvd[0],
                   "lag = KEV dateAdded minus NVD published date (days); a LISTING lag, not time-to-exploit",
                   "CVEs published 2022+ only; recent years are right-censored (late listings still to come)"])
        w = csv.writer(f)
        w.writerow(["pub_year", "n_in_kev", "median_lag_days", "listed_on_or_before_pub", "listed_within_7d",
                    "within_7d_pct"])
        w.writerows(kev_lag(pub_dates()))

    ep = epss(pub_years())
    with open(f"{OUT}/epss_by_pub_year.csv", "w", newline="") as f:
        header(f, ["source: FIRST EPSS scores model v2026.06.15, score_date 2026-10-24 (retrieved 2026-10-25)",
                   "https://epss.empiricalsecurity.com/epss_scores-2026-10-24.csv.gz ; joined to NVD published year",
                   "NOTE: these are today's scores for CVEs of each year, not historical scores"])
        w = csv.writer(f)
        w.writerow(["year", "scored", "epss_ge_0_1", "share_pct"])
        for y in range(FIRST_YEAR, LAST_YEAR + 1):
            r = ep[y]
            w.writerow([y, r["scored"], r["ge_0_1"], round(100 * r["ge_0_1"] / r["scored"], 2) if r["scored"] else ""])


if __name__ == "__main__":
    main()
