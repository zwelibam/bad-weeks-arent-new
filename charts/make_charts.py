"""Charts for OVERVIEW.md — Tufte style
(TUFTE_RC, range-frame axes, direct labels, no legends, no pies, no dual y-axes).

Data: charts/data/*.csv (each file carries a '#' source/date header; built by scripts/aggregate.py
except time_to_exploit_reports.csv and black_weeks_timeline.csv, which are hand-compiled and sourced).
Run from the project root:  python3 charts/make_charts.py   -> charts/*.png + charts/*.svg
"""
import csv
import os
from datetime import date

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

TUFTE_RC = {
    "font.family": "serif",
    "font.serif": ["Palatino", "Palatino Linotype", "Georgia", "DejaVu Serif"],
    "font.size": 12,
    "figure.facecolor": "#fffff8",
    "figure.figsize": (9, 6),
    "figure.dpi": 150,
    "axes.facecolor": "#fffff8",
    "axes.edgecolor": "#cccccc",
    "axes.linewidth": 0.5,
    "axes.labelcolor": "#666666",
    "axes.labelsize": 12,
    "axes.titlesize": 18,
    "axes.titleweight": "normal",
    "axes.titlepad": 16,
    "axes.spines.top": False,
    "axes.spines.right": False,
    "axes.grid": False,
    "xtick.color": "#999999",
    "ytick.color": "#999999",
    "xtick.labelsize": 11,
    "ytick.labelsize": 11,
    "xtick.direction": "in",
    "ytick.direction": "in",
    "xtick.major.size": 3,
    "ytick.major.size": 3,
    "xtick.major.width": 0.5,
    "ytick.major.width": 0.5,
    "lines.linewidth": 1.5,
    "lines.markersize": 3,
    "legend.frameon": False,
    "legend.fontsize": 11,
    "grid.color": "#eeeeee",
    "grid.linewidth": 0.5,
    "grid.alpha": 0.5,
    "savefig.facecolor": "#fffff8",
    "savefig.bbox": "tight",
    "savefig.pad_inches": 0.2,
}
plt.rcParams.update(TUFTE_RC)

C = {
    "text": "#111111",
    "text2": "#666666",
    "text3": "#999999",
    "axis": "#cccccc",
    "series": "#666666",
    "highlight": "#e41a1c",
    "cat": ["#4e79a7", "#f28e2b", "#e15759", "#76b7b2"],
}
HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")


def tufte_axes(ax, x_data, y_data):
    """Range-frame: axis lines span only the actual data range."""
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["bottom"].set_bounds(min(x_data), max(x_data))
    ax.spines["left"].set_bounds(min(y_data), max(y_data))
    ax.tick_params(direction="in", length=3, width=0.5)
    return ax


def direct_label(ax, x, y, label, color="#111", offset=(8, 0)):
    """Direct label at the last data point — replaces legend."""
    ax.annotate(label, xy=(x[-1], y[-1]), xytext=offset, textcoords="offset points",
                fontsize=12, color=color, fontfamily="serif", va="center")


def annotate_point(ax, x, y, text, color="#333", dy=24, ha="center"):
    """Annotate a notable data point with a hairline."""
    ax.annotate(text, xy=(x, y), xytext=(0, dy), textcoords="offset points", fontsize=11,
                fontstyle="italic", color=color, fontfamily="serif", ha=ha,
                arrowprops=dict(arrowstyle="-", color="#cccccc", lw=0.5))


def source_note(fig, text):
    fig.text(0.0, -0.02, text, fontsize=9, color="#aaaaaa", family="sans-serif", ha="left", va="top", wrap=True)


def read(name):
    with open(os.path.join(DATA, name)) as f:
        return list(csv.DictReader(line for line in f if not line.startswith("#")))


def save(fig, name):
    for ext in ("png", "svg"):
        fig.savefig(os.path.join(HERE, f"{name}.{ext}"))
    plt.close(fig)


# 1 — CVEs published per year -------------------------------------------------------------
def cves_per_year():
    rows = read("cves_per_year.csv")
    yrs = [int(r["year"]) for r in rows]
    tot = [int(r["total"]) for r in rows]
    fig, ax = plt.subplots()
    ax.plot(yrs[:-1], tot[:-1], color=C["series"])
    ax.plot(yrs[-2:], tot[-2:], color=C["highlight"])
    ax.plot(yrs[-1], tot[-1], "o", color=C["highlight"], markersize=4)
    # Linear annualisation of 2026 YTD (to 24 Oct = day 297) — an ESTIMATE, drawn as a hollow marker only.
    est = round(tot[-1] * 365 / 297)
    ax.plot(yrs[-1], est, "o", markerfacecolor="none", markeredgecolor=C["highlight"], markersize=5)
    ax.annotate(f"{est:,} if the 2026 pace holds (estimate)", xy=(yrs[-1], est), xytext=(-8, 0),
                textcoords="offset points", ha="right", va="center", fontsize=11, fontstyle="italic", color=C["text2"])
    ax.annotate(f"{tot[-1]:,}\n2026 to 24 Oct", xy=(yrs[-1], tot[-1]), xytext=(8, 0), textcoords="offset points",
                va="center", fontsize=12, color=C["highlight"])
    for y in (2015, 2017, 2021, 2024, 2025):
        v = tot[yrs.index(y)]
        ax.annotate(f"{v:,}", xy=(y, v), xytext=(0, 8), textcoords="offset points", ha="center",
                    fontsize=11, color=C["text2"])
    ax.set_title("CVEs published per year, 2015–2026", loc="left")
    ax.set_xticks(yrs)
    ax.set_xticklabels([str(y) if y % 2 else "" for y in yrs])
    ax.set_ylim(0, est * 1.05)
    ax.set_yticks([0, 20000, 40000, 60000, 80000, 100000])
    ax.set_yticklabels(["0", "20k", "40k", "60k", "80k", "100k"])
    tufte_axes(ax, yrs, [0, est])
    source_note(fig, "Source: NVD CVE JSON 2.0 yearly feeds, retrieved 2026-10-25; by published date, Rejected excluded. "
                     "Hollow marker = linear annualisation (estimate).")
    save(fig, "cves_per_year")


# 2 — KEV additions per year --------------------------------------------------------------
def kev_per_year():
    rows = read("kev_additions_per_year.csv")
    yrs = [int(r["year"]) for r in rows]
    add = [int(r["added"]) for r in rows]
    same = [int(r["cve_year_eq_added_year"]) for r in rows]
    fig, ax = plt.subplots(figsize=(9, 5))
    ax.bar(yrs, add, width=0.55, color="#bbbbbb")
    ax.bar(yrs, same, width=0.55, color=C["series"])
    for x, a, s in zip(yrs, add, same):
        ax.text(x, a + 8, f"{a}", ha="center", fontsize=12, color=C["text"])
        ax.text(x, s / 2, f"{s}", ha="center", va="center", fontsize=10, color="#fffff8")
    ax.text(2021, add[0] + 55, "catalogue opens 3 Nov 2021\nwith a backfill of older CVEs", ha="center",
            fontsize=10.5, fontstyle="italic", color=C["text2"])
    ax.text(2026, add[-1] + 55, "to 23 Oct", ha="center", fontsize=10.5, fontstyle="italic", color=C["text2"])
    ax.text(2026.42, same[-1] / 2, "dark: CVE from the\nsame year as listing", fontsize=10.5, color=C["text2"], va="center")
    ax.set_title("CISA KEV additions per year", loc="left")
    ax.set_xticks(yrs)
    ax.set_yticks([])
    ax.spines["left"].set_visible(False)
    ax.spines["bottom"].set_bounds(yrs[0] - 0.3, yrs[-1] + 0.3)
    ax.set_xlim(2020.5, 2027.4)
    ax.set_ylim(0, 680)
    source_note(fig, "Source: CISA KEV catalog JSON v2026.10.23, retrieved 2026-10-25; by dateAdded.")
    save(fig, "kev_per_year")


# 3 — Critical share ----------------------------------------------------------------------
def critical_share():
    rows = read("cves_per_year.csv")
    fig, ax = plt.subplots()
    v3 = [(int(r["year"]), float(r["v3_critical_share_pct"])) for r in rows if int(r["year"]) >= 2016]
    v2 = [(int(r["year"]), float(r["v2_ge9_share_pct"])) for r in rows if int(r["year"]) <= 2021]
    un = [(int(r["year"]), float(r["unscored_pct"])) for r in rows if int(r["year"]) >= 2023]
    for series, col, lab in ((v3, C["series"], f"CVSS v3 ≥ 9.0: {v3[-1][1]:.1f}% in 2026\n(share of v3-scored)"),
                             (v2, "#bbbbbb", "CVSS v2 ≥ 9.0\n(NVD stopped v2 in 2022)")):
        x, y = zip(*series)
        ax.plot(x, y, color=col)
        direct_label(ax, x, y, lab, color=col if col != "#bbbbbb" else C["text3"])
    x, y = zip(*un)
    ax.plot(x, y, color=C["highlight"], linestyle=(0, (2, 2)), linewidth=1)
    direct_label(ax, x, y, "no CVSS score at all\n(share of all CVEs)", color=C["highlight"])
    for yr, val in (v3[0], v3[6]):
        ax.annotate(f"{val:.1f}%", xy=(yr, val), xytext=(0, 8), textcoords="offset points", ha="center",
                    fontsize=11, color=C["text2"])
    ax.annotate(f"{v2[0][1]:.1f}%", xy=v2[0], xytext=(0, 8), textcoords="offset points", ha="center",
                fontsize=11, color=C["text3"])
    ax.set_title("Share of CVEs rated critical, 2015–2026", loc="left")
    ax.set_xticks(range(2015, 2027))
    ax.set_xticklabels([str(y) if y % 2 else "" for y in range(2015, 2027)])
    ax.set_ylim(0, 25)
    ax.set_yticks([0, 5, 10, 15, 20, 25])
    ax.set_yticklabels([f"{t}%" for t in (0, 5, 10, 15, 20, 25)])
    tufte_axes(ax, [2015, 2026], [0, 25])
    source_note(fig, "Source: NVD CVE JSON 2.0 feeds, retrieved 2026-10-25. Highest base score across NVD and CNA metrics. "
                     "2026 to 24 Oct.")
    save(fig, "critical_share")


# 4 — Time to exploit: two stacked panels sharing x (no dual axis) ------------------------
def time_to_exploit():
    tte = read("time_to_exploit_reports.csv")
    lag = read("kev_lag_by_pub_year.csv")
    fig, (a1, a2, a3) = plt.subplots(3, 1, figsize=(9, 10), sharex=True,
                                     gridspec_kw={"height_ratios": [1.3, 1, 1], "hspace": 0.35})
    m = [r for r in tte if r["metric"] == "mandiant_tte_days"]
    x = [float(r["period_mid_year"]) for r in m]
    y = [float(r["value"]) for r in m]
    a1.plot(x[:4], y[:4], color=C["series"])
    a1.plot(x[3:], y[3:], color=C["series"], linestyle=(0, (2, 2)))  # 2024 gap in the series
    a1.plot(x, y, "o", color=C["series"], markersize=4)
    a1.plot(x[-1], y[-1], "o", color=C["highlight"], markersize=5)
    a1.axhline(0, color=C["axis"], lw=0.5)
    for xi, yi, lab in zip(x, y, [r["period_label"] for r in m]):
        a1.annotate(f"{yi:+.0f} d" if yi < 0 else f"{yi:.0f} d", xy=(xi, yi), xytext=(6, 6),
                    textcoords="offset points", fontsize=12, color=C["highlight"] if yi < 0 else C["text"])
        a1.annotate(lab, xy=(xi, yi), xytext=(-6, -14), ha="right", textcoords="offset points", fontsize=9.5, color=C["text3"])
    a1.text(2024.0, 14, "no 2024 figure\npublished", fontsize=10, fontstyle="italic", color=C["text3"], ha="center")
    a1.text(2018.3, -12, "below zero = exploited before a patch exists", fontsize=10.5, fontstyle="italic",
            color=C["text2"])
    a1.set_title("Time to exploit is now negative", loc="left")
    a1.set_ylabel("Mandiant mean TTE (days)")
    a1.set_ylim(-20, 72)
    a1.set_yticks([0, 20, 40, 60])
    tufte_axes(a1, [2018.5, 2025], [-7, 63])

    v = [r for r in tte if r["metric"] == "vulncheck_exploited_on_or_before_disclosure_pct"]
    vx = [float(r["period_mid_year"]) for r in v]
    vy = [float(r["value"]) for r in v]
    order = sorted(range(len(vx)), key=lambda i: vx[i])
    a2.plot([vx[i] for i in order], [vy[i] for i in order], "o", color=C["series"], markersize=4)
    for i in order:
        lab = {2024.0: "2024", 2025.25: "1H 2025", 2025.0: "2025"}[vx[i]]
        a2.annotate(f"{vy[i]:.1f}% ({lab})", xy=(vx[i], vy[i]), xytext=(-6 if vx[i] == 2025.0 else 6, 0),
                    ha="right" if vx[i] == 2025.0 else "left", textcoords="offset points", va="center",
                    fontsize=11, color=C["text"])
    a2.set_ylabel("VulnCheck: KEVs exploited\non/before disclosure day")
    a2.set_ylim(15, 40)
    a2.set_yticks([20, 25, 30, 35])
    a2.set_yticklabels(["20%", "25%", "30%", "35%"])
    tufte_axes(a2, [2024, 2025.25], [20, 35])

    lx = [int(r["pub_year"]) for r in lag]
    ly = [float(r["median_lag_days"]) for r in lag]
    a3.plot(lx, ly, color=C["series"])
    a3.plot(lx[-1], ly[-1], "o", color=C["highlight"], markersize=4)
    for xi, yi, r in zip(lx, ly, lag):
        a3.annotate(f"{yi:.0f} d · {float(r['within_7d_pct']):.0f}% ≤7 d", xy=(xi, yi), xytext=(0, 8),
                    textcoords="offset points", ha="center", fontsize=10.5, color=C["text2"])
    a3.set_ylabel("median days from CVE\npublication to KEV listing")
    a3.set_ylim(0, 32)
    a3.set_xticks(range(2018, 2027, 2))
    tufte_axes(a3, [2018.5, 2026], [0, 24])
    a3.spines["bottom"].set_bounds(2018.5, 2026)
    source_note(fig, "Sources: Mandiant/Google TTE 2023 (2024-10-15) and M-Trends 2026 (−7 d is Mandiant's estimate); VulnCheck "
                     "1H-2025 and State of Exploitation 2026; bottom panel computed from NVD + CISA KEV, retrieved 2026-10-25 "
                     "(listing lag, not exploitation; 2026 right-censored). Series differ in method — compare within a panel only.")
    save(fig, "time_to_exploit")


# 5 — Black-weeks timeline strip ---------------------------------------------------------
CLASS_COLOR = {"supply chain": C["cat"][1], "memory safety": C["cat"][0], "identity": C["cat"][3],
               "AI-assisted": C["cat"][2]}


def class_key(c):
    c = c.lower()
    if "ai" in c.split() or c.startswith("ai") or "ai-assisted" in c or "ai-discovered" in c:
        return "AI-assisted"
    if "supply chain" in c:
        return "supply chain"
    if "identity" in c or "oauth" in c:
        return "identity"
    if "memory" in c:
        return "memory safety"
    return None


def to_year(d):
    dd = date.fromisoformat(d)
    return dd.year + (dd.timetuple().tm_yday - 1) / 365.25


def black_weeks_timeline():
    rows = read("black_weeks_timeline.csv")
    fig, ax = plt.subplots(figsize=(10, 9))
    n = len(rows)
    for i, r in enumerate(rows):
        yv = n - 1 - i
        d = to_year(r["disclosure"])
        is_bo = r["id"] == "blackoctober"
        col = C["highlight"] if is_bo else C["series"]
        if r["first_exploitation"]:
            e = to_year(r["first_exploitation"])
            if e < d:
                ax.plot([e, d], [yv, yv], color=C["highlight"], lw=2.2, solid_capstyle="butt", alpha=0.9)
        ax.plot(d, yv, "o", color=col, markersize=5 if is_bo else 4)
        k = class_key(r["class"])
        ax.text(2013.6, yv, r["label"].split(" (")[0].replace(" — CISA ED 26-03", "").replace(" → ", " / "), ha="right", va="center",
                fontsize=10.5, color=C["highlight"] if is_bo else C["text"])
        lag = r["lag_days"]
        note = (f"{int(lag):+d} d" if lag else "")
        cls = r["class"].split(" (")[0].replace(" → ", " to ")
        if r["id"] == "blackoctober":
            cls = "five classes at once"
        ax.text(2026.95, yv, f"{note:>6}  {cls}", va="center", fontsize=9.5,
                color=CLASS_COLOR.get(k, C["text3"]), family="serif")
    ax.set_xlim(2013.7, 2026.9)
    ax.set_ylim(-0.8, n - 0.2)
    ax.set_yticks([])
    ax.spines["left"].set_visible(False)
    ax.set_xticks(range(2014, 2027))
    ax.set_xticklabels([str(y) if y % 2 == 0 else "" for y in range(2014, 2027)])
    ax.spines["bottom"].set_bounds(2014, 2026.82)
    ax.set_title("Black weeks, 2014–2026: dot = public disclosure,\nred bar = exploitation before disclosure",
                 loc="left", fontsize=16)
    ax.text(2026.95, n - 0.1, "lag    class", fontsize=9.5, color=C["text3"], va="bottom")
    source_note(fig, "Source: charts/data/black_weeks_timeline.csv (compiled 2026-10-25 from CISA, Mandiant/GTIG, Volexity, "
                     "Cloudflare, SolarWinds SEC 8-K, Orca, Anthropic and others; see 'sources' column). Lag = first reported "
                     "exploitation minus disclosure; month-level for SolarWinds and GTG-1002.")
    save(fig, "black_weeks_timeline")


# 6 — Malicious packages (OSV MAL-*) — small multiples, shared log y ---------------------
def malicious_packages():
    rows = [r for r in read("malicious_packages_per_year.csv") if int(r["year"]) >= 2022]
    yrs = [int(r["year"]) for r in rows]
    fig, axes = plt.subplots(1, 2, figsize=(10, 4.8), sharey=True)
    for ax, eco in zip(axes, ("npm", "PyPI")):
        v = [max(int(r[eco]), 1) for r in rows]
        ax.plot(yrs, v, color=C["series"])
        ax.plot(yrs[-1], v[-1], "o", color=C["highlight"], markersize=4)
        for x, y in zip(yrs, v):
            ax.annotate(f"{y:,}", xy=(x, y), xytext=(0, 7), textcoords="offset points", ha="center",
                        fontsize=10.5, color=C["text2"])
        ax.set_yscale("log")
        ax.set_title(eco, loc="left", fontsize=14)
        ax.set_xticks(yrs)
        ax.set_xticklabels([str(y) if y != 2026 else "2026*" for y in yrs])
        ax.set_ylim(5, 600000)
        ax.set_yticks([10, 100, 1000, 10000, 100000])
        ax.set_yticklabels(["10", "100", "1k", "10k", "100k"])
        ax.minorticks_off()
        tufte_axes(ax, yrs, [10, 300000])
    axes[0].annotate("2025: spam/typosquat floods\ninflate the count", xy=(2025, 191420), xytext=(-200, -6),
                     textcoords="offset points", fontsize=10.5, fontstyle="italic", color=C["text2"],
                     arrowprops=dict(arrowstyle="-", color="#cccccc", lw=0.5))
    fig.suptitle("Malicious-package reports per year (OSV MAL-*) — none of these get a CVE", x=0.06, y=1.04, ha="left",
                 fontsize=16, color=C["text"])
    source_note(fig, "Source: OSV bulk exports npm/PyPI all.zip (OpenSSF malicious-packages), retrieved 2026-10-25; "
                     "by OSV 'published'. Counts are reports, not incidents. *2026 to 25 Oct. Log scale.")
    save(fig, "malicious_packages")


# 7 — Class mix: small multiples, all CVEs vs KEV, shared y ------------------------------
def class_mix():
    nv = read("cve_class_mix_per_year.csv")
    kv = read("kev_class_mix_per_year.csv")
    classes = [c for c in nv[0] if c != "year"]
    fig, axes = plt.subplots(2, 3, figsize=(12, 7.5), sharex=True, sharey=True)
    for ax, c in zip(axes.flat, classes):
        for rows, col, lab in ((nv, "#bbbbbb", "all CVEs"), (kv, C["series"], "KEV")):
            yrs = [int(r["year"]) for r in rows]
            tot = [sum(int(r[k]) for k in classes) for r in rows]
            sh = [100 * int(r[c]) / t for r, t in zip(rows, tot)]
            ax.plot(yrs, sh, color=col, lw=1.5)
            ax.annotate(f"{lab} {sh[-1]:.0f}%", xy=(yrs[-1], sh[-1]), xytext=(4, 0), textcoords="offset points",
                        fontsize=10, color=col if col != "#bbbbbb" else C["text3"], va="center")
        ax.set_title(c, loc="left", fontsize=13)
        ax.set_ylim(0, 50)
        ax.set_xlim(2015, 2029)
        ax.spines["bottom"].set_bounds(2015, 2026)
        ax.spines["left"].set_bounds(0, 50)
        ax.set_xticks([2016, 2020, 2024])
    for ax in axes[:, 0]:
        ax.set_yticks([0, 25, 50])
        ax.set_yticklabels(["0%", "25%", "50%"])
    fig.suptitle("Vulnerability class share by year: all CVEs (grey) vs exploited (KEV, dark)", x=0.06, ha="left",
                 fontsize=16, color=C["text"])
    fig.tight_layout()
    source_note(fig, "Sources: NVD feeds (by published year) and CISA KEV (by dateAdded, from 2021), retrieved 2026-10-25. "
                     "Class = coarse CWE grouping in scripts/aggregate.py; first matching class wins. Supply-chain malware "
                     "has no CWE/CVE and is not shown here.")
    save(fig, "class_mix")


if __name__ == "__main__":
    cves_per_year()
    kev_per_year()
    critical_share()
    time_to_exploit()
    black_weeks_timeline()
    malicious_packages()
    class_mix()
    print("charts written to", HERE)
