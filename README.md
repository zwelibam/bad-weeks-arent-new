# Bad weeks aren't new. The speed is.

The data, charts and code behind the post **[Bad Weeks Aren't New. The Speed Is.](https://www.ganthet.net/writing/bad-weeks-arent-new-the-speed-is/)** (26 October 2026).

The post places the 17–22 October 2026 "Black October" incidents against vulnerability data going back to 2002. It looks at how many CVEs are published, what share is known to be exploited, how fast exploitation follows disclosure, and how often comparable "bad weeks" have happened before.

The full write-up, with sources, caveats and a fact-check log, is **[OVERVIEW.md](OVERVIEW.md)**.

## Charts used in the post

| Chart | File | Data |
|---|---|---|
| Comparable bad weeks, 2014 to 2026 (a red bar shows exploitation before disclosure) | [`charts/black_weeks_timeline.svg`](charts/black_weeks_timeline.svg) | [`black_weeks_timeline.csv`](charts/data/black_weeks_timeline.csv) |
| Time to exploit, three measures (Mandiant mean days, VulnCheck share exploited by disclosure day, median days from CVE to KEV listing) | [`charts/time_to_exploit.svg`](charts/time_to_exploit.svg) | [`time_to_exploit_reports.csv`](charts/data/time_to_exploit_reports.csv), [`kev_lag_by_pub_year.csv`](charts/data/kev_lag_by_pub_year.csv) |
| CVEs published per year, 2015 to 24 October 2026 | [`charts/cves_per_year.svg`](charts/cves_per_year.svg) | [`cves_per_year.csv`](charts/data/cves_per_year.csv) |
| CISA KEV additions per year, 2021 to 23 October 2026 | [`charts/kev_per_year.svg`](charts/kev_per_year.svg) | [`kev_additions_per_year.csv`](charts/data/kev_additions_per_year.csv) |

Further charts that appear in OVERVIEW.md but not in the post: [`critical_share`](charts/critical_share.svg), [`class_mix`](charts/class_mix.svg) and [`malicious_packages`](charts/malicious_packages.svg). PNG versions sit next to every SVG.

## Reproduce

```bash
python3 -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt
bash scripts/download_raw.sh        # about 490 MB of public feeds into raw/ (not committed)
python3 scripts/aggregate.py        # rebuilds charts/data/*.csv
python3 charts/make_charts.py       # rebuilds charts/*.svg and *.png
```

The committed CSVs were computed from feeds retrieved on **25 October 2026**. Re-downloading gives current data, so the numbers will drift a little, especially for 2026. Each CSV carries a `#` header naming its source and retrieval date. [`raw/data-tables.md`](raw/data-tables.md) shows every table inline.

## Data sources and attribution

- **NVD CVE JSON 2.0 feeds**, National Institute of Standards and Technology. This product uses data from the NVD API but is not endorsed or certified by the NVD.
- **CISA Known Exploited Vulnerabilities catalogue** (catalogVersion 2026.10.23), Cybersecurity and Infrastructure Security Agency.
- **EPSS scores**, FIRST (Forum of Incident Response and Security Teams), https://www.first.org/epss, model v2026.06.15, score date 2026-10-24.
- **OSV malicious-package records** (OpenSSF malicious-packages, via osv.dev bulk exports), licensed CC-BY-4.0.
- **Reports and articles** (GTIG, Mandiant M-Trends 2026 and 2023 time-to-exploit, VulnCheck, Jerry Gamblin, Anthropic, Orca Security and others) are cited and linked in OVERVIEW.md. Their content is not redistributed here.

The bad-weeks timeline is a hand-compiled table. Every row lists its sources and a verification flag (Y checked at the primary source, P partly, N not checked). One row cites the author's unpublished Black October briefing of 24 October 2026; its underlying primary sources are cited in OVERVIEW.md.

## How this was made

Research and drafting used AI assistance, and every figure was recomputed from the bulk data or checked against the cited page. The corrections made along the way are listed at the end of OVERVIEW.md. Errors are mine: please open an issue.

## Licence

- Text, charts and derived data (`OVERVIEW.md`, `charts/`, `raw/data-tables.md`): **[CC BY 4.0](LICENSE-CC-BY-4.0)**. Please credit "Zweli, *Bad weeks aren't new. The speed is.*, ganthet.net, 2026".
- Code (`scripts/`, `charts/make_charts.py`): **[MIT](LICENSE)**.
- Third-party data keeps its own terms, listed above.
