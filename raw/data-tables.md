# Data tables — Vulnerabilities over time (compiled 2026-10-25)

## bad_weeks_timeline.csv
```
# Comparable clusters of high-impact vulnerabilities/incidents, compiled 2026-10-25 from the cited sources.
# disclosure = first public disclosure / vendor advisory; first_exploitation = earliest in-the-wild activity reported by the cited source.
# lag_days = first_exploitation - disclosure (negative = exploited before disclosure). Blank where not applicable or not established.
# verified: Y = date and figure checked against cited source on 2026-10-25; P = partly (some figure secondary/estimate); N = not checked at primary.
id,label,disclosure,first_exploitation,lag_days,lag_note,class,blast_radius,verified,sources
heartbleed,Heartbleed (OpenSSL CVE-2014-0160),2014-04-07,,,"exploitation reported within days (e.g. Canada Revenue Agency SIN theft disclosed 2014-04-14)",memory safety,"widely cited ~17% / ~0.5M of trusted TLS sites (Netcraft 2014-04-08; original page not retrievable 2026-10-25)",P,https://heartbleed.com/ ; https://nvd.nist.gov/vuln/detail/CVE-2014-0160
shellshock,Shellshock (Bash CVE-2014-6271),2014-09-24,2014-09-25,1,"scanning within ~24h; botnets by 25 Sep",injection / code exec,"any CGI/bash-reachable host; botnet DDoS within 2 days",P,https://nvd.nist.gov/vuln/detail/CVE-2014-6271 ; https://thehackernews.com/2014/09/Shellshock-Bash-Vulnerability-exploit.html
eternalblue,EternalBlue → WannaCry → NotPetya (MS17-010),2017-03-14,2017-05-12,59,"patch 14 Mar; Shadow Brokers leak 14 Apr (28 d before WannaCry); NotPetya 27 Jun via M.E.Doc update",memory safety + supply chain,"WannaCry ~200,000 victims in 150+ countries (Europol); NotPetya 'billions of dollars' (White House 2018-02-15)",P,https://learn.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010 ; https://www.executivegov.com/articles/europol-ransomware-attack-compromised-200k-computers-in-over-150-countries ; https://www.darkreading.com/threat-intelligence/white-house-russian-military-behind-notpetya-attacks/d/d-id/1331078
solarwinds,SolarWinds SUNBURST (Orion build compromise),2020-12-13,2020-03-01,-287,"trojanised updates shipped from ~Mar 2020 (month-level; lag approximate)",supply chain (build system),"fewer than 18,000 customers installed affected Orion (SolarWinds 8-K 2020-12-14)",Y,https://www.sec.gov/Archives/edgar/data/1739942/000162828020017451/swi-20201214.htm ; https://www.cisa.gov/news-events/directives/ed-21-01-mitigate-solarwinds-orion-code-compromise
proxylogon,ProxyLogon (Exchange CVE-2021-26855 chain),2021-03-02,2021-01-03,-58,"Volexity observed exploitation from 3 Jan 2021",auth bypass (SSRF) → RCE,"tens of thousands of on-prem Exchange servers (multiple vendors; estimate)",P,https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/
log4shell,Log4Shell (Log4j CVE-2021-44228),2021-12-09,2021-12-01,-8,"Cloudflare saw first payload 2021-12-01 03:58 UTC; public tweet 2021-12-09 14:25 UTC",injection in OSS dependency,"ubiquitous Java dependency; CISA ED 22-02 (2021-12-17)",Y,https://blog.cloudflare.com/exploitation-of-cve-2021-44228-before-public-disclosure-and-evolution-of-waf-evasion-patterns/ ; https://www.cisa.gov/news-events/directives/ed-22-02-mitigate-apache-log4j-vulnerability
moveit,MOVEit Transfer (CVE-2023-34362) / Cl0p,2023-05-31,2023-05-27,-4,"CISA/FBI: exploitation began 27 May 2023",injection (SQLi) in file-transfer appliance,"2,773 orgs / ~95.8M individuals (Emsisoft tally to 2024-06-28; estimate)",Y,https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-158a ; https://emsisoft.com/en/blog/44123/unpacking-the-moveit-breach-statistics-and-analysis/
xz,xz-utils backdoor (CVE-2024-3094),2024-03-29,,,"caught before reaching stable distros; no known mass exploitation",supply chain (maintainer takeover),"near miss: would have reached sshd on major Linux distros",P,https://www.openwall.com/lists/oss-security/2024/03/29/4 ; https://nvd.nist.gov/vuln/detail/CVE-2024-3094
snowflake,Snowflake customer intrusions (UNC5537),2024-06-10,2024-04-14,-57,"Mandiant: targeting from at least 14 Apr 2024",identity / SaaS (infostealer creds; no MFA),"~165 potentially exposed customer orgs (Mandiant)",P,https://cloud.google.com/blog/topics/threat-intelligence/unc5537-snowflake-data-theft-extortion ; https://thehackernews.com/2024/06/snowflake-breach-exposes-165-customers.html
crowdstrike,CrowdStrike Falcon content-update outage,2024-07-19,,,"not a vulnerability or attack: faulty vendor update",operational supply chain (no attacker),"8.5M Windows devices (<1% of all Windows machines) (Microsoft 2024-07-20)",Y,https://blogs.microsoft.com/blog/2024/07/20/helping-our-customers-through-the-crowdstrike-outage/
toolshell,SharePoint ToolShell (CVE-2025-53770),2025-07-19,2025-07-17,-2,"SentinelOne earliest exploitation 17 Jul 10:35 GMT; Microsoft patch 20 Jul",deserialization → RCE (on-prem SaaS-adjacent),"85+ servers / 29 orgs in first count (secondary); later reports in the hundreds",P,https://www.sentinelone.com/blog/sharepoint-toolshell-zero-day-exploited-in-the-wild-targets-enterprise-servers/ ; https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53770
salesloft,Salesloft Drift OAuth token theft (UNC6395),2025-08-20,2025-08-08,-12,"theft 8–18 Aug; Salesloft advisory 20 Aug",identity / SaaS (OAuth tokens),"700+ potentially impacted orgs (GTIG via The Hacker News)",P,https://cloud.google.com/blog/topics/threat-intelligence/data-theft-salesforce-instances-via-salesloft-drift ; https://thehackernews.com/2025/08/salesloft-oauth-breach-via-drift-ai.html
npmworm2025,npm chalk/debug hijack + Shai-Hulud worm,2025-09-08,2025-09-08,0,"chalk/debug phished maintainer 8 Sep; Shai-Hulud self-propagation from ~15 Sep",supply chain (npm),"18 pkgs with >2B weekly downloads; Shai-Hulud 500+ packages (CISA)",P,https://semgrep.dev/blog/2025/chalk-debug-and-color-on-npm-compromised-in-new-supply-chain-attack ; https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem
oracleebs,Oracle E-Business Suite (CVE-2025-61882) / Cl0p,2025-10-04,2025-08-09,-56,"data theft from Aug 2025; possible activity from 10 Jul (GTIG/Mandiant)",RCE in ERP (zero-day),"'dozens of organizations' (GTIG)",P,https://cloud.google.com/blog/topics/threat-intelligence/oracle-ebusiness-suite-zero-day-exploitation ; https://securityaffairs.com/183029/security/oracle-patches-critical-e-business-suite-flaw-exploited-by-cl0p-hackers.html
gtg1002,GTG-1002 AI-orchestrated espionage (Anthropic report),2025-11-13,2025-09-15,-59,"detected mid-Sep 2025 (day approximate)",AI-assisted operations,"~30 targets, a small number of successful intrusions; AI ran ~80–90% of tactical work",Y,https://assets.anthropic.com/m/ec212e6566a0d47/original/Disrupting-the-first-reported-AI-orchestrated-cyber-espionage-campaign.pdf
react2shell,React2Shell (React Server Components CVE-2025-55182),2025-12-03,2025-12-04,1,"exploitation within ~hours/1 day; CISA KEV 5 Dec",deserialization in OSS framework,"React 19 / Next.js 15–16 server deployments",P,https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components ; https://www.tenable.com/blog/react2shell-cve-2025-55182-react-server-components-rce
beyondtrust,BeyondTrust RS/PRA (CVE-2026-1731) — AI-discovered,2026-02-06,2026-01-31,-6,"conflict: secondary reports exploitation from 31 Jan; GTIG says first cluster within 4 days AFTER disclosure",injection (AI-discovered),"~11,000 internet-exposed instances (Hacktron); ransomware use (CISA)",P,https://cloud.google.com/blog/topics/threat-intelligence/vulnerability-discovery-and-exploitation-trends-in-the-ai-era ; https://www.hacktron.ai/blog/cve-2026-1731-beyondtrust-remote-support-rce ; https://securityaffairs.com/187962/uncategorized/attackers-exploit-beyondtrust-cve-2026-1731-within-hours-of-poc-release.html
ciscosdwan,Cisco SD-WAN zero-day (CVE-2026-20127) — CISA ED 26-03,2026-02-25,,,"exploited as zero-day before disclosure (date not public)",auth bypass (edge),"global; Five Eyes joint guidance",Y,https://www.cisa.gov/news-events/alerts/2026/02/25/cisa-and-partners-release-guidance-ongoing-global-exploitation-cisco-sd-wan-systems
teampcp,TeamPCP waves → Mini Shai-Hulud (TanStack et al.),2026-05-12,2026-05-11,-1,"waves from late Apr 2026 (SAP npm, PyTorch Lightning 30 Apr); lag approximate",supply chain (npm/PyPI; CI/OIDC),"169 npm + 2 PyPI packages, 373 malicious versions; valid provenance attestations",P,https://orca.security/resources/blog/tanstack-npm-supply-chain-worm/
netscaler,Citrix NetScaler ADC/Gateway — 10 zero-days,2026-09-27,,,"exploited before disclosure (CISA: active global exploitation)",edge appliance (RCE),"global; rotate creds and certificates",Y,https://www.cisa.gov/news-events/alerts/2026/09/27/critical-zero-day-vulnerabilities-exploited-citrix-netscaler-adc-gateway
blackoctober,Black October (PHP2Shell + eMudhra + LiteLLM + Storm-0940 + Railway),2026-10-21,2026-10-17,-4,"PHP2Shell honeypot hits 17 Oct (AWS), patch 21 Oct; eMudhra report 17 Oct; LiteLLM 21 Oct",memory safety + PKI/trust + supply chain + AI-assisted + identity,"PHP runtime (most of the web); browser-trusted CA; AI-gateway credentials; 2,250+ M365 tenants targeted",Y,author's unpublished Black October briefing (2026-10-24) (sources 3,4,9,13,16)
```

## cve_class_mix_per_year.csv
```
# source: NVD CVE JSON 2.0 yearly feeds https://nvd.nist.gov/feeds/json/cve/2.0/ (retrieved 2026-10-25)
# bucketed by 'published' date; Rejected records excluded; 2026 is partial (to 2026-10-24)
# scores: highest base score across NVD Primary and CNA Secondary metrics for that CVSS version
# class = coarse grouping of NVD/CNA CWE IDs, see CLASS in scripts/aggregate.py
year,memory safety,injection / code exec,auth / access control,path traversal / SSRF / file,web client (XSS/CSRF),other / unclassified
2015,1071,357,795,166,968,3137
2016,1626,210,1160,108,558,2787
2017,4090,1092,2396,452,1878,4734
2018,4309,1408,2268,849,2527,5149
2019,3910,1695,2254,787,2951,5708
2020,3464,1867,2473,758,2641,7119
2021,4475,2309,2460,910,3183,6812
2022,5530,3520,3354,1165,3925,7579
2023,5485,4426,4102,1275,6139,7389
2024,8050,5998,6021,1760,8741,9383
2025,7670,8598,7240,2137,9559,12947
2026,15471,11068,20499,5648,8272,25444
```

## cves_per_quarter.csv
```
# source: NVD CVE JSON 2.0 yearly feeds https://nvd.nist.gov/feeds/json/cve/2.0/ (retrieved 2026-10-25)
# bucketed by 'published' date; Rejected records excluded; 2026 is partial (to 2026-10-24)
# scores: highest base score across NVD Primary and CNA Secondary metrics for that CVSS version
year,quarter,total
2015,1,1652
2015,2,1443
2015,3,1747
2015,4,1652
2016,1,1379
2016,2,1775
2016,3,1713
2016,4,1582
2017,1,3424
2017,2,3613
2017,3,4035
2017,4,3570
2018,1,3935
2018,2,4612
2018,3,4349
2018,4,3614
2019,1,3232
2019,2,4103
2019,3,5150
2019,4,4820
2020,1,4804
2020,2,4990
2020,3,4165
2020,4,4363
2021,1,4426
2021,2,5003
2021,3,5569
2021,4,5151
2022,1,6016
2022,2,6346
2022,3,6483
2022,4,6228
2023,1,6975
2023,2,7132
2023,3,6930
2023,4,7779
2024,1,8681
2024,2,11698
2024,3,8523
2024,4,11051
2025,1,11946
2025,2,11695
2025,3,11725
2025,4,12785
2026,1,15152
2026,2,20688
2026,3,36961
2026,4,13601
```

## cves_per_year.csv
```
# source: NVD CVE JSON 2.0 yearly feeds https://nvd.nist.gov/feeds/json/cve/2.0/ (retrieved 2026-10-25)
# bucketed by 'published' date; Rejected records excluded; 2026 is partial (to 2026-10-24)
# scores: highest base score across NVD Primary and CNA Secondary metrics for that CVSS version
year,total,v3_scored,v3_critical,v2_scored,v2_ge9,v4_scored,v4_critical,any_ge9,unscored,nvd_analyzed,v3_critical_share_pct,v2_ge9_share_pct,unscored_pct
2015,6494,236,51,6494,1164,0,0,1186,0,6494,21.6,17.9,0.0
2016,6449,6231,887,6449,1350,0,0,1732,0,6449,14.2,20.9,0.0
2017,14642,14642,2130,14642,1525,3,0,3170,0,14642,14.5,10.4,0.0
2018,16510,16510,2633,16510,1568,0,0,3442,0,16508,15.9,9.5,0.0
2019,17305,17305,2697,17305,1416,0,0,3494,0,17305,15.6,8.2,0.0
2020,18322,18322,2849,18322,1503,5,3,3643,0,18317,15.5,8.2,0.0
2021,20149,20149,2897,20149,1181,10,0,3604,0,20145,14.4,5.9,0.0
2022,25073,25061,4618,13225,858,31,3,5010,2,25070,18.4,6.5,0.0
2023,28816,28815,5084,1926,9,54,4,5090,1,28815,17.6,0.5,0.0
2024,39953,39629,5567,2971,301,3576,275,5897,8,32173,14.0,10.1,0.0
2025,48151,45386,6418,5899,577,12421,1022,7401,897,30180,14.1,9.8,1.9
2026,86402,77939,10008,5961,739,27205,2660,11770,3186,38687,12.8,12.4,3.7
```

## epss_by_pub_year.csv
```
# source: FIRST EPSS scores model v2026.06.15, score_date 2026-10-24 (retrieved 2026-10-25)
# https://epss.empiricalsecurity.com/epss_scores-2026-10-24.csv.gz ; joined to NVD published year
# NOTE: these are today's scores for CVEs of each year, not historical scores
year,scored,epss_ge_0_1,share_pct
2015,6494,837,12.89
2016,6449,738,11.44
2017,14642,978,6.68
2018,16510,1274,7.72
2019,17305,1044,6.03
2020,18322,902,4.92
2021,20149,1023,5.08
2022,25073,955,3.81
2023,28816,954,3.31
2024,39953,949,2.38
2025,48151,730,1.52
2026,86371,196,0.23
```

## kev_additions_per_year.csv
```
# source: CISA KEV catalog JSON catalogVersion 2026.10.23 dateReleased 2026-10-23T19:30:18.9209Z (retrieved 2026-10-25)
# https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
# bucketed by dateAdded; KEV began 2021-11-03 with a backfill of older CVEs; 2026 partial (to 2026-10-23)
year,added,ransomware_known,cve_year_eq_added_year
2021,311,84,120
2022,555,132,91
2023,187,43,121
2024,186,44,116
2025,245,31,151
2026,272,27,185
```

## kev_class_mix_per_year.csv
```
# source: CISA KEV catalog JSON catalogVersion 2026.10.23 dateReleased 2026-10-23T19:30:18.9209Z (retrieved 2026-10-25)
# https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
# bucketed by dateAdded; KEV began 2021-11-03 with a backfill of older CVEs; 2026 partial (to 2026-10-23)
# class = coarse grouping of KEV 'cwes' field, see CLASS in scripts/aggregate.py
year,memory safety,injection / code exec,auth / access control,path traversal / SSRF / file,web client (XSS/CSRF),other / unclassified
2021,84,64,35,29,4,95
2022,160,84,51,39,10,211
2023,49,39,33,6,6,54
2024,32,50,35,13,6,50
2025,46,57,35,29,8,70
2026,40,69,58,28,5,72
```

## kev_lag_by_pub_year.csv
```
# source: CISA KEV catalog JSON catalogVersion 2026.10.23 dateReleased 2026-10-23T19:30:18.9209Z (retrieved 2026-10-25)
# https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
# bucketed by dateAdded; KEV began 2021-11-03 with a backfill of older CVEs; 2026 partial (to 2026-10-23)
# source: NVD CVE JSON 2.0 yearly feeds https://nvd.nist.gov/feeds/json/cve/2.0/ (retrieved 2026-10-25)
# lag = KEV dateAdded minus NVD published date (days); a LISTING lag, not time-to-exploit
# CVEs published 2022+ only; recent years are right-censored (late listings still to come)
pub_year,n_in_kev,median_lag_days,listed_on_or_before_pub,listed_within_7d,within_7d_pct
2022,131,24,39,51,38.9
2023,166,6.0,46,87,52.4
2024,160,11.0,40,78,48.8
2025,197,8,49,97,49.2
2026,195,4,56,115,59.0
```

## malicious_packages_per_year.csv
```
# source: OSV bulk exports, MAL-* records (OpenSSF malicious-packages) (retrieved 2026-10-25)
# https://osv-vulnerabilities.storage.googleapis.com/{npm,PyPI}/all.zip
# bucketed by OSV 'published'; counts reports not incidents (spam/typosquat floods inflate some years)
# malicious packages normally receive NO CVE, so they are invisible in NVD counts
year,npm,PyPI
2021,5,0
2022,7424,20
2023,2291,6468
2024,8372,2646
2025,191420,1245
2026,13255,1568
```

## time_to_exploit_reports.csv
```
# Vendor-reported time-to-exploit (TTE) and zero-day share figures, transcribed by hand (retrieved 2026-10-25)
# TTE = Mandiant/GTIG "average time taken to exploit a vulnerability before or after a patch is released" (days)
# Not one consistent series: periods overlap, sample sizes and methods differ between reports. 2024 value not found in a Mandiant primary source.
period_label,period_mid_year,metric,value,source,url,published
2018-2019,2018.5,mandiant_tte_days,63,Mandiant/Google Cloud "How Low Can You Go? An Analysis of 2023 Time-to-Exploit Trends",https://cloud.google.com/blog/topics/threat-intelligence/time-to-exploit-trends-2023,2024-10-15
2020-early 2021,2020.5,mandiant_tte_days,44,same,https://cloud.google.com/blog/topics/threat-intelligence/time-to-exploit-trends-2023,2024-10-15
2021-2022,2021.5,mandiant_tte_days,32,same,https://cloud.google.com/blog/topics/threat-intelligence/time-to-exploit-trends-2023,2024-10-15
2023,2023.0,mandiant_tte_days,5,same (n=138 exploited CVEs disclosed in 2023),https://cloud.google.com/blog/topics/threat-intelligence/time-to-exploit-trends-2023,2024-10-15
2025,2025.0,mandiant_tte_days,-7,M-Trends 2026 ("estimated -7 days"),https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2026,2026-03-23
2021-2022,2021.5,mandiant_zero_day_share_pct,62,Mandiant TTE 2023 (n-day:zero-day 38:62),https://cloud.google.com/blog/topics/threat-intelligence/time-to-exploit-trends-2023,2024-10-15
2023,2023.0,mandiant_zero_day_share_pct,70,Mandiant TTE 2023 (30:70),https://cloud.google.com/blog/topics/threat-intelligence/time-to-exploit-trends-2023,2024-10-15
Jan-Aug 2026,2026.3,gtig_zero_day_share_pct,62,GTIG "Vulnerability Discovery and Exploitation Trends in the AI Era",https://cloud.google.com/blog/topics/threat-intelligence/vulnerability-discovery-and-exploitation-trends-in-the-ai-era,2026-09-30
2024,2024.0,vulncheck_exploited_on_or_before_disclosure_pct,23.6,VulnCheck (via Infosecurity Magazine 2026-01-22),https://www.infosecurity-magazine.com/news/zeroday-exploits-surge-vulncheck,2026-01-21
1H 2025,2025.25,vulncheck_exploited_on_or_before_disclosure_pct,32.1,VulnCheck State of Exploitation 1H 2025,https://www.vulncheck.com/blog/state-of-exploitation-1h-2025,2025
2025,2025.0,vulncheck_exploited_on_or_before_disclosure_pct,28.96,VulnCheck State of Exploitation 2026 (via Infosecurity Magazine),https://www.infosecurity-magazine.com/news/zeroday-exploits-surge-vulncheck,2026-01-21
2025,2025.0,gtig_exploited_per_month,10.5,GTIG AI-era trends (127 for full year 2025 per same post),https://cloud.google.com/blog/topics/threat-intelligence/vulnerability-discovery-and-exploitation-trends-in-the-ai-era,2026-09-30
Jan-Aug 2026,2026.3,gtig_exploited_per_month,18,GTIG AI-era trends,https://cloud.google.com/blog/topics/threat-intelligence/vulnerability-discovery-and-exploitation-trends-in-the-ai-era,2026-09-30
2025,2025.0,gtig_zero_days_per_month,8,GTIG AI-era trends,https://cloud.google.com/blog/topics/threat-intelligence/vulnerability-discovery-and-exploitation-trends-in-the-ai-era,2026-09-30
Jan-Aug 2026,2026.3,gtig_zero_days_per_month,11,GTIG AI-era trends,https://cloud.google.com/blog/topics/threat-intelligence/vulnerability-discovery-and-exploitation-trends-in-the-ai-era,2026-09-30
```
