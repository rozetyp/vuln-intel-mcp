# vuln-intel

**Most CVE tools hand your agent raw data. This one ranks it by what is actually being exploited, finds bugs by mechanism, and catches the CVEs your agent makes up.**

A curated, hosted MCP corpus: **~332,000 CVEs**, fused from **NVD + CISA KEV + FIRST EPSS + OSV/GHSA + CISA Vulnrichment (SSVC)**, refreshed daily. Not another live-API wrapper.

---

## Why this, and not the next CVE wrapper

Most CVE MCP servers are thin wrappers: at query time they fan out to the same free public APIs and hand back whatever comes out. This is different in five concrete ways.

- **A curated, embedded corpus, not a live proxy.** One record per vulnerability, fused across NVD, OSV/GHSA and KEV through an identity graph, with roughly 2,100 vendor-qualified product aliases and embeddings for semantic search. Queried locally, ranked consistently.
- **SSVC as priority, not just CVSS.** Priority is exploitation-first: CISA SSVC (active / automatable / total impact), KEV and EPSS drive a P1 to P4 ranking. The wrapper MCPs do not carry SSVC at all.
- **Search by mechanism, not keywords.** Semantic search finds the same bug *class* across different products. Keyword tools structurally cannot.
- **It fact-checks the agent.** `verify_cve_claim` catches invented CVEs and wrong attributes. This is the one that matters most right now, with hallucinated AI bug reports flooding triage, and effectively no other CVE MCP does it.
- **Right vendor, and no false zeros.** "GitHub Enterprise" resolves to the right vendor, not every product that ships an "enterprise_server." A product it cannot resolve returns `resolved: false` with suggestions, never a silent `0` that reads as "not affected." A false zero is the worst answer a security tool can give.

The hard part of AI-assisted security is not *finding* CVEs. It is triage, prioritization, and false positives. That is what this targets.

Everything below is real output from the live server, trimmed only for length.

---

## It fact-checks your agent

The differentiator that matters most. Your agent cites `CVE-2025-99999`:

```
verify_cve_claim("CVE-2025-99999")
  ->  exists: false    "No record in NVD / OSV / GHSA. Likely hallucinated or not-yet-published."
```

Or it gets the details wrong. Claim: *"CVE-2021-44228 is a medium-severity Apache Struts bug, and it is not exploited."*

```
verify_cve_claim("CVE-2021-44228", product="Apache Struts", severity="medium", exploited=false)
  refuted  "not exploited"          ->  in CISA KEV (added 2021-12-10)
  refuted  "severity medium"        ->  actual CVSS 10.0, P1
  refuted  "affects Apache Struts"  ->  no product matching "Apache Struts"
```

The other feeds hand your agent data. This one tells you when the agent is wrong, before it reaches a report.

## Priority is exploitation-first (SSVC, KEV, EPSS), not CVSS

`check_technology("GitLab")` returns 792 CVEs for the product, de-duped and ranked so the exploited ones float to the top:

```
P1  KEV  EPSS 99.8   CVE-2023-7028   account-takeover: password-reset email sent to an attacker address (CVSS 10)
P2  KEV  EPSS 98.5   CVE-2021-39935  unauthenticated SSRF via the CI Lint API
P3       EPSS 99.7   CVE-2023-2825   unauthenticated path traversal, arbitrary file read (CVSS 10)
P3       EPSS 99.7   CVE-2022-2992   authenticated RCE via the GitHub import API (CVSS 9.9)
```

Names that map to more than one vendor are flagged `ambiguous` (here, `gitlab` vs a `jenkins` plugin) and kept separate, never silently merged. `enrich_cve` then gives you the full SSVC picture for any one of them:

```
enrich_cve("CVE-2024-3400")   PAN-OS GlobalProtect
  P1  KEV  CVSS 10.0  EPSS 99.95    unauthenticated command injection -> root RCE
  SSVC          exploitation=active   automatable=yes   technical_impact=total
  Metasploit    exploit/linux/http/panos_telemetry_cmd_exec  (rank: excellent)
  Public PoC    44 repos   (h4x0r-dz 162 stars, W01fh4cker 90 stars, ...)
```

## Turn recon into a dig-order

`hunt_plan(["craftcms 4.4", "nginx", "keycloak"])` ranks your stack by its most-exploitable bug and names where each component historically bleeds:

```
#1  craftcms 4.4    97 CVEs, 12 high-risk
    recurring_loci   CWE-94 code injection x7 (2 exploited in the wild)  ->  probe template / eval surfaces first
    dig here
       P1 KEV EPSS 99.8   CVE-2025-32432   unauthenticated RCE (CVSS 10)        your 4.4 is AFFECTED, fixed in 4.14.15
       P1 KEV EPSS 99.9   CVE-2024-56145   RCE when register_argc_argv is on    AFFECTED, fixed in 4.13.2

#2  nginx           HTTP/2 Rapid Reset CVE-2023-44487 (KEV)
#3  keycloak        recurring_loci CWE-287 auth x12.  OIDC request_uri SSRF CVE-2020-10770
```

It does not just list CVEs. It names the bug *class* a product family keeps failing at, ranked by real exploitation, and tells you whether *your version* is in range. Where to look, and what shape to expect.

## Search by mechanism, across products

`find_similar_vulns(cve_id="CVE-2021-44228")`, "what else works like Log4Shell":

```
sim 0.88   CVE-2021-44832   Log4j2 JDBC Appender, JNDI LDAP RCE
sim 0.82   CVE-2022-40145   Apache Karaf, code injection via an attacker-controlled JNDI URL
sim 0.79   CVE-2022-34916   Apache Flume, JNDI LDAP RCE via a JMS source
```

The same JNDI-injection mechanism, surfaced across *different products*. A keyword search for "log4j" never finds Karaf or Flume. Or search a concept directly, `search_vulns("SAML SSO authentication bypass")`:

```
P3      CVSS 9.1  CVE-2024-9487   GitHub Enterprise: SAML SSO bypass via signature verification
P3      CVSS 9.8  CVE-2025-25291  ruby-saml: auth bypass via a ReXML / Nokogiri parser differential
P1 KEV  CVSS 9.8  CVE-2025-59718  Fortinet FortiOS / FortiProxy: signature-verification bypass
```

## See what is being exploited right now

`find_recent_high_risk(days=7)`, run live today:

```
P1 KEV CVSS 10.0  CVE-2026-10520  Ivanti Sentry: unauthenticated OS command injection -> root RCE
P1 KEV CVSS 9.3   CVE-2026-50751  Check Point: IKEv1 auth bypass, remote-access VPN without a password
P2 KEV CVSS 8.8   CVE-2026-11645  Chrome V8: out-of-bounds read/write -> sandbox escape RCE
```

Median time from disclosure to in-the-wild exploitation is now days, not months. The Ivanti bug above carried a CISA remediation deadline in the same week it landed. `corpus_stats` right now: **332,031 CVEs, 1,619 KEV entries, latest data under a day old.**

---

## Connect, free

```
claude mcp add --transport http vuln-intel <YOUR_ENDPOINT> \
  --header "Authorization: Bearer <YOUR_KEY>"
```

Or any MCP client (`mcp.json`):

```json
{
  "mcpServers": {
    "vuln-intel": {
      "type": "http",
      "url": "<YOUR_ENDPOINT>",
      "headers": { "Authorization": "Bearer <YOUR_KEY>" }
    }
  }
}
```

It is **free**. Email **rozetyp@gmail.com** with what you are working on (bounty, pentest, research) and you get an endpoint and a personal key. Keys are per-user, so usage stays attributable and revocable.

## The nine tools

| Tool | What it does |
|---|---|
| `check_technology` | Map a product or stack to ranked CVEs, de-duped across NVD CPE and OSV. |
| `hunt_plan` | Turn a recon'd stack into a ranked dig-order with recurring bug-class loci. |
| `enrich_cve` | One CVE, full dossier: CVSS, KEV, EPSS, SSVC, affected versions, live PoC. |
| `verify_cve_claim` | Fact-check a CVE assertion; catch hallucinations and wrong attributes. |
| `find_recent_high_risk` | What is newly dangerous: KEV / high-EPSS, optionally per product. |
| `find_similar_vulns` | Semantic, by-mechanism search from a concept or a seed CVE. |
| `search_vulns` | Exact full-text / CWE search across CVE and advisory summaries. |
| `search_public_code` | Find where an exact code string appears across public repositories. |
| `corpus_stats` | Corpus size and data freshness. |

It lays out facts and ranked context, never an exploit or a payload. Your agent does the reasoning.

## What it is not

Not a scanner, not an exploit tool, not an SBOM / SCA replacement. A grounding, prioritization and fact-check layer for AI-assisted security work.

## Field notes

What we learned building this, including the experiments that failed: what actually predicts exploitation, how to prioritize beyond CVSS, and whether a CVE corpus can make an LLM a better bug hunter. Published with the site, linked at launch.

---

For **authorized, defensive** security research and bug-bounty triage. Not for exploitation. Output is decision support, not a substitute for your own verification.
