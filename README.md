<img src="logo.svg" alt="vuln-intel logo" width="64" align="left">

# vuln-intel

[![get a key: free](https://img.shields.io/badge/get_a_key-free-2ea44f)](https://mcp.rozetyp.com/signup) ![MCP server](https://img.shields.io/badge/MCP-server-5865F2) ![corpus: 364k CVEs](https://img.shields.io/badge/corpus-364k_CVEs,_daily-1f6feb)

**Most CVE tools hand your agent raw data. This one ranks it by what's actually being exploited, finds bugs by mechanism, catches the CVEs your agent invents — and transfers attack mechanics from ~14,000 disclosed bug-bounty reports.**

A curated, hosted MCP corpus: **~364,000 CVEs**, fused from **NVD + CISA KEV + FIRST EPSS + OSV/GHSA + CISA Vulnrichment (SSVC)**, plus a mechanic layer distilled from **~14,000 disclosed, paid bug-bounty reports** — refreshed daily. Not another live-API wrapper.

> **Free.** [Get a key](https://mcp.rozetyp.com/signup): enter your email and your personal key is sent over. Tell me what you are hunting.

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

Median time from disclosure to in-the-wild exploitation is now days, not months. The Ivanti bug above carried a CISA remediation deadline in the same week it landed. `corpus_stats` right now: **~364,800 CVEs, ~1,630 KEV entries, data under a day old** — these figures are point-in-time and drift daily, so call `corpus_stats` yourself for the live count rather than trusting the numbers on this page.

## Transfer attack mechanics from disclosed bug-bounty reports

Beyond CVEs, the corpus distills **~14,000 disclosed, paid HackerOne reports** into product-agnostic *attack mechanics* — each bug's `source → sink → trigger → preconditions`, de-anchored from the product it was filed against. The premise: a vulnerability is a transferable **mechanism**, not a property of one product — so a move that paid on one stack is a checklist item on the next.

`find_attack_approaches(query="ssrf reaching cloud metadata")` — the human moves that transferred, novelty-ranked, each tagged with live program-actionability:

```
Reddit         SSRF   preview_url fetches an unfiltered URL → returns metadata    program_active, pays
U.S. DoD       SSRF   /download-url?url= fetches AWS instance metadata            program_active
Concrete CMS   SSRF   DNS-rebind bypass → AWS IAM creds from the metadata svc     program_active
```

- `find_continuations(position=...)` — matches your *accumulated attacker position* mid-hunt to the next moves real reports played from a similar spot. Every move is `status: UNVERIFIED` with a `decisive_check` to run on the target — a legal move, never a confirmed bug.
- `assist_submission(finding=...)` — a grounded submission brief from the closest paid precedents (validity, what's novel, an escalation playbook), with every cited report **validated against the corpus** (`citations_grounded`) so it can't smuggle a fabricated precedent.
- `program_outcome_prior("hackerone:gitlab")` — the bug classes that historically *landed* on a program, with lift over base rate (GitLab: SSRF 3.4×, SQLi ~never).

Honest about what this is: it **primes and grounds a human hunter** — it surfaces the move and the precedent. It does not find the bug for you; the target decides whether the move survives, and that's a step you still run.

---

## The whole point: a memory of mechanics to borrow and run — not a CVE lookup

The moat is **three things a stateless model cannot self-generate**, and this corpus holds all three:

- **Watched over time** — priors, temporal drift (Log4Shell's affected set kept growing **+1,200 days** after publish), score stability. Your model has a training-cutoff snapshot; this has the *trajectory*.
- **Seen many** — every disclosed mechanic and CVE mechanism, embedded, so the *same bug class* transfers across products a model would never connect: Log4Shell's JNDI lookup → Apache Karaf, Flume; an SSRF that paid on Reddit → the move to try on the next target.
- **Live-fused recon** — `observe` recovers a host's real backend from its JS bundles and joins it to the corpus on the spot.

The cardinal sin is treating it as a severity-number checker. The job is to **transfer a proven mechanic onto your target and run it** — or read a fix to *falsify* an option before you spend a probe on it.

### Force your agent to reach for it — it won't on its own

Left alone, an agent answers from training data: stale, and it *invents* CVE ids under pressure. Paste this operating loop into your agent's rules (`CLAUDE.md`, Cursor/Windsurf, a system prompt):

```text
You have the vuln-intel MCP. Your own CVE knowledge is a guess to be verified — prefer the corpus.
Operating loop, in order:
1. Scoping a bounty program → program_outcome_prior (which bug classes have actually PAID here).
2. A live host → observe (call twice; the 2nd returns the cache). Mine endpoints[], recurring_loci, the CVE join — not two fields.
3. A product + version → check_technology / hunt_plan (dig-order + the recurring CWE loci).
4. Before asserting ANY CVE / "affects X" / "severity Y" / "exploited" → verify_cve_claim. Never cite from memory.
5. Feasibility of one CVE → enrich_cve; read the MECHANISM (POST vs GET, auth-required) to judge whether it chains.
6. Hunting a class → find_attack_approaches for the transferable move; RUN it on the target, don't cite it. Loop with a growing tried=.
7. Stuck / messy position → find_continuations(position) for the by-step move; then search_vulns that class against the target to prove it's live here.
8. Submitting → assist_submission; EXECUTE the techniques it transfers (referrer differential, key-reuse breadth), then file.
Above all: a finding isn't a finding until a cheap check that would kill it has failed to.
```

It surfaces the move and the precedent; **the target decides what survives.** That last rule is the product's whole ethos — every tool ships its own kill-check (`verify_cve_claim` refutations, `UNVERIFIED` + a `decisive_check`, `ambiguous`, `citations_grounded`), so an agent can never read a narrow signal as a green light.

---

## Connect, free

```
claude mcp add --transport http vuln-intel https://mcp.rozetyp.com/mcp \
  --header "Authorization: Bearer <YOUR_KEY>"
```

Or any MCP client (`mcp.json`):

```json
{
  "mcpServers": {
    "vuln-intel": {
      "type": "http",
      "url": "https://mcp.rozetyp.com/mcp",
      "headers": { "Authorization": "Bearer <YOUR_KEY>" }
    }
  }
}
```

You just need a key, free. See [Get a key](#get-a-key) below.

## The thirteen tools

*CVE intelligence:*

| Tool | Input | Returns |
|---|---|---|
| `check_technology` | a product (+ version, vendor) | ranked CVEs de-duped across NVD CPE + OSV, ambiguity-flagged |
| `hunt_plan` | a recon'd stack | per-component dig-order + the recurring bug-class (CWE) loci |
| `enrich_cve` | a CVE id | full dossier: CVSS, KEV, EPSS, SSVC, affected, Metasploit + live PoC repos |
| `verify_cve_claim` | a CVE + asserted attributes | per-claim `supported` / `refuted` / `unverifiable` + evidence |
| `find_recent_high_risk` | a window (+ product) | newly dangerous KEV / high-EPSS CVEs |
| `find_similar_vulns` | a concept or seed CVE | mechanism-siblings across products, with cosine similarity |
| `search_vulns` | free text (+ CWE) | ranked full-text matches + total coverage |
| `search_public_code` | an exact code string | public repos where it appears (repo / file / url) |
| `corpus_stats` | — | corpus size and data freshness |

*Bug-bounty mechanic transfer (from ~14k disclosed reports):*

| Tool | Input | Returns |
|---|---|---|
| `find_attack_approaches` | a target / CVE / bug-class | transferable attack mechanics, novelty-ranked + live program-actionability |
| `find_continuations` | your mid-hunt attacker position | the next moves real reports played from there, each `UNVERIFIED` + a decisive check |
| `assist_submission` | a draft finding | grounded submission brief + escalation playbook, citation-guarded (`citations_grounded`) |
| `program_outcome_prior` | a bug-bounty program | the bug classes that historically landed on it + lift over base rate |

It lays out facts, ranked context, and transferable precedent — never an exploit or a payload. Your agent does the reasoning; the target decides what survives.

**Full reference** — every argument, response field, and a live example per tool — in **[TOOLS.md](TOOLS.md)**.

## What it is not

Not a scanner, not an exploit tool, not an SBOM / SCA replacement. A grounding, prioritization and fact-check layer for AI-assisted security work.

## Get a key

**It is free.** Go to **[mcp.rozetyp.com/signup](https://mcp.rozetyp.com/signup)**, enter your email, and your personal key is sent over. Prefer to ask directly? Email [rozetyp@gmail.com](mailto:rozetyp@gmail.com?subject=vuln-intel%20key) with what you are working on (bounty, pentest, research). Keys are per-user, attributable and revocable.

---

For **authorized, defensive** security research and bug-bounty triage. Not for exploitation. Output is decision support, not a substitute for your own verification.

© 2026 rozetyp. All rights reserved. This is not open source; see [LICENSE](LICENSE).
