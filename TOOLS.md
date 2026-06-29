# vuln-intel — tool reference

Thirteen tools over Streamable HTTP (bearer-gated): **nine CVE-intelligence** tools (source-grounded,
fused from NVD, CISA KEV, FIRST EPSS, OSV/GHSA, CISA Vulnrichment/SSVC) and **four bug-bounty
mechanic-transfer** tools distilled from ~14,000 disclosed reports. The server lays out facts, ranked
context, and transferable precedent — never an exploit or a payload. Your agent reasons; the target
decides what survives.

> **Make your agent actually call these.** A great tool the agent never invokes is worthless — agents
> default to (stale, hallucination-prone) recall. Paste the drop-in rules block from the
> [README](README.md#the-catch-your-agent-wont-use-it-unless-you-make-it) so it reaches for the corpus
> instead of its memory. **Numbers in the examples below are point-in-time and drift daily** — call
> `corpus_stats` for live figures.

Need an endpoint and key? See [Get a key](README.md#get-a-key) — it's free.

---

## The result card

Most tools return CVE "cards" that share these fields, so they're defined once here:

| field | meaning |
|---|---|
| `cve_id` | CVE / GHSA / advisory id |
| `priority` | `P1`–`P4`, exploitation-first (below) |
| `action` | the directive for that priority |
| `cvss` | base score, 0–10 |
| `kev` | `true` if in CISA Known Exploited Vulnerabilities |
| `epss_percentile` | FIRST EPSS percentile, 0–1 (p99 = top 1% most likely to be exploited) |
| `summary` | advisory text |
| `cwes` | weakness types (CWE ids) |

**Priority is exploitation-first, not raw CVSS:**

- **P1** — actively exploited (in KEV) → *patch immediately*
- **P2** — exploited / imminently exploitable → *fix within days*
- **P3** — likely or schedulable → *patch within weeks*
- **P4** — monitor

---

## `check_technology`

Map a product (optionally a version) to the CVEs that affect it, de-duplicated across NVD CPE and
OSV package data and ranked by priority. Distinct products that share a name are kept distinct, not
merged.

| arg | type | default | notes |
|---|---|---|---|
| `product` | string | — | **required** — `"nginx"`, `"Keycloak"`, `"rhel"`, `"snapdragon"` |
| `version` | string | `null` | filters to vulns whose affected range actually includes it |
| `ecosystem` | string | `null` | package ecosystem filter: `PyPI`, `npm`, `Maven`, `Go` |
| `vendor` | string | `null` | disambiguate a shared product name (e.g. `vendor="envoyproxy"`) |
| `limit` | int | `20` | max result cards |

**Returns:** `resolved` (bool), `count` (distinct CVEs), `matched_products[]` (every
`vendor:product` matched, with `record_count`), `results[]` (ranked cards, each with
`match.products` showing which identities hit), and — when one name spans several vendors —
`ambiguous` + `distinct_vendors` (pass `vendor=` to filter). Large fan-outs are bounded:
`matched_products` caps at 50 (`matched_products_truncated`), `query.searched_as` at 30.

```jsonc
check_technology(product="rhel")
→ { "resolved": true, "count": 118,
    "matched_products": [{ "identity": "red_hat:red_hat_enterprise_linux_9", "record_count": 30 }, ...],
    "ambiguous": true, "distinct_vendors": ["red_hat", "redhat"],
    "results": [{ "cve_id": "CVE-2024-8698", "priority": "P3", "cvss": 7.7, ... }] }
```

---

## `enrich_cve`

One CVE, the full dossier — the deep-dive on a single finding.

| arg | type | default | notes |
|---|---|---|---|
| `cve_id` | string | — | **required** — `"CVE-2021-44228"` |
| `include_poc` | bool | `true` | also query GitHub live for public PoC / exploit repos |

**Returns:** the card fields plus `rationale`, `cvss_vector`, `published`, `references[]`,
`affected[]` (`vendor`/`product`/`range`), `affected_packages[]` (OSV ecosystems),
`ssvc{exploitation, automatable, technical_impact}`, `exploit_refs[]` (Metasploit modules),
`kev_detail{date_added, due_date, required_action}`, `kev_ransomware`, `aliases[]` (e.g. GHSA),
`sources[]`, and — when `include_poc` — `public_exploit{available, public_repo_count, top_repos[]}`.

```jsonc
enrich_cve(cve_id="CVE-2021-44228")
→ { "priority": "P1", "cvss": 10.0, "kev": true, "epss_percentile": 0.9996,
    "cwes": ["CWE-20","CWE-400","CWE-502","CWE-917"],
    "ssvc": { "exploitation": "active", "automatable": "yes", "technical_impact": "total" },
    "exploit_refs": [{ "source": "metasploit", "name": "Log4Shell HTTP Header Injection" }, ...],
    "public_exploit": { "available": true, "public_repo_count": 497,
                        "top_repos": [{ "name": "fullhunt/log4j-scan", "stars": 3427 }] } }
```

---

## `verify_cve_claim`

Fact-check a claim about a CVE before it ships — catch hallucinations and wrong attributes.
Returns a per-assertion verdict: `supported`, `refuted`, or `unverifiable`, each with cited evidence.

| arg | type | default | notes |
|---|---|---|---|
| `cve_id` | string | — | **required** — the id being claimed about |
| `product` | string | `null` | check the "affects this product" claim |
| `version` | string | `null` | check the "affects this version" claim, in range |
| `severity` | string | `null` | a number (`"9.8"`) or label (`"critical"`/`"high"`/…) |
| `exploited` | bool | `null` | the "actively exploited / in KEV" claim |
| `claim` | string | `null` | free text — returns evidence (summary, CWE) for you to judge |

**Returns:** `exists` (bool), `checks[]` (`assertion` → `verdict` + `evidence`), and `facts{}` (the
ground truth: CVSS, priority, KEV, CWEs, summary) so you can reason past the atoms it can check.

```jsonc
verify_cve_claim(cve_id="CVE-2021-44228", severity="critical", exploited=true)
→ { "exists": true, "checks": [
      { "assertion": "actively exploited (KEV) = True", "verdict": "supported",
        "evidence": "in CISA KEV (added 2021-12-10)" },
      { "assertion": "severity critical", "verdict": "supported",
        "evidence": "actual CVSS 10.0 (3.1) → P1" } ] }
```

---

## `find_similar_vulns`

Semantic search — find vulns by *mechanism / meaning*, not keywords. Surfaces mechanism-siblings
across different products that keyword search misses. Give **either** a free-text concept **or** a
seed CVE.

| arg | type | default | notes |
|---|---|---|---|
| `query` | string | `null` | a concept, e.g. `"JNDI lookup leading to RCE"` |
| `cve_id` | string | `null` | a seed finding — returns the closest mechanisms to it |
| `cwe` | string | `null` | optional weakness filter |
| `days` | int | `null` | optional recency filter |
| `order` | string | `similarity` | or `severity` |
| `limit` | int | `20` | max results |

**Returns:** result cards plus `similarity` (cosine, 1.0 = identical meaning). High similarity is
conceptual kinship, not proof of the same bug.

```jsonc
find_similar_vulns(cve_id="CVE-2021-44228")
→ [ { "cve_id": "CVE-2021-44832", "similarity": 0.88, "summary": "Log4j2 ... JDBC Appender JNDI ..." },
    { "cve_id": "CVE-2022-40145", "similarity": 0.82, "summary": "Apache Karaf JDBC JNDI injection ..." } ]
    // note the cross-product hit (Karaf) — same mechanism, different product
```

---

## `search_vulns`

Exact full-text / CWE search across CVE and advisory summaries — find vulns by concept or technique
when you don't have a specific product or id. Keyword-based: expand acronyms if results look thin.

| arg | type | default | notes |
|---|---|---|---|
| `query` | string | — | **required** — `"deserialization gadget chain"`; phrases, `OR`, `-negation` work |
| `cwe` | string | `null` | weakness filter, e.g. `"CWE-502"` or `"502"` |
| `days` | int | `null` | recency filter on publication date |
| `order` | string | `relevance` | or `severity` (P1>P4, EPSS, CVSS) |
| `limit` | int | `20` | max results |

**Returns:** `total_matches` (full coverage), `count`, `truncated`, and result cards each with a
`relevance` score (ts_rank_cd).

```jsonc
search_vulns(query="server-side request forgery cloud metadata", cwe="CWE-918", limit=5)
→ { "total_matches": 71, "truncated": true,
    "results": [{ "cve_id": "CVE-2026-10241", "cvss": 6.3, "cwes": ["CWE-918"],
                  "summary": "... Cloud Instance Metadata Endpoint ... SSRF ..." }, ...] }
```

---

## `find_recent_high_risk`

What's newly dangerous: recent CVEs that are KEV-exploited / P1–P2 / high-EPSS, optionally scoped to
one product.

| arg | type | default | notes |
|---|---|---|---|
| `product` | string | `null` | optional product filter |
| `days` | int | `90` | lookback window on publication date |
| `limit` | int | `25` | max results |

**Returns:** `window_days`, `count` (total in window), and result cards ordered by risk.

```jsonc
find_recent_high_risk(days=30, limit=6)
→ { "window_days": 30, "results": [
      { "cve_id": "CVE-2026-10520", "priority": "P1", "cvss": 10.0, "kev": true,
        "summary": "OS Command Injection in Ivanti Sentry ... unauthenticated root RCE" }, ...] }
```

---

## `hunt_plan`

Turn a recon'd stack into a ranked **dig-order** for authorized bug-hunting. For each component:
its top high-risk CVEs **and** its `recurring_loci` — the bug classes (CWE) that product family
repeatedly fails at, ranked by real in-the-wild exploitation. Components are ordered by their
most-exploitable bug (`dig_rank`).

| arg | type | default | notes |
|---|---|---|---|
| `technologies` | string[] | — | **required** — `["craftcms 4.4", "nginx", "keycloak"]` |
| `per_tech` | int | `4` | how many top CVEs per component |

**Returns:** `plan[]` (per component: `total_cves`, `high_risk_count`, `recurring_loci[]`
{`cwe`, `count`, `exploited_in_wild`}, `dig_here[]`, `dig_rank`, plus ambiguity flags),
`top_across_stack[]` (hottest CVEs over the whole stack), and `how_to_use`.

```jsonc
hunt_plan(technologies=["nginx","openssh"], per_tech=3)
→ { "plan": [
      { "technology": "nginx", "dig_rank": 1, "total_cves": 36, "high_risk_count": 19,
        "recurring_loci": [{ "cwe": "CWE-400", "count": 8, "exploited_in_wild": 1 }, ...],
        "dig_here": [{ "cve_id": "CVE-2023-44487", "kev": true, "epss_percentile": 0.9997 }, ...] } ] }
```

---

## `search_public_code`

Search public repositories for an **exact code string** and return where it appears — hunt
vendored / copy-pasted copies of known-vulnerable code. Returns **raw hits only**; you fetch and read
them to judge patched vs. unpatched vs. fossil. It makes no vulnerability judgment.

| arg | type | default | notes |
|---|---|---|---|
| `code` | string | — | **required** — a distinctive line or symbol, e.g. `"VP8LBuildHuffmanTable"` |
| `lang` | string | `c` | language filter |
| `limit` | int | `50` | max hits |

**Returns:** `count` and `matches[]` (`repo`, `file`, `url`, `snippet`).

```jsonc
search_public_code(code="VP8LBuildHuffmanTable", lang="c")
→ { "matches": [
      { "repo": "github.com/webmproject/libwebp", "file": "src/utils/huffman_utils.c",
        "snippet": "int VP8LBuildHuffmanTable(HuffmanTables* const root_table, ..." },   // patched signature
      { "repo": "github.com/onecoolx/picasso", "file": "third_party/libwebp-0.5.1/.../huffman.c",
        "snippet": "int VP8LBuildHuffmanTable(HuffmanCode* const root_table, ..." } ] }  // older signature
```

---

## `corpus_stats`

Corpus size and data freshness — no arguments.

**Returns:** `cves`, `kev_entries`, `epss_scores`, `latest_cve_modified`, `latest_kev_added`,
`latest_epss`, `data_age_days`, `stale`, `unembedded_summaries`.

```jsonc
corpus_stats()
→ { "cves": 364756, "kev_entries": 1629, "epss_scores": 341347,
    "data_age_days": 0.31, "stale": false, "unembedded_summaries": 0 }
    // point-in-time — the corpus grows daily; this call IS the live freshness source
```

---

## `find_attack_approaches`

Bug-bounty **mechanic transfer**: given a target, CVE, or bug class, retrieve the human *attack
approaches* — distilled from ~14,000 disclosed, paid reports — that transfer to it. Each is a
product-agnostic mechanic (`source → sink → trigger → preconditions → impact`), **novelty-ranked** to
surface the non-obvious move over the common playbook. **Reach for it when:** you're hunting a bug
class on a target and want the moves that have actually paid elsewhere.

| arg | type | default | notes |
|---|---|---|---|
| `query` | string | `null` | a concept/target, e.g. `"ssrf reaching cloud metadata"` — **provide this or `cve_id`** |
| `cve_id` | string | `null` | seed from a CVE's mechanism instead |
| `bug_class` | string | `null` | optional filter, e.g. `"ssrf"` |
| `tried` | string | `null` | what you've already tried — semantically excluded, so you get *what's left* |
| `limit` | int | `10` | max approaches |

**Returns:** `results[]` — each a mechanic card (`bug_class`, `trigger`, `source`, `sink`,
`preconditions`, `impact`, `weakness`) + the disclosed report `url` and `similarity`, plus **live
program-actionability** (`program_active`, `program_offers_bounty`) so you know it's still worth
filing. `trigger` is the move to adapt; `similarity` is conceptual, not proof the bug is on your target.

```jsonc
find_attack_approaches(query="ssrf reaching cloud metadata", limit=3)
→ [ { "program": "Reddit", "program_active": true, "bug_class": "SSRF",
      "trigger": "Provide an unfiltered URL to the preview endpoint so the server fetches it and returns metadata.",
      "url": "https://hackerone.com/reports/1960765", "similarity": 0.71 }, ... ]
```

---

## `find_continuations`

Position → continuations: given your **accumulated attacker position** (the capabilities you hold
mid-hunt, product-free), retrieve the concrete *next moves* real disclosed reports played from a
similar position — matched against full report bodies. **Reach for it when:** you've gained a foothold
and want "what did people do *from here*?" — not a product lookup. Every move is a **legal move, not a
finding.**

| arg | type | default | notes |
|---|---|---|---|
| `position` | string | — | **required** — capability-shaped, e.g. `"a trusted internal component can be made to emit its own secret over an attacker channel, blind"` |
| `program` | string | `null` | optional — scope to one program's reports |
| `limit` | int | `10` | max continuations |

**Returns:** `continuations[]` — each a `move_step` (the technique to transfer), `trigger`,
`bug_class`/`weakness`, the report `url` + program-actionability, and crucially `status: "UNVERIFIED"`
\+ a `decisive_check` you must run on the target. The corpus generates the move and the check; **the
target decides if it survives.**

```jsonc
find_continuations(position="a component can be made to emit its own secret over an attacker channel, blind")
→ [ { "move_step": "...", "trigger": "...", "status": "UNVERIFIED",
      "decisive_check": "Read the target: does the precondition this step needs actually hold here?" }, ... ]
```

---

## `assist_submission`

Submission & escalation co-pilot: paste a draft finding → a **grounded brief** synthesized from the
closest disclosed precedents — precedent/validity (is this an accepted, citable class?), what's
novel/stronger about yours, an escalation playbook, and submission framing. **Reach for it when:** you
have a finding and want to strengthen and frame it against real paid precedent before submitting.

| arg | type | default | notes |
|---|---|---|---|
| `finding` | string | — | **required** — your draft finding, in prose |
| `query` | string | `null` | override the retrieval text (default: the finding itself) |
| `limit` | int | `15` | prior-art reports to ground on |

**Returns:** `prior_art[]` (retrieved mechanic cards), `brief` (the synthesized write-up), and a
**citation guard**: `citations.{grounded, ungrounded}` + `citations_grounded` (true only when every
report the brief cited is in the retrieved set — *nothing fabricated*). `citations_grounded` guards the
**citations**, not your finding — it is **not** a verdict that the bug is real.

```jsonc
assist_submission(finding="SSRF in an image-fetch endpoint reaches cloud metadata, returns IAM creds")
→ { "prior_art": [ ... ], "brief": "1. PRECEDENT & VALIDITY ...",
    "citations": { "grounded": ["978823","1369312"], "ungrounded": [] }, "citations_grounded": true }
```

---

## `program_outcome_prior`

Minute-zero scope → outcome prior: given a bug-bounty program, the **empirical bug-class distribution
that historically landed** (paid, disclosed) on it, with lift over the global base rate — where to
dig, and where it rarely pays. **Reach for it when:** you've just scoped a program and want to tilt
effort before you've touched it. **Descriptive** (what landed), not a prediction.

| arg | type | default | notes |
|---|---|---|---|
| `program` | string | — | **required** — `"hackerone:gitlab"` (platform:handle) |

**Returns:** `n_reports`, `dig_here[]` (top classes by lift), `lands_rarely[]` (where NOT to look),
`full_distribution[]` (each `{class, pct, n, global_pct, lift}` — watch `n`: a high lift on a small
`n` is a thin prior), `examples_top_class`, and `caveats`. Withheld below a ~20-report floor.

```jsonc
program_outcome_prior(program="hackerone:gitlab")
→ { "n_reports": 257, "dig_here": [ { "class": "SSRF", "pct": 7.0, "n": 18, "lift": 3.4 }, ... ],
    "caveats": ["DESCRIPTIVE not prediction", "disclosure-selected", "payout not modeled"] }
```

---

For **authorized, defensive** security research and bug-bounty triage. Output is decision support,
not a substitute for your own verification — and never an exploit or payload.
