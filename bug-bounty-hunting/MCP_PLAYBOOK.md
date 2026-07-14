# MCP_PLAYBOOK: vuln-intel as a bug-hunting second brain

Single source of truth for driving the **vuln-intel MCP** during a hunt: how to turn its corpus tools into
landed findings, not CVE lookups. Self-contained; pairs with the `bug-bounty-hunting` skill (the cognition
and discipline layer), but stands alone.

---

## 0. The thesis (what the MCP is FOR)
It is a **memory of real mechanics to borrow and RUN**, not a CVE lookup. The value is three things a
stateless reasoner cannot self-generate: **watched-over-time** (priors / temporal / calibration),
**seen-many** (a disclosed-report plus CVE mechanism corpus), and **live-fused recon** (`observe`).
> The cardinal sin: using it as a status-code / severity-number checker. The job is not done until you have
> **transferred a mechanic onto a target and executed it**, or **read a fix to falsify an option**.

---

## 1. The operating loop (in order)
1. **Select a sandbox-winnable target.** `program_outcome_prior` (if n>=20) for the minute-zero prior; else select on *scope shape* (see §3). Target selection beats drill depth.
2. **Recon with a browser UA** (§5), then `observe` each live host. It is **async**: a cache miss returns `status="scanning"` immediately, so poll by calling `observe` again until `status="ready"` (SPAs take ~1-4 min); a recent scan returns instantly. Mine the WHOLE ready response (`endpoints[]`, `recurring_loci`, `internal_hosts`, `affected`-flags, `exploitation_signal`), not 2 fields.
3. **Version-match.** `check_technology` / `hunt_plan`; for any in-range KEV CVE, run a **non-destructive PoC oracle** (a safe version/endpoint probe, never a destructive exploit); do not just read `out_of_range`.
4. **`verify_cve_claim` BEFORE any claim.** Catches your own over-claims (§7).
5. **`enrich_cve`.** Full mechanism plus SSVC plus live PoC repos. Read it to decide *feasibility* (e.g. POST-vs-GET decides if an SSRF can deliver an RCE).
6. **Transfer-AND-EXECUTE.** `find_attack_approaches` gives `source -> sink -> trigger`; run those moves on the target (do not cite them). Loop with growing `tried=` (§4).
6b. **Stuck, or holding a messy pile of capabilities.** `find_continuations(position)`: describe your *product-free attacker state*, get concrete `move_step`s from full report **bodies** (the by-step layer, §4b). **Then immediately `search_vulns` the surfaced class against the target**: "mechanic plus proof it is live here" is the strongest where-to-dig signal. Orientation, NOT a finder; every result `UNVERIFIED`, so source-verify before claiming.
7. **`assist_submission`.** Transfers the *winning submission techniques* from accepted reports; execute them (referrer differential, key-reuse breadth, scope-containment), then file.

---

## 1b. Deep, multi-session hunts: the persistent memory tree

For driving ONE target across strings and sessions so the work COMPOUNDS (the tree loop, the tree-authoring
method, and the `hunt_memory_*` tools), use the **self-hosted memory MCP**: an optional free companion you run
on your own box. It holds your private hunt state and calls this corpus for the next move
(`find_attack_approaches`, `find_continuations`). The full method and tools live in that companion's own docs;
if you have not installed it, skip this and run the loop above.

---

## 2. Per-tool reference

| Tool | What it gives | Value | When / gotcha |
|---|---|---|---|
| **`observe`** | host to JS-bundle-recovered backend identity plus `endpoints[]` plus `recurring_loci` plus CVE join | **HIGHEST** | Lead with it on every live host. **Async: poll until `status="ready"`** (a cache miss returns `status="scanning"`). Mine endpoints plus affected-flags; they kill false-positive P1s. SPAs hide their backend from header-fingerprinting; observe recovers it. |
| **`program_outcome_prior`** | minute-zero bug-class prior for THIS program (lift, lands_rarely, example reports) | **HIGH** | A **disclosure-conditioned** prior (what got investigated / submitted / accepted / disclosed), not ground truth: "lands_rarely" means rare in this disclosed sample, not rare in reality. Use it to **reorder attention, never to eliminate a class**. Needs n>=20 or it is withheld; HackerOne-only. |
| **`find_attack_approaches`** | disclosed-report mechanic cards (source / sink / trigger / preconditions) | **HIGH** | The ideation plus transfer engine. Loop with `tried=` (§4). `bug_class=` filter is exact-match, so it easily returns 0; prefer query plus tried. A `cve_id` seed works off a *broad* CVE; a narrow seed gives diffuse results. |
| **`find_continuations`** | concrete `move_step`s from full report **bodies** matched to a product-free POSITION | **HIGH for orientation, NOT a finder** | The by-STEP twin of find_attack_approaches (by-card). Returns the payload-bearing step the card compresses away (a smuggling header, a code-leak-on-redirect, a name-XSS). **Pair with `search_vulns`** to confirm the class recurs for the target's product. Noise floor on commodity positions; phrasing-dependent; every move `UNVERIFIED` (§4b). |
| **`assist_submission`** | precedent-grounded submission brief plus escalation playbook; validates citations | **HIGH** | Use at submission time. EXECUTE the techniques it returns; do not just cite the precedent for a severity number. |
| **`hunt_plan`** | recon'd stack to dig-order plus `recurring_loci` per component | **HIGH (for chaining)** | Feed it the *internal* stack an SSRF reaches; it ranks which internal product has an unauth KEV RCE to chain into. |
| **`verify_cve_claim`** | per-assertion verdict (exists / in-range / severity / KEV) | **MED-HIGH** | Guardrail. Refutes "affects X" on a **product-NAME mismatch** even when the version is in range; re-run with the corpus's exact CPE string from `enrich_cve.affected[].product`. |
| **`enrich_cve`** | full CVE intel: SSVC, CVSS vector, affected ranges, **live PoC repos**, the mechanism | **MEDIUM** | Read the *mechanism* (POST vs GET, auth-required) to judge chainability: the differentiated bit plus PoC signal. |
| **`search_public_code`** | repos containing an exact code string | **MEDIUM** | "How was this fixed / who vendored it" plus credential/secret hunting. Underused. |
| **`search_vulns`** | ONE corpus search: `query=` fuses keyword plus semantic, `cve_id=` returns mechanism-siblings, `days=`/`product=` returns the recent high-risk window | **LOW-MED** | Commodity CVE data: confirm a version range or pivot by mechanism, not the primary discovery engine. `query=` fuses lexical plus semantic so phrasing does not decide recall; `product=` is CPE-name-resolved and carries `match.products` provenance. |
| **`check_technology`** | one product's version-resolved CVEs plus `match.products` provenance | **LOW-MED** | Single-product version resolution; keep the ambiguity/vendor guard. Distinct from `hunt_plan` (a whole stack). |
| **`corpus_stats`** | corpus freshness / coverage | info | Sanity check that the corpus is current before you trust a "nothing found". |

---

## 3. Cross-cutting disciplines (the rules that actually matter)

**Browser UA is call #1.** A default `curl/8.x` UA is bot-blocked, and many CDN/WAF "Access Denied" 403s are
**UA rules, not walls**. `-A "Mozilla/5.0 ... Chrome/125.0.0.0 Safari/537.36" -H "Accept: text/html,*/*;q=0.8"
-H "Accept-Language: en-US,en;q=0.9"` routinely reopens several times the surface on estates you would wrongly
call "hardened." For a real anti-bot fingerprint (e.g. an enterprise bot-manager), escalate to curl_cffi
TLS-fingerprint impersonation or a headed browser earning a valid session cookie.
*Does NOT bypass:* real origin blocks, app-WAF on payloads (SQLi keywords), gRPC/SNI gateways, auth.

**Read the fix / source to FALSIFY an option; do not fire blind probes.** Before blasting a target with an
exploit hypothesis, pull the patch commit (`enrich_cve` gives refs) or the source and check feasibility. A fix
that is a dependency bump to an HTTP-only fetcher makes a `file://`-SSRF architecturally impossible: killed in
two reads instead of a hundred blind probes.

**Transfer-AND-EXECUTE, never cite-for-severity.** `find_attack_approaches` / `assist_submission` hand you the
*technique* (how it was proven, framed, escalated). Run it on the target: an unrestricted-key finding becomes
submission-ready by *executing* the transferred referrer-differential and key-reuse-breadth techniques, not by
citing the precedent for a number.

**Verify before you claim** (the whole edge; the recurring false-positive shapes plus the check that kills each are in §7).

**Do not over-parallelize MCP calls.** The server has a small worker pool; bursting `observe` plus others
cascades into timeouts. One heavy call at a time; lightweight priors / verifies can pair.

**Mine the full response.** `recurring_loci` is the bug *shape* to hunt. `endpoints[]` is the real attack
surface. `affected` / `distinct_vendors` flags say which P1 badges are false positives. Reading 2 fields is the
amnesiac move.

**Target selection beats drill depth.** Sandbox-winnable means web/network-heavy scope
(`url`/`wildcard`/`ip`/`cidr`/`source`), a **low mobile ratio**, and self-hosted software (version CVEs land),
NOT a mobile-app or WAF fortress. Scope *sprawl* is not soft for major brands: they are all CDN-fronted. The
pro-signal is `ip`/`cidr`/`source` assets and self-hosted products; the anti-signal is monolithic CDN fronting.

**The sandbox wall.** Unauthenticated recon primes, culls, and strengthens submissions; it **walls at
exploitation** (auth, valid object IDs, WAF, blind read-planes). The paying bugs (BOLA, payment logic, auth)
live behind auth, so use your own authed environment (self-register plus capture a token, residential proxy,
OOB listener). Know which side of the wall you are on, and stop expecting an unauth P1 from a fortress.

---

## 4. `find_attack_approaches`: the ideation loop
Run it as a **real loop**, not once:
- Seed each call with everything attempted: `tried=[...]` (grows every round) novelty-ranks the moves you **have not** tried.
- **Vary the input type**: free-text query (richest), `cve_id` seed (off a *broad* CVE), `bug_class` (short token only; multi-word returns 0). Different framings surface different option sets.
- Re-query per **bug-class layer**: when one layer exhausts (access-control, then auth, then injection, then client-side, then supply-chain), pivot the query and grow `tried=`.
- A **corpus-thin** result (only loosely-related cards) is itself a signal: that angle is a dead end, do not grind it.
- Mine for what is **novel** (filter out cards you already hold); the gold is the non-obvious transfer (e.g. "the machine-to-machine secret is not in the web frontend, so decompile the mobile app" is a paid pattern).

---

## 4b. `find_continuations`: the position-to-continuations layer (what it is FOR)
The by-STEP twin of §4. Where `find_attack_approaches` matches a query to the distilled *card*,
`find_continuations` matches a product-free **POSITION** (your accumulated attacker *state*, stripped of product
names) against the full report **bodies**, returning the concrete *step/payload* the card compresses away (a
`Transfer-Encoding: chunked` smuggling header; a `?code=` leaked on redirect; an unescaped name rendered to an
admin). Every result carries the structural contract `{move_step, status:UNVERIFIED, decisive_check}`.

**Product-free, not constraint-free.** Strip *product names* (they cause superficial matches); **keep the
load-bearing constraints**, or retrieval precision collapses: blind vs response-readable SSRF, a GET-only
callback vs an arbitrary POST body, a name rendered to *another* tenant vs only to yourself, an OAuth *code* vs
an access *token*, an admin viewer vs a public one. A canonical position:
```
I control:             the input / object / token I hold
I can reach:           the surface / endpoint / internal host
I can observe:         response-readable? blind? OOB only?
I cannot currently:    the gate I'm stuck behind
The boundary to cross: whose data / privilege / tenant
Protocol constraints:  method, auth, encoding, redirect behavior
Already attempted:     feeds tried=
```

**What it IS, and what it is NOT.**
- It is a **priming / orientation / surface-selection** layer. It routes a hunt to the *precise* surface in minutes with a concrete, payload-bearing move, better than an unaided brainstorm at reaching the long-tail move.
- It is **NOT a bug-finder.** The real progress is always the *source-read* that follows. The tool is a smart map; it does not drive the car. Budget the verification time.

**The killer combo: `find_continuations` plus a corpus cross-check.** It surfaces a transferable mechanic
(e.g. "stored-XSS via a user-set *name*"); `search_vulns` then shows whether that class *recurs in the
identified product or family* in the corpus (recent same-shape CVEs). That is **corpus recurrence, not proof
the class is live on this deployment** (the exact distinction §7 exists to protect). Read it as a chain: the
continuation *proposes* the mechanic, `search_vulns` shows *corpus recurrence*, `observe` plus version
resolution show *target plausibility*, and a decisive source / config read or scoped live test shows whether it
is *real here*. Pairing the first two is the strongest *where-to-dig* signal in the stack; it is not the
finding. **Always pair them, and never stop at them.**

**Honest limits (state them, do not pretend):**
- **Noise floor.** Commodity-class positions (generic IDOR/XSS) return thin matches at the top; you wade past junk.
- **It reflects your framing back.** A sharp position retrieves a sharp move; a vague one retrieves noise. The phrasing skill lives in you.
- **It primes, it does not grant the bug.** A lead that looks strong still has to survive a source-read into a current-version gap. Treat every move as `UNVERIFIED` until you have reproduced its load-bearing step.

---

## 4c. When is a position genuinely EXHAUSTED? (the 5-point check)

How you *know* you have actually cleared a surface, not just gotten bored (walls are wins, but only a
*survived* wall counts):
1. Every material candidate mechanic reached a **decisive check** (source inspection, patch analysis, config confirmation, protocol constraint, or a scoped live test) and **died with evidence** (not "sounds unlikely").
2. You **re-looped `find_attack_approaches`/`find_continuations` with a growing `tried=`** across the bug-class layers (access-control, auth, injection, client-side), not just the first layer.
3. A comprehensive-state query returns **only off-target cards at high tried-similarity**: the corpus is echoing your own tried set back, nothing new.
4. The **sibling sweep is dry** (no untested endpoint / parameter of the same class remains).
5. The remainder is **gated by a NAMED external unblock or rule** (a credential you do not hold, a WAF, a scope boundary), written down, not vague.

Corollary, the foreign-object discipline: *the bug is whatever survives the foreign-object disambiguation*.
Prove a leaked / returned object is actually FOREIGN (not your own) before claiming cross-tenant.

---

## 5. Recon plumbing that makes the MCP usable (non-MCP, but required)
- **Browser UA plus Accept headers** on every curl (§3).
- **Subdomain enum**: crt.sh often blocks datacenter IPs, so fall back to **certSpotter** (does the heavy lifting), AlienVault OTX, HackerTarget. Note: these disclose your target-of-interest to a 3rd party (low-sensitivity, the names are public, but flag it).
- **Classify hosts** public vs private (`10./192.168./172.16-31.` is internal-only, so not reachable).
- **Bundle mining**: pull JS bundles, grep for API base hosts, `/api/...` route templates, cloud/API keys, `@scope/pkg` names (dependency-confusion), DSNs, internal URLs. Then **verify** (a leaked API key is only a finding if *unrestricted*; an unclaimed npm scope is only RCE if the build resolves from *public* npm).
- **Clean up `/tmp`**: multi-MB bundle downloads fill the disk fast.

---

## 6. Honest economics
Even expert engagements mostly land **P2-P4** (a blind SSRF capped by blindness; an unrestricted API key in the
low hundreds; access-control / over-privilege P3); **P1s are usually *open leads*** (credential hunts) not
landed, because they need auth or a non-front-end secret leak. Set expectations accordingly: the MCP sharpens
*where and how* to strike and *what not to waste time on*; it does not grant access.

---

## 7. Verification patterns (the checks that kill a false positive)
"Verify before you claim" is the whole edge. Below are the recurring shapes where a non-finding *looks* like a
finding, each with the single check that settles it.

- **Version-in-range is not exploitable.** A CVE that affects the installed version still needs its precondition met. Confirm the required setting or flag is actually on before you claim it.
- **Product-NAME mismatch.** `verify_cve_claim` can refute "affects X" even when the version is in range, because the corpus CPE names a different product. Re-verify with the exact CPE from `enrich_cve.affected[].product`, not the version alone.
- **Private-scope vs public-fallback (dependency confusion).** A `@scope/pkg` that returns 401 (not 404) on the public registry is a *private* scope with scoped routing: no public fallback, no RCE. Prove the public fallback resolves before claiming.
- **Prove a concrete capability, not mere presence.** A leaked API key is only a finding if it *does something*. But a `REQUEST_DENIED` refutes only the **tested** operation / API / origin / permission, not every possible use of the key. Demonstrate the capability you are claiming; a denial kills that attempt, not the credential.
- **"Unguarded" is not "exploitable" (the trust boundary).** A missing redirect-disable, sanitizer, or header-strip is only a bug if crossing it harms a *different* principal. Ask who controls the input versus who is harmed. If the attacker and the victim are the same party, no boundary is crossed.
- **Reachable is not vulnerable (the ground-truth origin).** A `200` can come from an SPA catch-all on the wrong host and read exactly like a finding. Confirm which host and origin actually served the bytes before you interpret them.
- **Trace the exact path you are claiming.** A look-unescaped sink is a bug if *any* attacker-reachable write path hits it unsanitized: find that one path to confirm. To refute, show that *every* reachable write path is sanitized, encoded, unreachable, or not attacker-controlled. A separate sanitized path proves nothing about the vulnerable one.
- **Your summary is not the bytes.** A "CONFIRMED" written off a *summarized* source-read is phantom judgment on your own tool. Read the actual call-chain or raw response; the exact code often refutes what the summary implied.
- **Your own confidence number has a stake.** If you scored the go/no-go, you had an interest in the answer. Have something with no stake re-score it against a strict rubric. The phantom judgment relocates all the way into the *measurement* itself.

> If a claim has not survived a check, it is not a finding yet, and that includes your own confidence numbers.
> **Phantom judgment relocates one layer deeper every time you secure a layer** (finding, then class-validity,
> then the decisive gate, then the metric itself). The fix is not to eliminate it; it is to **attach every
> confident claim to the cheapest check that kills it if it is wrong**, at every layer, run by something with no
> stake in the answer. That attachment is the discipline the whole stack rests on.

**The no-stake review, concretely** (so "something with no stake" is a procedure, not a vibe):
1. Give a second reviewer only the **raw evidence** and the claim, against a fixed rubric.
2. **Hide** the first pass's confidence and its desired conclusion.
3. Require it to name the **cheapest falsifying check** for the claim.
4. It returns `supported` / `unsupported` / `insufficient-evidence`, nothing else.
5. Prose confidence never overrides a **missing decisive check**: no check run means `insufficient-evidence`, not "probably real".
