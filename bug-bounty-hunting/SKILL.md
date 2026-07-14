---
name: bug-bounty-hunting
description: >-
  Hunt vulnerabilities like an expert, not a linear software engineer: come at a target from the
  overlooked angle, reason by analogy and transfer proven attack mechanisms, attack the hidden
  assumptions and the seams between systems, drill to the mechanism, then keep it honest with proof
  and persistence (acceptance != impact, never quit at the first wall). Use when hunting bugs, doing
  bug-bounty recon or triage, mapping an attack surface, getting unstuck on a finding, deciding whether
  something is exploitable or submittable, or escalating past a wall. Pairs with the cloud vuln-intel
  MCP corpus tools (find_attack_approaches for analogical mechanism transfer, find_continuations for a
  product-free position to by-step moves, hunt_plan, check_technology, observe, enrich_cve,
  verify_cve_claim, search_vulns, program_outcome_prior, assist_submission) and, for deep multi-session
  hunts, an optional separate self-hosted memory MCP (hunt_memory_mirror/record). Triggers on "hunt for
  bugs", "bug bounty", "find vulnerabilities", "think like an attacker", "different angle", "overlooked
  approach", "is this exploitable", "attack surface", "escalate this finding", "hunt this target deeply".
license: MIT
metadata:
  author: rozetyp
  version: 3.0.0
  mcp-server: vuln-intel
---

# Bug-Bounty Hunting

Real bugs on mature targets are not found by reading code top-to-bottom like a software engineer.
They are found by **expert adversarial cognition**: coming at the system from an angle nobody designed
for, reasoning by analogy from a bug you have seen elsewhere, attacking the assumption the whole thing
rests on, and drilling to the mechanism. Then they are **kept honest** by proof and persistence, so the
creativity does not turn into fiction. Both halves are required: the generative half finds the
non-obvious thing; the disciplinary half stops a clever idea from becoming a fabricated report. This one
file carries both, plus the loop and the tool interface. Nothing else needs to be loaded.

## Think like an expert, not a software engineer

A software engineer asks *"how does this work?"* and sees the happy path. An expert asks *"what does
this assume, who does it trust, and what happens when that is false?"* and sees the failure surface. The
shift is always from intended behavior to implicit assumption, trust, and boundary:

| The situation | Engineer asks (happy path) | Expert asks (failure surface) |
|---|---|---|
| An API endpoint | "What does it return? How do I call it right?" | "What does it **assume** about its caller? What if that is false?" |
| An ID in a URL | "What record is this?" | "Who is allowed to see it, and does the **server** check, or just the UI?" |
| A login / token | "How does auth work?" | "Where is the token **minted**, who **validates** it, what is **replayable**?" |
| Two services talking | "What is the protocol?" | "Do they parse it **identically**? The bug is in the disagreement." |
| An error / 400 / 403 | "It rejected my input." | "**Why**, at which layer, and what does the rejection **reveal**?" |
| A version string | "It is v2.3.1." | "What did the patch change, and is *that path* reachable as deployed?" |
| A 'low' info leak | "That is a P4." | "What does it **let me do**? Map / oracle / building block for a chain?" |
| A feature flag / config | "That toggles X." | "Is the gate **server-side**, or can I flip it client-side and walk in?" |

### The generative moves (run each explicitly, do not wait for inspiration)

- **Attack the assumption, not the feature.** Every system rests on silent assumptions: *this input was
  validated upstream; this ID is unguessable; this header is set by the proxy; this check runs
  server-side; this runs only once; this field is a string.* Enumerate them, then violate each (send what
  upstream would have caught; increment the ID; set the header yourself; call the API directly; run it
  twice concurrently; send an object where a string was expected). A vulnerability is a **false assumption
  made load-bearing**, not a missing feature.
- **Hit the seam.** Bugs concentrate where two components meet and **interpret the same thing
  differently**: front-end vs back-end HTTP parsing (request smuggling / desync), client vs server
  validation (skip the client), two services parsing one string differently (confused deputy, allow-list
  bypass), URL/encoding/charset boundaries (normalization bugs), and the integration glue (webhooks,
  OAuth callbacks, SSO assertions, file imports), which is the least-tested, highest-trust code. Do not
  attack a hardened system; attack the boundary to a system that trusts it.
- **Follow the trust, not the data.** Draw the trust graph: who trusts whom, on what evidence. The
  exploit is almost always *make a trusted component act on behalf of untrusted me*: become the thing it
  trusts (spoof the internal header, ride the service account, replay the SSO assertion), or find where it
  trusts input it should not (the SSRF that reaches an implicitly-trusted internal service).
- **Reason by analogy: transfer a proven mechanism.** The unfamiliar thing has the **shape** of a bug you
  have seen before (a webhook URL is SSRF-to-metadata wearing a different hat; a recursive config merge is
  prototype pollution; a check-then-use on a balance is a TOCTOU race; a bearer token in a URL leaks via
  Referer/logs/history). Name the shape, then transfer the mechanic. Pull the closest disclosed mechanic
  with **`find_attack_approaches`** (a cross-product mechanism-transfer engine, novelty-ranked to surface
  the non-obvious move) and adapt its `trigger` to this target. Cross-domain analogies work too: a cache is
  shared mutable state (poisoning), a queue is a buffer (desync), a parser is a state machine (smuggle a
  transition).
- **Test the move you would dismiss: that is where the bug is.** The transfer tools exist to hand you the
  approach you would NOT have generated yourself. Your gut reaction (*"that is not how this works," "does
  not sound logical," "I have never seen that"*) is familiarity bias, and the surviving bugs hide exactly
  behind it. Load `tried=[every class you have burned]` to force the non-obvious set, take the move you
  would wave off, and run its `decisive_check` against the target. The bar to drop a corpus move is a
  FAILED check, never "it does not feel right."
- **Take the overlooked path.** Everyone crowds the glamorous RCE on the front door. Go where they do not:
  the deprecated v1 API still running unpatched, the mobile/desktop app's extra endpoints, the
  error/exception/timeout path, the old auth flow left enabled during a migration, the race window nobody
  thinks is reachable, and the boring breadth (authz, IDOR, cross-tenant isolation) where mature-program
  bugs actually survive. Often the move that finds the bug is the work others skip: actually reading the
  large JS bundle, standing up a real callback listener, registering a second account to test isolation.
- **Reframe the artifact as a capability.** Do not file by severity reflex. Ask *"what does this let me
  do?"* A source-map disclosure is a white-box map that re-prices every other lead; a verbose error is an
  oracle for blind injection; a leaked internal hostname is the next hop in an SSRF chain; a timing
  difference is a boolean oracle for enumeration.
- **Chain nothings into a finding.** Three observations that are each "not a bug" can be one real bug: an
  injection point **plus** a delivery mechanism **plus** a reachable backend is SSRF with impact. Hold the
  pieces together and ask what the combination enables, not whether each piece is exploitable alone.
- **Drill to the mechanism.** Never stop at the symptom. A 400, a 0-byte read, a redirect: go to the line
  of code / config / protocol step that produces it and ask *why*. A read returning 0 bytes for a file
  that cannot be empty is not a dead end, it is a signal that a hook sits in the path, which you find by
  reading the source, not retrying the payload. Every observation has a mechanism behind it; chase it down.

**When stuck, force a perspective shift.** Re-ask the question as four people, each surfacing what the
others hide: the **attacker** with six months and no scruples (what would they patiently chain?); the
**engineer** who built this at 2am under deadline (where did they cut the corner, trust the input, skip
the check?); the **auditor** who must *prove* it is safe (what can they not prove? that gap is your bug);
the **hunter in two years** (what will be obvious in hindsight about this design? go find it now).

Creativity cannot be fully proceduralized, but you can guarantee you ran the moves instead of stopping at
the first linear pass. On every non-trivial lead, make it mechanical: *assumption attacked? seam hit?
trust followed? analogy named (and `find_attack_approaches` queried)? overlooked path checked? reframed
as capability? chain considered? drilled to mechanism?*

## The loop

1. **Frame the engagement.** Scope vs out-of-scope, payout ceiling, traffic-ID header, stop-and-report
   rules. Knowing the boundary up front kills unpayable findings before you spend effort. If the program
   has >=20 disclosed reports, pull `program_outcome_prior` for the minute-zero prior: which bug-classes
   actually LAND here and which to skip, before you form a target you have no tacit knowledge of.
2. **Recon: ground in the REAL artifact.** `observe` the host; *read* the bundle/source for real
   endpoints, config, keys, auth logic. Never brute-guess what is in front of you. Verify your egress IP.
3. **Map to a ranked dig order and a written LEAD REGISTRY.** `hunt_plan` for the order plus recurring
   loci; `check_technology` per product. Write every lead down with a status and a next action.
4. **GENERATE the attack-approach map (the corpus's whole point; do NOT skip to confirming one lead).**
   For the *real* surface, run `find_attack_approaches` across each candidate bug-class angle (`query=` the
   target's actual capability, `tried=[classes already covered]` to force the non-obvious set), then
   `find_continuations` from your product-free POSITION for the concrete by-step moves. Each result is a
   legal move with a `decisive_check`, not a finding. Then `search_vulns` the class each move surfaced
   against THIS target: a transferable mechanic *plus* proof it is a live, recurring class here is the
   strongest where-to-dig signal the stack gives. THEN pick **one** and escalate it through the ladder
   before ever calling it dead, logging the lateral leads as you go, not chasing them.
5. **Verify the mechanism, not the acceptance.** Prove the backend *acted* (an out-of-band callback, data
   returned, a real second principal). `verify_cve_claim` any CVE assertion to catch hallucinations.
6. **Validate, then triage.** Apply "so what?": name the attacker action against a concrete victim, or it
   is not impact. Run the 7-Question kill-gate (one wrong answer kills the finding, move to the next
   class), then triage Tier 1 submit / Tier 2 document / Tier 3 dead-ledger / Tier 4 unexplored.
7. **Self-audit before you declare done** (checkpoints below).

## Deep hunts: drive one target off a persistent tree (optional)

For a target worth working deeply, especially across sessions, do not restart each time. Drive it off a
**persistent hunt-memory tree** so the work COMPOUNDS. This is the OUTER loop that wraps the one above; it
stalls every time a step is skipped (jumped targets, went manual, over-claimed). The tree tools
(`hunt_memory_*`) come from a **separate, optional, self-hosted memory MCP** you run on your own box, so
your target/finding data never leaves it. If you have not installed it, skip this and run the inner loop.

0. **Commit to ONE target.** Every target-hop costs tokens for nothing.
1. **Build or lift the tree first, then work FROM it, never from your head.** Distill sources oldest to
   newest into a few nodes/edges each (not a transcription); draw the **chokepoint chain**
   `[source] --leaks--> [credential] <--requires-- [each P1 gate]`; record every wall as an edge with its
   re-runnable `decisive_check`.
2. **Read the mirror (`hunt_memory_mirror`), then ABSTRACT.** Find the chokepoint (the one credential
   every P1 gates on) and the systemic pattern (e.g. "trusts the client"). Leverage lives here, not in
   single findings.
3. **Ask the corpus for the next string:** `find_attack_approaches(tried=recorded walls)` plus
   `find_continuations`.
4. **Pull ONE string with ONE agent:** hand it the tree position, the string, the tools, the discipline.
   If you are hand-grepping source yourself, you have left the loop.
5. **Verify it yourself:** a finding is not a finding until YOU reproduced its load-bearing claim.
6. **Interrogate the wall, THEN record it.** Before accepting any wall, attack it: is it real, or did I
   test the wrong vector? What assumption does it rest on, and what if that is false? What unconventional
   route around it have I not tried? Only a wall that survives that gets recorded (with its reopen check).
   Recording a wall is HYGIENE so you do not re-walk it, NOT an achievement.
7. **Next string, next agent, same tree. Compound.** You are done when you REACH IMPACT or have
   adversarially attacked every route, NOT when the map of walls looks complete. A tidy graph of walls is
   a FAILED hunt, not a finished one.

Two disciplines this adds: *one agent per string, evaluated before the next*, and *keep the operator at
the exploitation boundary* (the top finding on a live web target needs their session/phone; hand over the
one trigger, do not fake the land).

## Standing assumptions (defaults)

- Depth exists until proven otherwise. Running out of *easy* ideas is not target exhaustion.
- A claim of success is a hypothesis to falsify, not a result.
- A wall is a hypothesis to falsify, not a fact to record. Most walls are your own untested assumption.
- Acceptance != impact; version-vulnerable != exploitable; defeats-a-layer != achieves-impact.
- Knowing facts that *describe* the system is not a finding.
- The obvious path is picked over; the bug is in the overlooked angle or the boring breadth.

## Cardinal rules (non-negotiable)

**Discipline judges findings, not effort.** Every gate here answers *"is this signal a finding?"* None of
them answers *"should I send the next probe?"* That answer is **yes** until scope is exhausted or the user
says stop. "Stop at PoC" means stop escalating that class, not stop testing the others. If the user chose
"go deep" at the start, that authorization stands; asking "want me to continue?" mid-run is a stall.

- Never quit at the first wall. A 403/WAF is rung A, not death. Climb the ladder first.
- A wall is a detour, never a trophy. The only win is impact or a live lead. If a session's output is a
  clean map of walls, the hunt FAILED. And question every wall before you accept it: a 403 / "closed" /
  "patched" is a hypothesis to falsify (usually your own untested assumption), not a fact to file.
- Never declare victory after one finding. Keep digging; there is almost always more in the same place.
- Never confuse acceptance / 200 / version with impact. Prove the mechanism out-of-band.
- Never report a number you did not verify. `verify_cve_claim` before any severity/payout claim.
- Never use the transfer engine as a fact-checker. `find_attack_approaches` / `find_continuations`
  GENERATE approaches (the corpus's highest value); `verify_cve_claim` / `check_technology` / `enrich_cve`
  only CONFIRM one lead (its lowest). If you ran only the confirm tools on a single glamorous CVE and
  concluded "nothing," you ran the WRONG loop: go generate the approach map for the whole surface.
- Never conclude "nothing" from an anchored pass, and never drop a corpus move unTESTED. If you only
  chased the classes you already expected and they walled, you confirmed your priors, you did not hunt.
  Run the OPEN generative pass with `tried=` loaded with everything you burned; the bar to drop a surfaced
  move is a failed `decisive_check`, not "that does not sound right."
- Verify the ground truth before you read a result: WHICH host / origin / environment did the request
  actually hit? A 200 from the wrong host (an SPA serving its catch-all shell for an endpoint that does
  not exist) reads exactly like a finding. Confirm the target context before you interpret the bytes.
- Never trust your own summary over the raw output. Read the actual bytes.
- Never brute-guess when the real artifact is in hand. Read it.
- Never lose a lateral lead, never re-walk a confirmed dead end. Write both down.

## Verify the mechanism, not the acceptance

The single most-repeated correction: prove the mechanism, never the acceptance. Reachability is not
exploitation.

| You observed | That only proves | To prove impact you must show |
|---|---|---|
| Endpoint returned **200** | it is reachable | it performed a privileged action *for you* |
| Payload **accepted** (no error) | input was ingested | the backend **acted** on it (fetched/executed/returned) |
| **Version** matches a CVE | a lead exists | the vuln is reachable **as deployed**, with a PoC |
| A hardening flag is **bypassed** | one layer is down | data actually crossed (not still blocked by layer 2) |
| A **public key** wraps payment data | a layer exists | a concrete victim's data is decryptable/exposed |
| Admin UI **renders** | the page loads | the *server* authorizes the action (not a client flag) |

**Named false-positive traps** (a non-finding masquerading as a finding; learn the shape and the disproof):
- **URL echo dressed as reflection.** Your payload appears in the response because the body *is* the URL
  you sent. Disprove: confirm it is injected into a *different* context (HTML/JS/SQL), not echoed back.
- **200 without a leak.** Status differs from the baseline 403 so it looks like a bypass, but the body is
  byte-identical to baseline or carries no victim-identifiable data. Disprove: diff against an authorized
  response; a status change with an identical body is not access.
- **Server policy mistaken for a state oracle.** A path returns "blocked" for *every* input: it is a
  deny-list, not an existence oracle. Disprove: request something you *know* exists vs something you
  *know* does not; identical responses mean no oracle.
- **Own data vs victim data (the marker test).** An IDOR "works" but the data is *yours*, scoped to your
  session despite the attacker-supplied ID. Disprove: tag a **second account** with a unique random
  marker; if the response does not contain *that* marker, you are reading your own data.
- **Single-sample timing.** One slow response looks like blind injection; it was jitter. Disprove:
  interleaved n-sample baseline with 3+ distinct payloads; if the differential collapses, it was noise.
- **Stale cache.** Victim data cached by browser/proxy from a prior legitimate session. Disprove: a fresh
  incognito session; if it does not reproduce, it was a cache artifact.

**Prove it out-of-band.** For any "the server does X with my input" claim, instrument X and watch it
happen: SSRF/URL-fetch needs a hit from the target's **egress** on a listener you control (acceptance of a
metadata URL is nothing); injection needs **data back** or a timing/OOB signal proving execution;
isolation/IDOR/cross-tenant needs a **real second principal** ("isolated" judged from inside one tenant is
the assumption you were supposed to challenge). **Cross-validate every finding two ways** (a single signal
can be coincidence): time-blind SQLi with 3 distinct SLEEP variants; SSRF/RCE with an OOB DNS callback;
auth-bypass with the session persisting on the *next* request. **Prove ONE before the matrix:** confirm a
single instance works end to end before fanning out N payloads across M hosts. And **"defeats a layer" is
not "achieves impact":** trace the full chain to a concrete victim (a hardcoded *public* key defeats a
layer but does not decrypt a victim while transit is still TLS-protected; if your "secret" matches a
public sample, it is not a secret).

## Escalate past walls: never declare "dead" early

A wall (WAF / 403 / timeout / captcha / rate-limit) is the **first rung**, not death.

- **Rung A: proxied HTTP client.** A TLS-fingerprint-spoofing client (e.g. `curl_cffi`) over a
  **residential proxy**. Verify egress IP first.
- **Rung B: real-browser cookie handoff.** Drive a real browser past the JS/WAF challenge, hand the
  validated cookies to your client.
- **Rung C: full in-browser.** Run the whole interaction inside a headless real browser; every challenge
  solved natively.

Do not mark a target "blocked/dead" until Rung C. When you hit a defense you have beaten before, **reuse
the tooling you already built**; do not re-derive or hand-wave "defeat the WAF." Per-blocker, when one
vector fails the next move is *another vector to the same goal*, not "documented as not vulnerable":
- **WAF blocks the payload:** slow the pace, encode (URL/hex/base64/mixed-case), change injection context
  (cookie/header/JSON body), change HTTP verb, change content-type, try host-level bypass
  (`X-Forwarded-Host`, `X-Original-URL`), or probe the origin directly (find it via certificate transparency).
- **Rate limit:** IP rotation across regions, UA rotation, slower pace with jitter, distribute across TLS sessions.
- **Captcha:** is the field required? omit it / empty value / reuse one value (session-bound?), OCR, or a paid solver (a real attacker pays it).
- **Timing oracle too slow:** different injection point, alternate oracle (error-based / lock-based), OOB DNS callback, or run the dumper unattended and deliver partials.

## Manage leads and triage

**Drive ONE lead to ground, log the rest.** The two opposite failures are thrashing (sampling-tour: probe
-> 403 -> next, finish nothing) and tunnel-vision (drill one path to "no" while dropping every lateral
lead). Both are fixed by one artifact, a **written lead registry**: per lead an id, one-line description,
**status**, and concrete **next action**. Statuses: `DRIVING` (the one lead you finish now, exactly one),
`OPEN` (a real lateral lead written at the branch point so it is not lost), `DEAD` (confirmed, with the
evidence that killed it), `PARKED` (needs a capability you do not have yet). A dead-end is only valid if
killed at the **right rung** ("dead at Rung A" is not dead); re-open it if you later gain a capability that
changes the premise.

**Depth vs breadth on a mature target.** The bug you *want* (RCE, file-read) is picked over; the bugs that
**survive** are in the breadth (authz, IDOR, cross-tenant isolation), tested with a real second principal,
not introspected from inside one account. The program's own #1 stated concern is often what is left
structurally untested. **Sister-app sweep:** when you confirm a vuln on app A, the same template almost
certainly sits on siblings B/C/D on shared infra (same IP/LB/TLS-cert/cookie-name/login-HTML); sweep all
siblings with the same payload immediately: that is a class finding, not one bug.

**The 7-Question kill-gate** (run per finding, in order; one wrong answer kills this finding and you move
to the next test class, which is not stopping the engagement):
1. **Usable right now, step by step?** Write it as a copy-pasteable request that *does something on the server*. Cannot write the request -> kill.
2. **On the program's accepted-impact list?** Maps to a listed exclusion -> kill.
3. **Root cause in an in-scope, production asset?** (not `*.internal`, not staging, not a third-party SaaS they merely use) -> else kill.
4. **Realistic privilege?** "Admin can do X" is centralization risk -> kill. "Non-admin can do what only admin should" is valid.
5. **Already known / intended?** Check disclosed reports, security issues, changelog, API docs -> if acknowledged, kill.
6. **Impact beyond "technically possible"?** Show the actual leaked data / executed command / cross-user record, not a 200, not `alert(1)`, not a DNS ping. If only "technically possible" -> **downgrade**, do not kill.
7. **Not a known-invalid class?** (never-submit list below) -> else kill.

**Never submit alone** (it dents your validity ratio): missing security headers (CSP/HSTS); missing
SPF/DKIM/DMARC; GraphQL introspection alone; banner/version disclosure without a working exploit;
clickjacking on non-sensitive pages; CORS wildcard without a credential-exfil PoC; logout/login CSRF;
self-XSS; open redirect alone; SSRF DNS-callback only (no internal service/data); host-header injection
alone; rate-limit on non-critical forms; internal IP in an error; weak TLS ciphers; missing cookie flags alone.

**Conditionally valid: chain required** (build the chain end-to-end first, then report):

| Alone (nothing) | + chain | = |
|---|---|---|
| Open redirect | OAuth `redirect_uri` -> auth-code theft | ATO (Critical) |
| CORS wildcard | credentialed request exfils PII | High |
| CSRF | sensitive action (funds / email / delete) | High |
| SSRF DNS-only | internal service access + data returned | Medium+ |
| Host-header injection | password-reset email uses injected host | High |
| Self-XSS | CSRF to fire it on the victim | Medium |
| Subdomain takeover | OAuth `redirect_uri` registered there | Critical |
| GraphQL introspection | auth-bypass mutation or IDOR on `node()` | High |

**Before you label anything Critical/High**, answer each as a one-liner or the severity is wrong: did I
validate the *full* chain to attacker impact, or only one primitive in the middle? What does the attacker
walk away with, in one concrete sentence? Reproduced end-to-end *twice*? Any inheritance/signature/audience
gate still blocking the chain? Critical means impact-demonstrated, not impact-inferable.

**Then triage by payout reality:** Tier 1 submit (proven, in scope, pays; run `assist_submission` for
prior-art plus citation guard, only now); Tier 2 document, do not submit (real but will not pay; submitting
burns a slot); Tier 3 ledger (confirmed dead, never re-walk); Tier 4 backlog (honest unexplored).
**Retraction discipline:** if a submitted finding stops reproducing, self-retract with a short appendix
(original signal -> disproving evidence -> why it looked real). A self-retraction reads "this researcher
validates their own work"; a triager-retraction reads "this researcher submits noise."

## Failure modes: scan this list when a hunt stalls

The meta-pattern behind all of them: the agent declares victory and wants to write the report; the honest
move is to go deeper. The urge to wrap up is the signal to keep going.

1. **Premature victory.** You announce success and offer the report off the first minor thing. A finding is the *start* of work; keep digging the same place.
2. **Excitement about non-findings.** You present endpoints/versions/hostnames/config as wins. Knowing facts that describe the system is not impact; apply "so what?" first.
3. **Acceptance mistaken for impact.** "Returned 200 / accepted / version matches" treated as exploitation. Prove the backend acted.
4. **Fabricated severity or dollar figures.** A confident severity/payout on an unproven finding. It is a hypothesis until live-retested; `verify_cve_claim` first.
5. **Shallow coverage.** You judge a result dead without reading all of it, or extract one item and stop. Read all of it; when you find several of a thing, check every one.
6. **Thrashing / sampling-tour.** Jump between leads, drive none to ground. Pick one and finish it.
7. **Giving up at the first wall.** A WAF/403 marks the target "dead." Escalate A->B->C before declaring dead.
8. **Tunnel-vision while the mapped surface sits untouched.** Periodically zoom out: "what did I enumerate and then ignore?"
9. **Depth-first on the glamorous exploit.** On a mature program the surviving bugs are the boring breadth (authz/IDOR/cross-tenant), tested with a real second principal.
10. **Blind guessing instead of reading the artifact.** Brute-guessing paths while the real API surface sits unread in a bundle. Ground every move in the observed artifact.
11. **Dropped earlier leads.** You push for a "complete picture" while flagged leads sit un-investigated; a 401 may mask an unauthenticated path. Re-mine your own backlog before declaring done.
12. **Did not leverage an acquired asset.** You get an account/credential/session and treat acquisition as the finish line. Ask what previously-closed doors it now opens.
13. **Wrong instrumentation -> false-negative dead ends.** Recon without the proxy, fingerprinting your own IP, misreading blocks as "dead hosts." Fix the method before trusting the result.
14. **Trusting your own summary over the raw output.** If the human keeps out-noticing you in your own evidence, you are narrating, not reading.
15. **Trusting a tool/CVE match without checking product identity.** An automated "match" can be a different vendor's same-named product; always confirm the product before you cite a CVE.

## Self-audit checkpoints (run on yourself, out loud)

- **Only tried the obvious angle?** Which assumption have I not attacked? What is the analogy to a known bug? What seam have I not hit? Did I run `find_attack_approaches` for an overlooked move?
- **Before "I found it":** What is the PoC? What does an attacker *do* with this? Acted, or just accepted?
- **Before writing a report:** Tier 1 (pays) or am I dressing up Tier 2? In scope?
- **Feeling excited?** Impact, or excitement about *describing* the system? Apply "so what?" cold.
- **Hit a wall?** Is it even REAL, or did I test the wrong vector / assume something I never checked? What does it assume, and what if that is false? What route around it have I not tried? Which rung am I on?
- **About to record a wall?** Because it is genuinely dead, or because filing it *feels* like progress? If my session output is mostly walls, I mapped, I did not hunt.
- **About to call it dead?** Did I read *all* of it? A result that "cannot be empty" being empty is a signal.
- **Been going a while?** Am I circling? Re-read my backlog for abandoned leads. Zoom out: what did I enumerate and then ignore?
- **Acquired an asset?** What previously-closed doors does it open now? Acquisition is not leverage.
- **Confirmed a vuln?** Do sibling apps on shared infra share the template? Sweep them with the same payload: that is a class finding.

## Scope and operational safety (read before you touch the target)

- **Read out-of-scope first.** Common exclusions that silently kill findings: WAF bypass as a finding, internal-IP/version disclosure, known-CVE-without-PoC, self-XSS, missing headers. Check before investing.
- **Target selection is reasoning, not reflex.** Prefer programs where your edge is fresh, AI agents are not banned, contestation is low, credentials are provided, the payout ceiling is real.
- **Identify your traffic** with the program's required header/tag.
- **Route recon through a residential proxy;** verify egress; never fingerprint your own IP.
- **Never leak your identity.** A throwaway/branded subdomain or tool can leak your real name into the target's logs, irreversibly. Use a neutral domain.
- **Honor "stop and report" rules.** If a program says "report a found credential, do NOT probe its scope," stop at discovery; probing trips alarms and gets access revoked.
- **Own-accounts-only, non-destructive, verify-before-claim.** The operator is at the exploitation boundary (live sessions, browser enroll, captcha, phone OTP); the tools prime and prioritize, the operator lands.

## Working with the vuln-intel MCP tools

The tools are a **fact substrate, not a verdict**: `similarity` is conceptual, a 200 is reachability, a
version match is a lead. The tools lay out facts; you supply the expert reasoning, then verify it.

| Step | Tool | What it gives the hunt |
|---|---|---|
| **Minute-zero prior** | `program_outcome_prior` | which bug-classes historically LAND on this program and what to skip (lift over base-rate). Needs >=20 disclosed reports, descriptive not predictive |
| Recon a live host | `observe` | the real bundle/endpoints; do not guess |
| Rank the dig order | `hunt_plan` | one ranked order plus recurring loci; do not sampling-tour |
| Version-specific CVEs | `check_technology` | affected / out-of-range / unconfirmed; never a silent zero |
| **GENERATE approaches (by-card)** | `find_attack_approaches` | transfer a proven mechanism from real paid reports; novelty-ranked to the non-obvious; `query=` the real surface, `tried=[classes done]` to force what you have not thought of |
| **GENERATE moves (by-step)** | `find_continuations` | your product-free POSITION to concrete `move_step`s from real report BODIES; every result UNVERIFIED plus a `decisive_check` |
| **Prove the class is LIVE here** | `search_vulns` | CVE/advisory search by concept/CWE (fuses keyword plus semantic; also `cve_id=` for mechanism-siblings, `days=`/`product=` for the recent window). The killer combo: run it on the class `find_continuations` surfaced |
| Dig one finding | `enrich_cve` | full card: KEV/EPSS/SSVC plus temporal plus stability |
| **Fact-check a claim** | `verify_cve_claim` | catch hallucinations before they reach a report |
| Vendored/copied vuln code | `search_public_code` | who copy-pasted a known-vulnerable line; RAW hits, you fetch and read to judge unpatched-vs-fossil |
| Draft the submission | `assist_submission` | prior-art plus citation guard (Tier 1 only) |
| Compound across sessions | `hunt_memory_*` *(optional, separate self-hosted memory MCP)* | read your tree as a mirror; record every lead AND every wall (plus its reopen check) so the next run inherits, not restarts |

## Sources

The generative cognition and failure modes are distilled from real bug-bounty / red-team engagement logs.
The operational artifacts (the 7-Question kill-gate, the never-submit list, the conditionally-valid chain
table, and the per-blocker escalation ladders) are adapted from the MIT-licensed Claude-BugHunter
(`triage-validation` plus `redteam-mindset`), kept lean: the high-ROI gates, not the full machine.
