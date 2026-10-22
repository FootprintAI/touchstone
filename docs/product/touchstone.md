# PRD: Touchstone — paste a vendor's URL, get an evidence-graded CVE report

**Date:** 2026-10-22
**Status:** draft
**Owner:** hsinatfootprintai
**Name:** Touchstone. Repo `FootprintAI/touchstone`, CLI `touchstone`, npm `@footprintai/touchstone` (the unscoped npm name is taken)
**Repo split:** standalone OSS project (Apache 2.0, proposed). Bundling with
the Containarium coding agent is Phase 2 (see "Later phases"). Litmus: a
single security reviewer with a laptop wants this with no platform at all,
so the engine is OSS. Hosting, scheduling, history and tenancy around it
follow the existing `licensing.md` line (cloud).

## Problem

A company that buys or integrates a third-party web product (SaaS vendor,
agency-built site, embedded widget) has no quick, honest way to answer
"is this vendor running software with known CVEs?" Today the reviewer:

- **Sends a security questionnaire** and waits days or weeks for answers
  the vendor writes about itself.
- **Runs tools built for site owners.** Nuclei, ZAP and Nikto send active
  probes, which is unauthorized scanning against a site you don't own.
  Wappalyzer/WhatWeb identify technologies but stop before CVEs.
  Dependency-Track, Trivy, Grype and OSV-Scanner need an SBOM or source
  tree the reviewer usually doesn't have.
- **Pastes version strings into NVD by hand.** That's slow, and it produces
  false positives: distro backports keep old version numbers, and NVD's
  analysis backlog leaves many CVEs without product/version data.

What's missing is a tool that **uses the best evidence available about a
site** (a published SBOM/VEX, then a linked source repo, then passive
fingerprinting) and **says how sure it is** about each finding, without
sending a single request a normal browser wouldn't send.

**Who hurts and how often: unknown, no evidence collected yet.** No user
quotes, tickets or usage data exist for this. The problem statement rests
on assumptions A1 to A3 below, and the first action is to validate them.

## Target user

**Third-party risk reviewer:** a security engineer, procurement or
vendor-risk analyst, or an engineering lead who has to approve a vendor or
integration. Job to be done: *"Before I sign off on this vendor, tell me
what known vulnerabilities their public-facing software likely has, with
evidence I can cite and send to the vendor."*

Not the target (deliberately): the site owner checking their own site.
Dependency-Track, Trivy and Dependabot already serve them well.

## Success metrics

| Metric | Baseline | Target (first 90 days after MVP) |
|---|---|---|
| **Precision** of High/Medium-confidence findings on a hand-labelled corpus of 30 sites | unknown, build the corpus first | ≥ 90% are true (vulnerable version actually present, CVE applies) |
| **Coverage**: share of a fixed list of 100 SaaS vendor URLs where the tool produces at least one finding source (SBOM, repo or fingerprint) | unknown, instrument first | ≥ 70% |
| **Time to report** for one URL, end to end | Manual review: unknown, ask the 5 interviewees (A1) | p50 ≤ 60 s, p95 ≤ 3 min |

Precision is the metric that matters most: a vendor report full of false
alarms destroys trust in the tool and damages the reviewer's relationship
with the vendor.

## MVP scope — the core journey

> A reviewer pastes `https://vendor.example.com` into a web page (or runs
> `touchstone https://vendor.example.com`). Within a minute they get
> a report listing the components detected, where each came from, the
> confidence tier, and the applicable CVEs ranked by known exploitation.
> They export it as Markdown/JSON to attach to a vendor review ticket.

Confidence tiers used throughout:

| Tier | Source | Meaning |
|---|---|---|
| **High** | Vendor-published SBOM (CycloneDX or SPDX), with VEX if present | The vendor declared it |
| **Medium** | Public source repo linked from the site, scanned at its latest release tag | Declared source, may differ from what's deployed |
| **Low** | Passive fingerprint of the page and the assets it loads | Inferred from outside |

**Hard rule for every story: passive only.** The tool sends only requests
a browser loading the page would send, plus fetching well-known discovery
paths (`/.well-known/security.txt`, SBOM discovery locations). It never
sends exploit or CVE-test payloads, never brute-forces paths, and
identifies itself with a descriptive `User-Agent`.

### Story 1 — Discover published evidence (P0)

**Story:** As a vendor-risk reviewer, I want the tool to find any SBOM,
VEX or source-repo link the vendor publishes so that findings rest on the
vendor's own declarations wherever possible.
**Acceptance criteria:**
- [ ] Given a URL, the tool checks `/.well-known/security.txt`, the
      SBOM-discovery locations listed in the design doc, HTML `<link>`/`<meta>`
      tags, and repo links on the page, and records every location it
      checked and the result (found / not found / error)
- [ ] A CycloneDX 1.5+ JSON or SPDX 2.3 JSON SBOM found at any of those
      locations is parsed. A fixture site serving a known SBOM yields
      exactly the components in the fixture
- [ ] A VEX document (CycloneDX VEX or OpenVEX) found alongside it is
      parsed and attached to the matching components
- [ ] The total number of requests per scan is capped (default 50,
      configurable) and is shown in the report

### Story 2 — Match components to CVEs, honoring VEX (P0)

**Story:** As a reviewer, I want each detected component matched to known
CVEs, minus the ones the vendor has declared not affected, so that the list
reflects real exposure.
**Acceptance criteria:**
- [ ] Components with a package URL (purl) are matched against OSV.dev.
      Components with only a CPE fall back to NVD
- [ ] A component whose VEX status is `not_affected` or `fixed` for a CVE
      shows that CVE as suppressed, with the vendor's justification, and it
      is excluded from the counts
- [ ] Each CVE carries a CISA KEV flag and an EPSS score. The list is
      sorted KEV first, then by EPSS descending
- [ ] With the CVE sources unreachable, the scan completes and the report
      says which source failed. It never shows "0 CVEs" as if clean

### Story 3 — Scan a linked or supplied source repo (P0)

**Story:** As a reviewer of an open-source-based vendor, I want the tool to
scan the vendor's public repo when no SBOM is published, so that I still
get declared dependencies rather than guesses.
**Acceptance criteria:**
- [ ] A public GitHub/GitLab repo URL, found on the site or supplied by the
      user, is scanned at its latest release tag (falling back to the
      default branch, which the report labels as such) using the repo's
      lockfiles
- [ ] Findings are labelled Medium confidence, with the repo, ref and
      lockfile path as evidence
- [ ] A repo with no lockfile reports "no lockfile, dependencies not
      resolvable" rather than guessing versions from manifest ranges

### Story 4 — Passive fingerprint fallback (P0)

**Story:** As a reviewer of a vendor that publishes nothing, I want a
best-effort fingerprint of the site so that I get some signal, clearly
marked as inferred.
**Acceptance criteria:**
- [ ] Loads the page and the scripts/styles it references (same-origin and
      CDN), and detects JS libraries and versions using Retire.js-compatible
      signatures plus version-revealing response headers
- [ ] Every fingerprint finding is labelled Low confidence and shows the
      exact evidence (URL plus matched string or header)
- [ ] Server-banner versions (e.g. `Apache/2.4.38`) carry a visible
      "may be backported by the OS vendor" caveat
- [ ] Against the labelled corpus, the request log shows no requests
      beyond the page load set and the Story 1 discovery paths

### Story 5 — Report and export (P0)

**Story:** As a reviewer, I want one report I can read in the browser and
attach to a vendor ticket so that the finding is shareable and citable.
**Acceptance criteria:**
- [ ] The web page has one URL input and shows: detected components grouped
      by confidence tier, CVEs per component, the KEV/EPSS ranking, the
      evidence for each finding, and the list of locations checked
- [ ] The same engine runs as a CLI and produces identical findings (same
      fixture site → identical JSON from both)
- [ ] Export to Markdown and to a JSON document with a published,
      versioned schema
- [ ] Every report carries a timestamp, tool version, CVE-data snapshot
      date, and a fixed disclaimer that Low-confidence findings are
      inferred and unverified
- [ ] Reports are not stored or published by the tool. The web
      deployment keeps no scan history

5 P0 stories. The JSON schema in Story 5 is what makes the Phase 2 bundle
cheap: the coding agent consumes the report, it doesn't re-implement the
scan.

## Later phases

**Phase 2: bundle with the Containarium coding agent (P1)**
- **Catalog skill**: `touchstone` as a skill in the agent catalog,
  running the CLI in a box with run-scoped credentials. Gives the hosted
  product a third-party-risk use case, and inside a box the scan gets
  network egress control and a run audit trail
- **Dependency-intake check**: when the coding agent is asked to add a
  third-party SDK/service to a repo, it runs the check on the vendor and
  puts the report in the PR description
- **Upstream fix PR**: when a High/Medium finding is in a vendor's *public
  OSS repo*, the issue-to-PR crew drafts a dependency-bump PR for the
  vendor to review. Only after a human approves, because it acts on
  someone else's project

**P1, other**
- **Re-scan on new CVEs**: a saved vendor list re-checked when OSV/KEV
  changes, with alerts. The hosted/scheduled form is cloud scope
- **Batch mode**: CSV of vendor URLs → one summary report
- **"Ask the vendor" template**: generate a request asking the vendor for
  their SBOM/VEX, pre-filled with Low-confidence findings to confirm

**P2**
- **PDF export** for procurement packets
- **Container-image SBOMs** when a vendor publishes image references

## Out of scope

| Item | Why it stays cut |
|---|---|
| Active probing, exploit checks, Nuclei templates, port scanning | Unauthorized against sites the user doesn't own. Being passive is the product's differentiator and its legal footing |
| Authenticated or behind-login scanning | Needs vendor credentials, which means vendor cooperation, which means they could send an SBOM instead |
| Public vendor scores, leaderboards, published reports | Publishing inferred vulnerabilities about named companies carries defamation and disclosure risk. Reports stay private to the person who ran them |
| Self-scanning for site owners | Dependency-Track, Trivy, Dependabot already do this well |
| Our own CVE database | OSV, NVD, KEV and EPSS are the sources. We match, we don't curate |
| Proving exploitability | Requires active testing. VEX is the only exploitability input |

## Open questions & assumptions

**Assumptions (unvalidated, no evidence yet):**
- **A1:** Vendor-risk reviewers check vendors' public software by hand
  today and would use this. *Validate:* 5 interviews with security or
  vendor-risk people, including FootprintAI customers, before Story 1
  starts. Ask how long a review takes (baseline for metric 3)
- **A2:** Enough vendors publish an SBOM or link a public repo that the
  High/Medium tiers aren't empty in practice. *Risk:* if almost none do,
  the product is mostly the Low tier, which is Wappalyzer plus Retire.js.
  *Validate:* the 100-vendor coverage survey (metric 2), run by hand
  before building Story 1
- **A3:** Passive fetching of public pages plus well-known paths is
  legally acceptable in our target markets. *Validate:* legal review of
  the passive-only rule and the report disclaimer

**Open questions (defaults in brackets):**
1. **SBOM discovery standard:** which discovery locations count? The IETF
   SBOM-access draft and CISA's SBOM-sharing work were cited from memory
   and their current status is unverified. [Check in `/architect-design`.
   MVP supports whatever is standardized plus `security.txt` pointers]
2. **Engine language:** Go or TypeScript (Retire.js signatures are JS)?
   [Decide in `/architect-design`]
3. **Hosted web page:** do we run a public instance, given that it makes
   outbound requests on users' behalf (abuse vector)? [No public instance
   in MVP. Self-host and CLI only, hosted comes with Phase 2]
4. **Repo home:** new `FootprintAI/touchstone` repo, or a pack inside
   Containarium? [New standalone repo, so the OSS project stands alone]
5. ~~Project name~~ Resolved 2026-10-22: Touchstone
