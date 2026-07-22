---
status: working sheet (gold NOT yet achieved)
date: <!-- FILL:date --> <!-- date you start filling this sheet, YYYY-MM-DD -->
owner: vstantch
target: OpenSSF Best Practices Badge — GOLD level (project 0, on top of silver)
project_url: https://github.com/presidio-v/presidio-hardened-ikigov-assess
related:
  - plan/cii-silver-answers.md
  - plan/cii-passing-answers.md
---

# CII Best Practices — GOLD answer sheet (working)

Fill-in + roadmap for the **gold** tab at <https://www.bestpractices.dev/en/projects/13748>.
Covers only the criteria gold *adds* on top of silver. **Gold is a bigger lift than silver
was** — it is not "mostly documentation." Two genuine blockers typically remain (a second
*unassociated* contributor, and reproducible builds), plus a mechanical per-file header
pass and a handful of config/doc items.

`REPO` = `https://github.com/presidio-v/presidio-hardened-ikigov-assess`.

## Current standing

<!-- FILL:gold-standing -->
<!-- One short paragraph tallying where presidio-hardened-ikigov-assess actually stands: how many gold
     criteria are already Met (cite them), how many are small config/doc actions, and how
     many are real lifts still open. Be honest — do not pad the "Met" column. -->

---

## A. Already Met — cite and move on

| Criterion | Status | Justification |
|---|---|---|
| `two_person_review` | **Met** | Every change to `main` requires an approving code-owner review from someone other than the author. Enforced by branch protection (`required_approving_review_count:1`, `require_code_owner_reviews:true`, `require_last_push_approval:true`, `dismiss_stale_reviews:true`, `enforce_admins:true`) + `REPO/blob/main/.github/CODEOWNERS`. External reviewer `ceoofcyber` (write collaborator, different organization) provides independent review. <!-- FILL:review-gate-date --> <!-- date the gate went live; the criterion needs it to have actually been operating --> |
| `bus_factor` | **Met** | At least two people can sustain the project (maintainer `vstantch` + reviewer `ceoofcyber`), and continuity is org-backed — see `REPO/blob/main/GOVERNANCE.md#project-continuity`. |
| `access_continuity` | **Met** | Org-owned repo, OIDC / tokenless publishing where applicable, recoverable org-held signing key, documented release flow, staffed org — `REPO/blob/main/GOVERNANCE.md#project-continuity`. |
| `security_review` | **Met** | Independent security review within the last 5 years — <!-- FILL:security-review-cite --> <!-- link the audit report file in the repo and its date --> and the audit history in SECURITY.md. |
| `dynamic_analysis` | **Met** | <!-- FILL:dynamic-analysis-cite --> <!-- name the dynamic-analysis tool (fuzzer / sanitizer) and where it runs in CI, e.g. .github/workflows/ci.yml + fuzz/; state that it is applied before every release --> |
| `test_statement_coverage90` | **Met** | Statement coverage <!-- FILL:statement-coverage --> <!-- actual %, must be ≥90 -->, gated at ≥90% in CI. |
| `repo_distributed` | **Met** | git. |
| `test_invocation` | **Met** | `<!-- FILL:test-command -->` — documented in CONTRIBUTING local-verification block. |
| `test_continuous_integration` | **Met** | CI on every push/PR <!-- FILL:ci-matrix --> <!-- across which language/runtime versions -->. |
| `hardening` | **Met** | <!-- FILL:hardening-cite --> <!-- list the concrete hardening measures actually in place: e.g. TLS enforcement, bounded buffers, SHA-pinned Actions, digest-pinned base image --> |
| `crypto_used_network` / `crypto_tls12` | **Met** | TLS ≥1.2 with certificate verification on all egress. |

## B. Small actions — config / docs (mostly in your control)

| Criterion | Status → target | Action |
|---|---|---|
| `test_branch_coverage80` | **Met / Action** | Branch coverage <!-- FILL:branch-coverage --> <!-- actual %, must be ≥80 -->, measured and gated at ≥80% in CI. Enable per-metric enforcement in `.github/workflows/ci.yml` and branch measurement in the coverage config. |
| `code_review_standards` | **Action** | Document in `CONTRIBUTING.md#code-review`: PR-based flow, required non-author code-owner approval, and the checklist reviewers apply. |
| `small_tasks` | **Action** | Create a `good first issue` label and point newcomers to it from `CONTRIBUTING.md`. |
| `dynamic_analysis_enable_assertions` | **Action** | Ensure the dynamic-analysis / fuzz job runs with assertions enabled (e.g. no `-O` / `PYTHONOPTIMIZE`) and document that in CI. |
| `require_2FA` | **Action — coordinate first** | Enable "Require two-factor authentication for everyone in the organization" (Org → Settings → Authentication security). This is org-wide, not per-repo. **Coordinate before flipping it** — members without 2FA are removed from the org when it is turned on. Confirm every member has 2FA enrolled first. |
| `secure_2FA` (SHOULD) | **Met-with-justification** | State that members use TOTP / WebAuthn security keys, not SMS. Answer this only once `require_2FA` is actually enforced. |
| `hardened_site` | **Action — verify headers** | Confirm hardening headers (HSTS, X-Content-Type-Options, CSP where applicable) on the project sites. <!-- FILL:site-hosts --> <!-- which sites: the GitHub/PyPI project pages already send them; if there is a self-hosted site, name it and check its server config, otherwise scope the answer to the hosted project pages --> |

## C. Real lifts — the actual gold blockers

| Criterion | Status | What it takes |
|---|---|---|
| `copyright_per_file` + `license_per_file` | **Action — mechanical** | Add a 2-line `SPDX-License-Identifier: MIT` + `Copyright (c) 2026 PRESIDIO Group` header to every source file. Run `scripts/spdx_headers.py --apply` to stamp them, align the LICENSE holder to `PRESIDIO Group`, and add a CI lint job that guards new files. Touches every source file — mechanical but not zero. <!-- FILL:header-scope --> <!-- note which trees are covered (src, fuzz, tests) and any deferred set --> |
| `build_reproducible` | **Not met — real work** | Gold requires that **multiple parties can independently reproduce identical builds**. Do **not** claim this until it is true. Needs: a deterministic build (`SOURCE_DATE_EPOCH`, pinned build backend, normalized file ordering/timestamps) **and** at least one independent party reproducing the same artifact digest, plus a documented procedure. Until then, state plainly in SECURITY.md that reproducible builds are not yet claimed. Schedule as its own multi-step task. |
| `contributors_unassociated` | **Not met — strategic blocker** | Gold requires **two significant contributors from different organizations**, judged on contribution history. A reviewer is not automatically a *contributor* — the criterion looks at merged, non-trivial contributions. Path: have `ceoofcyber` (external, different org) author some non-trivial merged PRs so they qualify, **or** onboard another genuine external contributor. **This cannot be faked** — it gates the badge regardless of everything else and is usually the highest-effort item. |

---

## Recommended sequencing

1. **Quick wins now:** turn on branch-coverage measurement in CI (confirm ≥80%), pad
   statement coverage above 90%, write the `code_review_standards` doc, add the
   `good first issue` label, document `dynamic_analysis_enable_assertions`.
2. **Coordinated config:** enable org-wide `require_2FA` (after checking all members have
   2FA), then answer `secure_2FA`; verify `hardened_site` headers.
3. **Mechanical pass:** stamp SPDX + copyright headers on every source file
   (`copyright_per_file` + `license_per_file`) with a CI guard.
4. **Big rocks (parallelizable, slow):** stand up `build_reproducible`; grow
   `ceoofcyber` (or another external person) into a significant *contributor* for
   `contributors_unassociated`.

Gold is realistic but is a multi-week effort gated on (4). Silver is usually the honest
ceiling until the two big rocks land.

## Notes — do not over-claim

- Every "Met" URL under §A must resolve at the moment you attest.
- **Do not mark a gold criterion until it is genuinely closed.** Claiming reproducible
  builds that no independent party has reproduced, or a phantom second contributor who has
  not actually contributed, is a **false attestation** — on an audit-grade repo that is a
  serious integrity failure, not a shortcut. When in doubt, leave it unmet and say so.
