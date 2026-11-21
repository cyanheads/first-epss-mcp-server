---
name: first-epss-guide
description: Gates and workflows for the epss_* tools (FIRST EPSS). When EPSS answers a question and when an NVD or KEV source must, where score dates and offsets come from, when batch and candidate paging is done, why discovery pages are not EPSS-ranked, and how to tell a model change from real score movement. Use when triaging a CVE list or scanner export, explaining an EPSS change, or finding high-likelihood or newly added CVEs.
license: Apache-2.0
metadata:
  author: cyanheads
  version: "1.1"
---

## Scope

EPSS is a likelihood forecast and nothing else. No epss_* tool retrieves CVSS (epss_prioritize_cves only echoes the value the caller supplies), CVE descriptions, affected products, vendors, or known-exploited status, and epss_query_threshold has no product, vendor, or keyword filter.

- **Product- or vendor-scoped questions** ("high-EPSS Apache CVEs") start at an NVD/CPE source such as nist-nvd-mcp-server: resolve the CVE IDs there, then score them here.
- **"Is it being exploited?"** is a question for CISA KEV, which cisa-cybersecurity-mcp-server covers. A score near 1 is still a forecast and a KEV listing is evidence, so report the two separately.
- **Severity** comes from the scanner export or an NVD source. epss_prioritize_cves uses only the CVSS base score the caller passes in.

## Where each value comes from

| Value | Source | Notes |
|:---|:---|:---|
| Score date | each row's `date`; `provenance.scoreDates` | Omitting `date` returns the latest published day, which can be the previous UTC day. Read `date` before calling anything "today's score". |
| `nextBatchOffset` | previous batch response | Present only while work remains. |
| `pagination.nextOffset` | previous epss_query_threshold response | A candidate position, not a count of matches. |
| `previousAnchorDate` | each epss_get_timeseries item | Anchor for the adjacent earlier 30-day window. |
| `modelVersion`, `modelVersionSource` | each row | `csv_header` is verified, `published_schedule` is inferred, `unavailable` is unknown. |

## Gates

**Before submitting a batch**

1. **Collapse to unique CVEs first.** The 5,000-entry ceiling counts submitted entries, duplicates included, so per-host scanner rows can exceed it even when the unique set is small.
2. **Use one severity per CVE.** `epss_prioritize_cves` checks the entire submission for conflicting values, including a supplied score paired with an omitted one. Resolve each group in the `conflicting_cvss` recovery hint before resubmitting. `null` denotes an omitted score, and row positions are zero-based in the original `cves` array. Scored CVEs without caller severity land in `epssOnly`.
3. **Don't ask for a date that hasn't been published.** That includes today's UTC date before FIRST publishes it, which fails with `snapshot_unavailable`; a date after today fails argument validation instead. Omit `date` to get the latest available day.

**While paging**

4. **A batch is done when `nextBatchOffset` is absent.** `deferredCount: 0` does not mean done. A near-full batch comes back `budgetLimited`, with already-processed entries withheld and a `nextBatchOffset` even though nothing was deferred. Take the continuation `date` from the first response's `provenance.scoreDates`, so a run that crosses FIRST's daily publish stays on one snapshot.
5. **A year-filtered search is done when `hasMore` is false.** The first pages can have no exact-year matches because FIRST's candidate search also matches those digits elsewhere in the ID. When `nextOffset` is present, keep the filters and applied `limit`. Use the returned score date unless the query uses `addedWithinDays` (gate 9).
6. **Keep `limit` at a few hundred.** A larger page is cut to fit the byte budget. `nextOffset` then points back at the first withheld row, so the next call fetches those rows again.

**Before drawing a conclusion**

7. **Treat a missing score as unknown, never zero.** EPSS v1 snapshots from 2021-04-14 through 2022-02-03 cover CVE IDs from 2017 onward. If a pre-2017 CVE is `not_returned` on a v1 date, retry on or after 2022-02-04, when v2 began publishing. For other omissions, check the CVE record before drawing conclusions.
8. **Discovery pages are not EPSS-ranked.** FIRST currently returns candidates in descending CVE-ID string order (CVE-2026-8037 before CVE-2026-39987) whatever ordering is requested, so the first page does not hold the top scorers. To rank, raise `minEpss` (or `minPercentile`) until `candidateTotal` is small enough to page through, collect every page, and sort locally.
9. **Omit `date` on every `addedWithinDays` page.** The combination fails with `invalid_filter_combination`. Continue with the same filters, applied `limit`, and `nextOffset` as `offset`, including after a byte-limited or empty exact-year page. Candidates can shift between calls as the live dataset changes.
10. **Check model boundaries before explaining score movement.** If `crossesModelBoundary` is true, use `modelBoundariesCrossed` for the exact transition date or `modelBoundaryEvidence` for the interval. A transition can affect scores. Check the percentile series too, since the score and the rank can move differently.
11. **Check for incomplete boundary coverage.** `modelBoundaryCoverageThrough` dates the published schedule. Beyond it, verified headers can show a change between endpoints. Equal endpoint versions can hide an intervening change, so preserve the uncertainty when `modelBoundaryCoverageIncomplete` is present.
12. **Compare `modelVersion` before comparing scores from two dates.** If the versions differ, the difference mixes model change with any real movement. Report it that way, not as a trend.

## Workflows

### Triage a CVE list or scanner export

1. Reduce the export to unique CVEs with one CVSS base score each, using the scanner's value or an NVD source.
2. Call epss_prioritize_cves without `date`, then keep going until `nextBatchOffset` is absent (gate 4).
3. Merge the tiers across pages. Resubmit any `epssOnly` CVEs once their severity is known. List `unscoredCves` separately as unknown.
4. Report the score date and the applied `thresholds` alongside the tiers.

### Explain how a CVE's likelihood changed

1. Call epss_get_timeseries anchored on the end of the period (omit `date` for now).
2. For more than 30 days, call again with each item's `previousAnchorDate`. The windows abut without overlap. If that snapshot is unavailable, step back a day.
3. If `delta7d` or `delta30d` is missing, describe the observed series. Don't interpolate.
4. Apply gates 10–12 before attributing the change to anything.

### Find candidates

- **High likelihood now:** a `minEpss` or `minPercentile` bound. Page through everything when the order matters (gate 8).
- **Newly added to EPSS:** `addedWithinDays` with no `date` (gate 9).
- **One CVE year:** `year` plus a score bound, paged until `hasMore` is false (gate 5).
