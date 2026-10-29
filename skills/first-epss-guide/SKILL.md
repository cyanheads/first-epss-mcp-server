---
name: first-epss-guide
description: Gates and workflows for the epss_* tools (FIRST EPSS). When EPSS answers a question and when an NVD or KEV source must, where score dates and offsets come from, when batch and candidate paging is done, why discovery pages are not EPSS-ranked, and how to tell a model change from real score movement. Use when triaging a CVE list or scanner export, explaining an EPSS change, or finding high-likelihood or newly added CVEs.
license: Apache-2.0
metadata:
  author: cyanheads
  version: "1.0"
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
2. **Give each CVE exactly one severity.** In epss_prioritize_cves, the same CVE with two CVSS values fails the whole call with `conflicting_cvss`, and so does the same CVE with and without one. Fill CVSS gaps before calling: CVEs without it land in `epssOnly` and need a second call.
3. **Don't ask for a date that hasn't been published.** That includes today's UTC date before FIRST publishes it, which fails with `snapshot_unavailable`; a date after today fails argument validation instead. Omit `date` to get the latest available day.

**While paging**

4. **A batch is done when `nextBatchOffset` is absent.** `deferredCount: 0` does not mean done. A near-full batch comes back `budgetLimited`, with already-processed entries withheld and a `nextBatchOffset` even though nothing was deferred. Take the continuation `date` from the first response's `provenance.scoreDates`, so a run that crosses FIRST's daily publish stays on one snapshot.
5. **A year-filtered search is done only when `hasMore` is false.** `year` alone matches any identifier containing those digits, so the first pages can hold no matches at all. Add a score bound to shrink `candidateTotal`.
6. **Keep `limit` at a few hundred.** A larger page is cut to fit the byte budget. `nextOffset` then points back at the first withheld row, so the next call fetches those rows again.

**Before drawing a conclusion**

7. **Treat a missing score as unknown, never zero.** Don't rank a missing score last or fill it with 0. `not_returned` on a historical `date` can simply mean the CVE had not entered the dataset yet, and the API holds no scores at all before 2022-02-04, though earlier dates are accepted. Check the CVE record in an NVD source before saying it doesn't exist.
8. **Discovery pages are not EPSS-ranked.** FIRST currently returns candidates in descending CVE-ID string order (CVE-2026-8037 before CVE-2026-39987) whatever ordering is requested, so the first page does not hold the top scorers. To rank, raise `minEpss` (or `minPercentile`) until `candidateTotal` is small enough to page through, collect every page, and sort locally.
9. **Never combine `addedWithinDays` with `date`.** With a date, FIRST ignores an `addedWithinDays` of 2 or more, so the result is the entire dated snapshot (or everything meeting any score bound) and `candidateTotal` jumps toward the corpus size; with 1 it returns nothing. For "recently added", omit `date`.
10. **Check score movement against model boundaries before calling it real.** If a `deltaComparisons` entry has `crossesModelBoundary: true`, find the step in `series`. A step dated exactly on a `modelBoundariesCrossed` date is the methodology change: at the EPSS v5 transition, unrelated CVEs all stepped on the same day. Read the percentile series as well. Percentile is a rank against all scored CVEs, and across a boundary it can barely move, or move against the probability.
11. **After `modelBoundaryCoverageThrough`, the boundary list can't confirm anything.** Rows after that date carry `modelVersionSource: unavailable`, and a newer transition would not be listed. Before ruling out a model change, compare the anchor's verified `modelVersion` with the last inferred version in `series`.
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
