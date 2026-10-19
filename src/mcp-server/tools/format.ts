/**
 * @fileoverview Complete Markdown renderers for EPSS domain values.
 * @module mcp-server/tools/format
 */
import type { z } from '@cyanheads/mcp-ts-core';
import type { provenanceSchema, scoreSchema, unscoredSchema } from './schemas.js';

type Score = z.infer<typeof scoreSchema>;
type Provenance = z.infer<typeof provenanceSchema>;
type UnscoredCve = z.infer<typeof unscoredSchema>;

/** Escape untrusted values in Markdown tables and labelled lines. */
export function cell(value: unknown): string {
  return String(value).replaceAll('\\', '\\\\').replaceAll('|', '\\|').replaceAll('\n', ' ');
}
/** Render every forecast field without rounding. */
export function scoresText(scores: Score[]): string {
  return [
    '| CVE | EPSS | Percentile | Date | Model version | Model source |',
    '| --- | --- | --- | --- | --- | --- |',
    ...scores.map(
      (s) =>
        `| ${cell(s.cve)} | ${s.epss} | ${s.percentile} | ${s.date} | ${cell(s.modelVersion ?? 'unavailable')} | ${s.modelVersionSource} |`,
    ),
    ...(scores.length ? [] : ['No scored records.']),
  ].join('\n');
}
/** Render all provenance, including unavailable/inferred explanations. */
export function provenanceText(p: Provenance): string {
  const m = p.modelMetadata;
  return [
    `## Provenance`,
    `Source: ${p.source}`,
    `API URL: ${p.apiUrl}`,
    `Retrieved at: ${p.retrievedAt}`,
    `Requested date: ${p.requestedDate ?? 'latest available'}`,
    `Score dates: ${p.scoreDates.join(', ') || 'none'}`,
    `Model metadata status: ${m.status}`,
    `Model metadata source URL: ${m.sourceUrl ?? 'unavailable'}`,
    `Model metadata score date: ${m.scoreDate ?? 'unavailable'}`,
    `Model metadata version: ${m.modelVersion ?? 'unavailable'}`,
    `Model metadata explanation: ${m.explanation ?? 'none'}`,
  ].join('\n');
}
/** Render explicit omissions, including optional caller severity. */
export function unscoredText(
  items: (UnscoredCve & { cvssBaseScore?: number | undefined })[],
  includeSeverity = false,
): string {
  return [
    '## Unscored CVEs',
    ...items.map(
      (item) =>
        `- ${cell(item.cve)}: ${item.reason}${includeSeverity ? `; CVSS base score: ${item.cvssBaseScore ?? 'unknown'}` : ''}. ${item.guidance}`,
    ),
    ...(items.length ? [] : ['None.']),
  ].join('\n');
}
/** Render accounting and each deferred identifier once, with an executable next step. */
export function accountingText(
  value: {
    requestedCount: number;
    processedCount: number;
    duplicateCount: number;
    deferredCves: string[];
    unscoredCves: (UnscoredCve & { cvssBaseScore?: number | undefined })[];
    batchOffset?: number | undefined;
    nextBatchOffset?: number | undefined;
    returnedCount?: number | undefined;
    withheldCount?: number | undefined;
    withheldCves?: string[] | undefined;
    withheldCvesComplete?: boolean | undefined;
    deferredCount?: number | undefined;
    deferredCvesComplete?: boolean | undefined;
    budgetLimited?: boolean | undefined;
  },
  tool: string,
): string {
  return [
    `Requested count: ${value.requestedCount}; processed count: ${value.processedCount}; duplicate count: ${value.duplicateCount}.`,
    ...(value.batchOffset === undefined
      ? []
      : [
          `Batch offset: ${value.batchOffset}; returned count: ${value.returnedCount}; withheld count: ${value.withheldCount}; deferred count: ${value.deferredCount}; budget limited: ${value.budgetLimited}.`,
          `Withheld CVEs complete: ${value.withheldCvesComplete}; deferred CVEs complete: ${value.deferredCvesComplete}.`,
          '## Already processed but withheld CVEs',
          ...(value.withheldCves ?? []).map((cve) => `- ${cell(cve)}`),
          ...(value.nextBatchOffset === undefined
            ? []
            : [
                `Next batch offset: ${value.nextBatchOffset}. Call ${tool} with the original cves, batchOffset=${value.nextBatchOffset}, and the returned score date (or requested date when no scores were returned)${tool === 'epss_prioritize_cves' ? ', retaining original severity inputs and policy' : ''}.`,
              ]),
        ]),
    unscoredText(value.unscoredCves, tool === 'epss_prioritize_cves'),
    '## Deferred CVEs',
    ...value.deferredCves.map((cve) => `- ${cell(cve)}`),
    value.deferredCves.length
      ? `Deferred identifiers have not been queried. ${value.batchOffset === undefined ? `Call ${tool} with these deferred CVEs to process the remainder.` : 'Use nextBatchOffset with the original submission to resume.'}`
      : value.deferredCount
        ? `Preview omitted; ${value.deferredCount} deferred identifiers have not been queried. Use nextBatchOffset with the original submission to resume.`
        : 'None.',
  ].join('\n');
}
