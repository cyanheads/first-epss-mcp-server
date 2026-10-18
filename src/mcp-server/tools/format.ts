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
): string {
  return [
    '## Unscored CVEs',
    ...items.map(
      (item) =>
        `- ${cell(item.cve)}: ${item.reason}; CVSS base score: ${item.cvssBaseScore ?? 'unknown'}. ${item.guidance}`,
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
  },
  tool: string,
): string {
  return [
    `Requested count: ${value.requestedCount}; processed count: ${value.processedCount}; duplicate count: ${value.duplicateCount}.`,
    unscoredText(value.unscoredCves),
    '## Deferred CVEs',
    ...value.deferredCves.map((cve) => `- ${cell(cve)}`),
    value.deferredCves.length
      ? `Call ${tool} with these deferred CVEs to process the remainder.`
      : 'None.',
  ].join('\n');
}
