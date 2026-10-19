/**
 * @fileoverview Identifier, date, and score normalization for FIRST EPSS.
 * @module services/epss/normalization
 */
import { serializationError } from '@cyanheads/mcp-ts-core/errors';
import { trustedError, localValidationError as validationError } from './errors.js';
import type { BatchAccounting, Score } from './types.js';
/** Earliest published score date. */
export const FIRST_SCORE_DATE = '2021-04-14';
/** Last verified publishing schedule date. */
export const MODEL_SCHEDULE_VERIFIED_AT = '2026-10-18';
/** Documented scoring model transitions. */
export const MODEL_TRANSITIONS = [
  { date: '2021-04-14', label: 'EPSS v1' },
  { date: '2022-02-04', label: 'EPSS v2', version: 'v2022.01.01' },
  { date: '2023-03-07', label: 'EPSS v3', version: 'v2023.03.01' },
  { date: '2025-03-17', label: 'EPSS v4', version: 'v2025.03.14' },
  { date: '2026-06-15', label: 'EPSS v5', version: 'v2026.06.15' },
] as const;
/** Reject invalid upstream shapes without leaking upstream content. */
export function upstreamShape(): never {
  throw trustedError(
    serializationError('FIRST EPSS returned inconsistent or invalid score data.', {
      reason: 'upstream_shape',
      retryable: false,
      recovery: {
        hint: "Retry the same tool call once; if it persists, call epss_list_reference with topic='coverage' and do not interpret the response as missing scores.",
      },
    }),
  );
}
/** Match a real ISO date without rollover. */
export function isCalendarDate(value: string): boolean {
  return (
    /^\d{4}-\d{2}-\d{2}$/.test(value) &&
    Number.isFinite(Date.parse(value)) &&
    new Date(value).toISOString().slice(0, 10) === value
  );
}
/** Validate and normalize an optional historical date. */
export function normalizeDate(value?: string): string | undefined {
  const date = value?.trim();
  if (!date) return undefined;
  if (
    !isCalendarDate(date) ||
    date < FIRST_SCORE_DATE ||
    date > new Date().toISOString().slice(0, 10)
  )
    throw validationError('Date must be a real UTC calendar date from 2021-04-14 through today.');
  return date;
}
/** Shift a calendar date by whole days. */
export function shiftDate(date: string, days: number): string {
  return new Date(Date.parse(date) + days * 86_400_000).toISOString().slice(0, 10);
}
/** Normalize a CVE without repairing it. */
export function normalizeCve(value: string): string {
  return value
    .trim()
    .toUpperCase()
    .replace(/[\u2010-\u2015\u2212\uFE63\uFF0D]/g, '-');
}
/** Recognize canonical identifiers. */
export function isCve(value: string): boolean {
  return /^CVE-[0-9]{4}-[0-9]{4,}$/.test(value);
}
/** Resolve canonical deduplication and bounded batch work. */
export function normalizeBatch(
  cves: readonly string[],
  cap: number,
  offset = 0,
): BatchAccounting & { processedCves: string[]; validCves: string[] } {
  if (
    !cves.length ||
    cves.length > 5000 ||
    cves.some((cve) => typeof cve !== 'string' || !cve.trim() || cve.length > 128)
  )
    throw validationError(
      'Supply between 1 and 5000 nonempty CVE strings of at most 128 characters.',
    );
  const unique = [...new Set(cves.map(normalizeCve))];
  if (!Number.isSafeInteger(offset) || offset < 0)
    throw validationError('Use a nonnegative safe integer batchOffset.');
  const processedCves = unique.slice(offset, offset + cap);
  return {
    requestedCount: unique.length,
    processedCount: processedCves.length,
    duplicateCount: cves.length - unique.length,
    deferredCves: unique.slice(offset + cap),
    processedCves,
    validCves: processedCves.filter(isCve),
    unscoredCves: processedCves
      .filter((cve) => !isCve(cve))
      .map((cve) => ({
        cve,
        reason: 'invalid_format',
        guidance: 'Supply a complete CVE-YYYY-NNNN identifier, then retry epss_get_scores.',
      })),
  };
}
/** Split the actual comma-joined parameter strictly below 2000 characters. */
export function chunkCves(cves: readonly string[]): string[][] {
  const chunks: string[][] = [];
  let chunk: string[] = [];
  let length = 0;
  for (const cve of cves) {
    if (cve.length >= 2000) throw validationError('A CVE exceeds the upstream parameter budget.');
    if (length + (chunk.length ? 1 : 0) + cve.length >= 2000) {
      chunks.push(chunk);
      chunk = [];
      length = 0;
    }
    length += (chunk.length ? 1 : 0) + cve.length;
    chunk.push(cve);
  }
  if (chunk.length) chunks.push(chunk);
  return chunks;
}
/** Parse explicit finite decimal values; absent and blank values never become zero. */
export function probability(value: unknown): number {
  if (
    typeof value !== 'number' &&
    (typeof value !== 'string' || !/^[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?$/.test(value))
  )
    upstreamShape();
  const number = Number(value);
  if (!Number.isFinite(number) || number < 0 || number > 1) upstreamShape();
  return number;
}
/** Narrow an untrusted object at the boundary. */
export function record(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) upstreamShape();
  return value as Record<string, unknown>;
}
/** Normalize required raw forecast data. */
export function normalizeScore(value: unknown, cve?: string): Score {
  const raw = record(value);
  if (
    cve !== undefined &&
    raw.cve !== undefined &&
    (typeof raw.cve !== 'string' || normalizeCve(raw.cve) !== cve)
  )
    upstreamShape();
  const identifier = cve ?? (typeof raw.cve === 'string' ? normalizeCve(raw.cve) : '');
  if (
    !isCve(identifier) ||
    typeof raw.date !== 'string' ||
    !isCalendarDate(raw.date) ||
    raw.date < FIRST_SCORE_DATE ||
    raw.date > new Date().toISOString().slice(0, 10)
  )
    upstreamShape();
  return {
    cve: identifier,
    epss: probability(raw.epss),
    percentile: probability(raw.percentile),
    date: raw.date,
    modelVersionSource: 'unavailable',
  };
}
/** Stable descending probability ordering. */
export function compareScores(a: Score, b: Score): number {
  return b.epss - a.epss || a.cve.localeCompare(b.cve);
}
