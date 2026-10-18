/**
 * @fileoverview Described public EPSS tool schemas.
 * @module mcp-server/tools/schemas
 */
import { z } from '@cyanheads/mcp-ts-core';
import { FIRST_SCORE_DATE, isCalendarDate } from '../../services/epss/index.js';

/** Finite unit-interval value. */
export const probabilitySchema = z.number().min(0).max(1);
/** Bounded submitted identifier; malformed CVEs are accounted for by the service. */
export const cveSchema = z
  .string()
  .min(1)
  .max(128)
  .refine((value) => value.trim().length > 0, 'Supply a nonempty CVE identifier.')
  .describe('Complete CVE-YYYY-NNNN identifier; whitespace and case are normalized.');
/** Batch input with domain-specific comma/newline normalization. */
export const cvesSchema = z
  .preprocess(
    (value) =>
      typeof value === 'string'
        ? value
            .split(/[,\n]/)
            .map((part) => part.trim())
            .filter(Boolean)
        : value,
    z.array(cveSchema).min(1).max(5000),
  )
  .describe('One to 5000 CVE identifiers; comma/newline-delimited strings are also accepted.');
/** Historical date, blank meaning latest available. */
export const dateSchema = z
  .string()
  .refine(
    (value) =>
      !value.trim() ||
      (isCalendarDate(value.trim()) &&
        value.trim() >= FIRST_SCORE_DATE &&
        value.trim() <= new Date().toISOString().slice(0, 10)),
    'Use a real UTC date from 2021-04-14 through today.',
  )
  .optional()
  .describe(
    'UTC date YYYY-MM-DD from 2021-04-14 through today; omitted or blank selects latest available data.',
  );
/** Forecast with per-record model attribution. */
export const scoreSchema = z
  .object({
    cve: z.string().describe('Canonical CVE identifier.'),
    epss: probabilitySchema.describe(
      '0–1 probability of observed exploitation within the next 30 days.',
    ),
    percentile: probabilitySchema.describe('0–1 population rank, not exploitation probability.'),
    date: z.string().describe('Upstream score date.'),
    modelVersion: z
      .string()
      .optional()
      .describe('Verified or inferred scoring model version when available.'),
    modelVersionSource: z
      .enum(['csv_header', 'published_schedule', 'unavailable'])
      .describe(
        'csv_header: verified metadata; published_schedule: inferred; unavailable: unknown.',
      ),
  })
  .describe('Daily exploitation forecast and model attribution.');
/** Source attribution and snapshot metadata. */
export const provenanceSchema = z
  .object({
    source: z.literal('FIRST EPSS').describe('Score publisher.'),
    apiUrl: z.string().describe('FIRST lookup endpoint.'),
    retrievedAt: z.string().describe('UTC retrieval timestamp.'),
    requestedDate: z.string().optional().describe('Explicit requested historical date.'),
    scoreDates: z
      .array(z.string().describe('Observed snapshot date.'))
      .describe('Returned anchor or candidate score dates.'),
    modelMetadata: z
      .object({
        status: z
          .enum(['verified', 'inferred', 'unavailable'])
          .describe(
            'verified: matching metadata; inferred: published schedule; unavailable: unknown.',
          ),
        sourceUrl: z.string().optional().describe('Model metadata source.'),
        scoreDate: z.string().optional().describe('Snapshot attributed by metadata.'),
        modelVersion: z.string().optional().describe('Attributed model version.'),
        explanation: z.string().optional().describe('Attribution limitations and inference basis.'),
      })
      .describe('Snapshot model attribution.'),
  })
  .describe('Snapshot source provenance.');
/** Explicit missing-score semantics. */
export const unscoredSchema = z
  .object({
    cve: z.string().describe('Submitted normalized identifier.'),
    reason: z
      .enum(['invalid_format', 'not_returned'])
      .describe('Invalid identifier or upstream omission; neither implies zero risk.'),
    guidance: z.string().describe('Next step for missing scores.'),
  })
  .describe('Identifier with an explicitly unknown forecast.');
/** Shared bounded-work accounting. */
export const accountingShape = {
  unscoredCves: z
    .array(unscoredSchema)
    .describe('Processed identifiers without scores, in request order.'),
  deferredCves: z
    .array(z.string().describe('Identifier not queried.'))
    .describe('Identifiers beyond this call workload cap; submit them in another call.'),
  requestedCount: z.number().int().describe('Unique normalized identifiers submitted.'),
  processedCount: z
    .number()
    .int()
    .describe('Unique identifiers processed, including invalid formats.'),
  duplicateCount: z.number().int().describe('Duplicate submitted entries removed.'),
  provenance: provenanceSchema.describe('Source and model attribution.'),
};
/** Optional success-path caveat, rendered by the framework. */
export const noticeEnrichment = {
  notice: z.string().optional().describe('Missing-data, deferred-work or model-metadata caveats.'),
};
