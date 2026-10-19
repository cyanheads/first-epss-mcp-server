/**
 * @fileoverview Described public EPSS tool schemas.
 * @module mcp-server/tools/schemas
 */
import { z } from '@cyanheads/mcp-ts-core';
import { FIRST_SCORE_DATE, isCalendarDate } from '../../services/epss/index.js';

/** Finite unit-interval value. */
export const probabilitySchema = z.number().min(0).max(1);
/** Offset into the original first-occurrence normalized unique submission. */
export const batchOffsetSchema = z
  .number()
  .int()
  .min(0)
  .max(Number.MAX_SAFE_INTEGER)
  .default(0)
  .describe(
    'Resume in first-occurrence normalized unique input order; resubmit the original cves, returned score date and original policy/severity inputs.',
  );
/** Bounded submitted identifier; malformed CVEs are accounted for by the service. */
export const cveSchema = z
  .string()
  .min(1)
  .max(128)
  .refine((value) => value.trim().length > 0, 'Supply a nonempty CVE identifier.')
  .describe(
    'Complete CVE-YYYY-NNNN identifier; whitespace, case and Unicode dashes are normalized.',
  );
/** Batch input with domain-specific comma/newline normalization. */
export const cvesSchema = z
  .preprocess(
    (value) =>
      typeof value === 'string'
        ? value
            .split(/[\s,;]+/)
            .map((part) => part.trim())
            .filter(Boolean)
        : value,
    z.array(cveSchema).min(1).max(5000),
  )
  .describe(
    'One to 5000 CVE identifiers; whitespace, comma or semicolon-delimited strings are also accepted.',
  );
/** Historical date, blank meaning latest available. */
export const dateSchema = z
  .string()
  .regex(/^\s*(?:\d{4}-\d{2}-\d{2}\s*)?$/)
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
  batchOffset: z
    .number()
    .int()
    .optional()
    .describe('Starting offset in the original normalized unique input.'),
  nextBatchOffset: z
    .number()
    .int()
    .optional()
    .describe(
      'Resume with this batchOffset and the original cves, returned date and original severity/policy inputs.',
    ),
  returnedCount: z
    .number()
    .int()
    .optional()
    .describe('Processed identifiers whose complete score, history or unscored entry is included.'),
  withheldCount: z
    .number()
    .int()
    .optional()
    .describe(
      'Processed identifiers withheld by the response byte budget; queried valid entries are included in processedCount.',
    ),
  withheldCves: z
    .array(z.string().describe('Already processed identifier withheld from this response.'))
    .optional()
    .describe(
      'Already processed identifiers withheld by the byte budget, in original input order; may be a preview.',
    ),
  withheldCvesComplete: z
    .boolean()
    .optional()
    .describe('True when withheldCves includes every withheld identifier.'),
  deferredCount: z
    .number()
    .int()
    .optional()
    .describe('Identifiers beyond this call workload cap, not queried.'),
  deferredCvesComplete: z
    .boolean()
    .optional()
    .describe('True when deferredCves includes every never-queried deferred identifier.'),
  budgetLimited: z
    .boolean()
    .optional()
    .describe(
      'True when whole entries or accounting lists were shortened to fit the serialized response budget.',
    ),
  unscoredCves: z
    .array(unscoredSchema)
    .describe('Retained processed identifiers without scores, in request order.'),
  deferredCves: z
    .array(z.string().describe('Identifier not queried.'))
    .describe(
      'Never-queried identifiers beyond this call workload cap; complete unless deferredCvesComplete is false. Resume using nextBatchOffset and the original submission.',
    ),
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
