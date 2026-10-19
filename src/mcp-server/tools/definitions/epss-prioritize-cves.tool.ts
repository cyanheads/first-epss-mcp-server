/**
 * @fileoverview Transparent EPSS and caller-severity prioritization.
 * @module mcp-server/tools/definitions/epss-prioritize-cves.tool
 */
import { tool, z } from '@cyanheads/mcp-ts-core';
import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { getEpssService, normalizeCve, type Score } from '../../../services/epss/index.js';
import { accountingText, provenanceText, scoresText } from '../format.js';
import { withBatchBudget } from '../response-budget.js';
import {
  accountingShape,
  batchOffsetSchema,
  cveSchema,
  dateSchema,
  noticeEnrichment,
  probabilitySchema,
  scoreSchema,
  unscoredSchema,
} from '../schemas.js';

const cvssSchema = z
  .number()
  .min(0)
  .max(10)
  .describe('0–10 caller-supplied CVSS base severity; not retrieved.');
const likelihoodSchema = z.discriminatedUnion('metric', [
  z
    .object({
      metric: z.literal('epss').describe('Exploitation probability metric.'),
      threshold: probabilitySchema.describe('0–1 inclusive probability cutoff.'),
    })
    .strict()
    .describe('Probability-based likelihood policy.'),
  z
    .object({
      metric: z.literal('percentile').describe('Population rank metric; not probability.'),
      threshold: probabilitySchema.describe('0–1 inclusive percentile cutoff.'),
    })
    .strict()
    .describe('Percentile-based likelihood policy.'),
]);
const tierRow = scoreSchema
  .extend({
    cvssBaseScore: cvssSchema,
    highSeverity: z.boolean().describe('Severity meets inclusive severityThreshold.'),
    highLikelihood: z.boolean().describe('Selected likelihood metric meets inclusive threshold.'),
  })
  .describe('Scored CVE with known severity and explicit threshold flags.');
type TierRow = Score & { cvssBaseScore: number; highSeverity: boolean; highLikelihood: boolean };

/** Classify known severity and likelihood without inventing unknown inputs. */
export const epssPrioritizeCves = withBatchBudget(
  tool('epss_prioritize_cves', {
    description:
      'Assign remediation tiers using latest or dated EPSS and caller-supplied CVSS base severity. Defaults are severity >= 7 and EPSS probability >= 0.10; select percentile explicitly for population rank. Missing severity stays in epssOnly and missing EPSS stays unscored. Thresholds are policy conventions, not FIRST guidance. Process up to 500 unique entries from batchOffset, returning whole entries within the byte budget. Resume using nextBatchOffset as batchOffset, the original cves with original cvssBaseScore values, returned score date as date, and the same severityThreshold and likelihood. Deferred lists may be declared previews; withheldCves were already processed.',
    annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: true },
    input: z.object({
      batchOffset: batchOffsetSchema,
      date: dateSchema,
      cves: z
        .array(
          z
            .object({
              cve: cveSchema,
              cvssBaseScore: cvssSchema
                .optional()
                .describe('Optional caller-supplied severity; absent remains unknown.'),
            })
            .strict()
            .describe('CVE identifier with optional supplied severity.'),
        )
        .min(1)
        .max(5000)
        .describe(
          'One to 5000 CVEs with optional caller severity; process up to 500 unique identifiers from batchOffset.',
        ),
      severityThreshold: cvssSchema
        .default(7)
        .describe('Inclusive high severity threshold, default 7.'),
      likelihood: likelihoodSchema
        .optional()
        .describe('Select one likelihood metric and threshold; omitted uses EPSS >= 0.10.'),
    }),
    output: z.object({
      tiers: z
        .object({
          act_now: z.array(tierRow).describe('High severity and high likelihood.'),
          scheduled: z.array(tierRow).describe('High severity and low likelihood.'),
          monitor: z.array(tierRow).describe('Low severity and high likelihood.'),
          defer: z.array(tierRow).describe('Low severity and low likelihood.'),
        })
        .describe('Policy tiers, each sorted by EPSS, CVSS descending then CVE ascending.'),
      epssOnly: z
        .array(
          scoreSchema
            .extend({
              highLikelihood: z.boolean().describe('Selected likelihood meets threshold.'),
              guidance: z.string().describe('How to supply missing severity.'),
            })
            .describe('Forecast with unknown caller severity.'),
        )
        .describe('Scored CVEs without caller severity; never classified as low severity.'),
      ...accountingShape,
      unscoredCves: z
        .array(
          unscoredSchema
            .extend({
              cvssBaseScore: cvssSchema
                .optional()
                .describe('Preserved caller severity even when EPSS is absent.'),
            })
            .describe('Unknown forecast with preserved caller severity.'),
        )
        .describe('Processed identifiers without EPSS, preserving supplied severity.'),
      thresholds: z
        .object({
          severityThreshold: cvssSchema.describe('Applied inclusive high severity cutoff.'),
          likelihood: likelihoodSchema.describe(
            'Applied alternative likelihood metric and cutoff.',
          ),
        })
        .describe('Applied policy conventions, not FIRST recommendations.'),
    }),
    enrichment: noticeEnrichment,
    errors: [
      {
        reason: 'conflicting_cvss',
        code: JsonRpcErrorCode.ValidationError,
        when: 'Duplicate canonical CVEs have different severity inputs, including missing versus supplied.',
        retryable: false,
        recovery:
          'Call epss_prioritize_cves again with one caller-supplied severity value per CVE.',
      },
      {
        reason: 'snapshot_unavailable',
        code: JsonRpcErrorCode.ValidationError,
        thrownBy: 'service',
        when: 'FIRST identifies the requested dated snapshot as unavailable.',
        retryable: false,
        recovery: 'Call the same tool with another date or omit date for latest available data.',
      },
      {
        reason: 'upstream_shape',
        code: JsonRpcErrorCode.SerializationError,
        thrownBy: 'service',
        when: 'The score envelope, batch completeness or snapshot is invalid.',
        retryable: false,
        recovery:
          "Retry the same tool call once; if it persists, call epss_list_reference with topic='coverage' and do not interpret the response as missing scores.",
      },
    ],
    async handler(input, ctx) {
      const severity = new Map<string, number | undefined>();
      for (const entry of input.cves) {
        const cve = normalizeCve(entry.cve);
        if (severity.has(cve) && severity.get(cve) !== entry.cvssBaseScore)
          throw ctx.fail('conflicting_cvss');
        severity.set(cve, entry.cvssBaseScore);
      }
      const likelihood = input.likelihood ?? { metric: 'epss' as const, threshold: 0.1 };
      const { notices, scores, ...result } = await getEpssService().getScores(
        {
          cves: input.cves.map((entry) => entry.cve),
          batchOffset: input.batchOffset,
          ...(input.date === undefined ? {} : { date: input.date }),
        },
        ctx,
      );
      const tiers: Record<'act_now' | 'scheduled' | 'monitor' | 'defer', TierRow[]> = {
        act_now: [],
        scheduled: [],
        monitor: [],
        defer: [],
      };
      const epssOnly: (Score & { highLikelihood: boolean; guidance: string })[] = [];
      for (const score of scores) {
        const highLikelihood = score[likelihood.metric] >= likelihood.threshold;
        const cvssBaseScore = severity.get(score.cve);
        if (cvssBaseScore === undefined) {
          epssOnly.push({
            ...score,
            highLikelihood,
            guidance: `Call epss_prioritize_cves with a cves entry for ${score.cve} and its caller-supplied cvssBaseScore to classify severity.`,
          });
          continue;
        }
        const highSeverity = cvssBaseScore >= input.severityThreshold;
        const tier = highSeverity
          ? highLikelihood
            ? 'act_now'
            : 'scheduled'
          : highLikelihood
            ? 'monitor'
            : 'defer';
        tiers[tier].push({ ...score, cvssBaseScore, highSeverity, highLikelihood });
      }
      for (const rows of Object.values(tiers))
        rows.sort(
          (a, b) =>
            b.epss - a.epss || b.cvssBaseScore - a.cvssBaseScore || a.cve.localeCompare(b.cve),
        );
      return {
        notices,
        ...result,
        tiers,
        epssOnly,
        unscoredCves: result.unscoredCves.map((entry) => {
          const cvssBaseScore = severity.get(entry.cve);
          return {
            ...entry,
            guidance: `${entry.reason === 'invalid_format' ? 'Supply a complete CVE-YYYY-NNNN identifier.' : "Call epss_list_reference with topic='coverage' to interpret missing scores."} Retry epss_prioritize_cves with the original cves entries, retaining cvssBaseScore when supplied and the same severityThreshold and likelihood policy.`,
            ...(cvssBaseScore === undefined ? {} : { cvssBaseScore }),
          };
        }),
        thresholds: { severityThreshold: input.severityThreshold, likelihood },
      };
    },
    format(result) {
      const { thresholds } = result;
      return [
        {
          type: 'text',
          text: [
            `Severity threshold: ${thresholds.severityThreshold}; likelihood metric: ${thresholds.likelihood.metric}; likelihood threshold: ${thresholds.likelihood.threshold}. Inclusive policy conventions, not FIRST guidance.`,
            ...Object.entries(result.tiers).map(([name, rows]) =>
              [
                `## ${name}`,
                scoresText(rows),
                ...rows.map(
                  (row) =>
                    `- ${row.cve}: CVSS base score: ${row.cvssBaseScore}; highSeverity: ${row.highSeverity}; highLikelihood: ${row.highLikelihood}`,
                ),
              ].join('\n'),
            ),
            '## EPSS only (severity unknown)',
            scoresText(result.epssOnly),
            ...result.epssOnly.map(
              (row) => `- ${row.cve}: highLikelihood: ${row.highLikelihood}; ${row.guidance}`,
            ),
            accountingText(result, 'epss_prioritize_cves'),
            ...(result.deferredCves.length
              ? [
                  'For each deferred entry, retain its original cvssBaseScore when supplied and repeat the same severityThreshold and likelihood policy.',
                ]
              : []),
            provenanceText(result.provenance),
          ].join('\n\n'),
        },
      ];
    },
  }),
);
