/**
 * @fileoverview Daily EPSS history with exact-date comparisons.
 * @module mcp-server/tools/definitions/epss-get-timeseries.tool
 */
import { tool, z } from '@cyanheads/mcp-ts-core';
import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { getEpssService } from '../../../services/epss/index.js';
import { accountingText, provenanceText, scoresText } from '../format.js';
import { deriveHistory } from '../history.js';
import { withBatchBudget } from '../response-budget.js';
import {
  accountingShape,
  batchOffsetSchema,
  cvesSchema,
  dateSchema,
  noticeEnrichment,
  scoreSchema,
} from '../schemas.js';

const windowShape = {
  startDate: z.string().describe('First calendar date in the window.'),
  endDate: z.string().describe('Last calendar date in the window.'),
};
/** Retrieve anchors and preceding observations without interpolation. */
export const epssGetTimeseries = withBatchBudget(
  tool('epss_get_timeseries', {
    description:
      'Retrieve an EPSS anchor and up to 30 preceding daily observations for up to 50 unique CVEs from batchOffset. Response byte limits retain whole history items. Resume CVE batches with nextBatchOffset as batchOffset, the original cves and returned score date as date; withheldCves were processed, deferredCves were not queried, and lists can be declared previews. Exact 7-day and 30-day deltas require their calendar baselines; gaps remain unknown. Model boundaries do not explain score movement. Re-anchor using previousAnchorDate for the preceding history window; that snapshot may be unavailable.',
    annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: true },
    input: z.object({ cves: cvesSchema, date: dateSchema, batchOffset: batchOffsetSchema }),
    output: z.object({
      items: z
        .array(
          z
            .object({
              current: scoreSchema.describe('Anchor score, separate from preceding history.'),
              series: z
                .array(scoreSchema)
                .describe(
                  'Available preceding observations in ascending date order; excludes anchor.',
                ),
              requestedWindow: z
                .object(windowShape)
                .describe('Anchor minus 30 through anchor minus one calendar day.'),
              previousAnchorDate: z
                .string()
                .optional()
                .describe(
                  'Anchor minus 31 days for the preceding window; absent before 2021-04-14. Snapshot availability is not guaranteed.',
                ),
              observedWindow: z
                .object({
                  ...windowShape,
                  observationCount: z
                    .number()
                    .int()
                    .describe('Number of available preceding observations.'),
                })
                .optional()
                .describe('Extent and count of preceding data; absent when no observations exist.'),
              missingDates: z
                .array(z.string().describe('Missing expected calendar date.'))
                .describe('Every gap in the requested preceding window.'),
              delta7d: z
                .number()
                .optional()
                .describe('Anchor EPSS minus exact seven-day baseline, in probability units.'),
              delta30d: z
                .number()
                .optional()
                .describe('Anchor EPSS minus exact thirty-day baseline, in probability units.'),
              unavailableDeltas: z
                .array(z.number().describe('Unavailable baseline day distance, 7 or 30.'))
                .describe('Comparisons without exact-date baselines.'),
              deltaComparisons: z
                .array(
                  z
                    .object({
                      days: z.number().describe('Comparison day distance.'),
                      baselineDate: z.string().describe('Exact baseline date.'),
                      endpointDate: z.string().describe('Anchor endpoint date.'),
                      crossesModelBoundary: z
                        .boolean()
                        .describe(
                          'A documented model transition falls after baseline through endpoint.',
                        ),
                    })
                    .describe('One exact-date comparison.'),
                )
                .describe('Available exact-date comparison provenance.'),
              peak: z
                .object({
                  epss: z.number().describe('0–1 peak EPSS across anchor and observations.'),
                  dates: z
                    .array(z.string().describe('Date tied for peak EPSS.'))
                    .describe('All tied peak dates, ascending.'),
                })
                .describe('Observed peak without inferring missing dates.'),
              modelBoundariesCrossed: z
                .array(
                  z
                    .object({
                      date: z.string().describe('Model publishing transition date.'),
                      fromModel: z.string().describe('Preceding model label.'),
                      toModel: z.string().describe('New model label.'),
                    })
                    .describe('Documented model publishing transition.'),
                )
                .describe('Transitions strictly after earliest observed date through anchor.'),
              modelBoundaryCoverageThrough: z
                .string()
                .describe('Last date the model schedule was verified.'),
            })
            .describe('One anchor and its derived history.'),
        )
        .describe('Derived trajectories ordered by anchor EPSS descending then CVE.'),
      ...accountingShape,
    }),
    enrichment: noticeEnrichment,
    errors: [
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
        when: 'The envelope, snapshots or history dates contain invalid or contradictory data.',
        retryable: false,
        recovery:
          "Retry the same tool call once; if it persists, call epss_list_reference with topic='coverage' and do not interpret the response as missing scores.",
      },
    ],
    async handler(input, ctx) {
      const { notices, items, ...result } = await getEpssService().getTimeseries(
        {
          cves: input.cves,
          batchOffset: input.batchOffset,
          ...(input.date === undefined ? {} : { date: input.date }),
        },
        ctx,
      );
      return { ...result, notices, items: items.map(deriveHistory) };
    },
    format(result) {
      return [
        {
          type: 'text',
          text: [
            ...result.items.map((item) =>
              [
                `## ${item.current.cve}`,
                'Anchor:',
                scoresText([item.current]),
                'Preceding series:',
                scoresText(item.series),
                `Requested window: ${item.requestedWindow.startDate} through ${item.requestedWindow.endDate}`,
                ...(item.previousAnchorDate
                  ? [
                      `Previous anchor date: ${item.previousAnchorDate}. Call epss_get_timeseries with ${JSON.stringify({ cves: [item.current.cve], date: item.previousAnchorDate })} for the preceding window; its snapshot may be unavailable.`,
                    ]
                  : []),
                item.observedWindow
                  ? `Observed window: ${item.observedWindow.startDate} through ${item.observedWindow.endDate}; observation count: ${item.observedWindow.observationCount}`
                  : 'Observed window: unavailable',
                `Missing dates: ${item.missingDates.join(', ') || 'none'}`,
                `delta7d: ${item.delta7d ?? 'unavailable'}; delta30d: ${item.delta30d ?? 'unavailable'}; unavailable deltas (days): ${item.unavailableDeltas.join(', ') || 'none'}`,
                'Delta comparisons:',
                ...item.deltaComparisons.map(
                  (c) =>
                    `- ${c.days} days; baseline date: ${c.baselineDate}; endpoint date: ${c.endpointDate}; crosses model boundary: ${c.crossesModelBoundary}`,
                ),
                `Peak EPSS: ${item.peak.epss}; dates: ${item.peak.dates.join(', ')}`,
                'Model boundaries crossed:',
                ...item.modelBoundariesCrossed.map(
                  (b) => `- ${b.date}: ${b.fromModel} → ${b.toModel}`,
                ),
                `Model boundary coverage through: ${item.modelBoundaryCoverageThrough}. A boundary does not establish why a score changed.`,
              ].join('\n'),
            ),
            accountingText(result, 'epss_get_timeseries'),
            provenanceText(result.provenance),
          ].join('\n\n'),
        },
      ];
    },
  }),
);
