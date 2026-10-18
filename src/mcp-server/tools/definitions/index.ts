/**
 * @fileoverview Registered FIRST EPSS tool surface.
 * @module mcp-server/tools/definitions
 */
import { epssGetScores } from './epss-get-scores.tool.js';
import { epssGetTimeseries } from './epss-get-timeseries.tool.js';
import { epssListReference } from './epss-list-reference.tool.js';
import { epssPrioritizeCves } from './epss-prioritize-cves.tool.js';
import { epssQueryThreshold } from './epss-query-threshold.tool.js';

export {
  epssGetScores,
  epssGetTimeseries,
  epssListReference,
  epssPrioritizeCves,
  epssQueryThreshold,
};
/** All callable EPSS tools. */
export const allToolDefinitions = [
  epssGetScores,
  epssGetTimeseries,
  epssQueryThreshold,
  epssPrioritizeCves,
  epssListReference,
];
