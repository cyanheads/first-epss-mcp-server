/**
 * @fileoverview Registered FIRST EPSS definition surface.
 * @module tests/smoke/definitions.smoke.test
 */
import { expect, it } from 'vitest';
import { allToolDefinitions } from '@/mcp-server/tools/definitions/index.js';

it('registers exactly five EPSS tools with structured and formatted output', () => {
  expect(allToolDefinitions.map((definition) => definition.name)).toEqual([
    'epss_get_scores',
    'epss_get_timeseries',
    'epss_query_threshold',
    'epss_prioritize_cves',
    'epss_list_reference',
  ]);
  for (const definition of allToolDefinitions) {
    expect(definition.annotations?.readOnlyHint).toBe(true);
    expect(typeof definition.handler).toBe('function');
    expect(typeof definition.format).toBe('function');
    expect(definition.output).toHaveProperty('parse');
  }
});
