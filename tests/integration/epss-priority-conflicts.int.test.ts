/**
 * @fileoverview Prioritization conflict diagnostics across both caller surfaces.
 * @module tests/integration/epss-priority-conflicts.int.test
 */
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { createInterface } from 'node:readline';
import type { z } from '@cyanheads/mcp-ts-core';
import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { runToolContract } from '@cyanheads/mcp-ts-core/testing';
import MarkdownIt from 'markdown-it';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { epssPrioritizeCves } from '@/mcp-server/tools/definitions/epss-prioritize-cves.tool.js';

const malformed = '<untrusted>&private';
const fetch = vi.fn(() => {
  throw new Error('Unexpected EPSS request');
});

beforeEach(() => {
  fetch.mockClear();
  vi.stubGlobal('fetch', fetch);
});
afterEach(() => {
  expect(fetch).not.toHaveBeenCalled();
  vi.unstubAllGlobals();
});

async function prioritize(input: z.input<typeof epssPrioritizeCves.input>) {
  const result = await runToolContract(epssPrioritizeCves, input);
  const text = result.content.map((block) => (block.type === 'text' ? block.text : '')).join('\n');
  return { result, text };
}

it('rejects a conflict before I/O even when the batch offset is past the end', async () => {
  const { result, text } = await prioritize({
    batchOffset: 5000,
    cves: [{ cve: 'CVE-2022-0001' }, { cve: ' cve−2022−0001 ', cvssBaseScore: 0 }],
  });
  expect(result.isError).toBe(true);
  expect(result.structuredContent).toMatchObject({
    error: {
      code: JsonRpcErrorCode.ValidationError,
      data: { reason: 'conflicting_cvss', retryable: false },
    },
  });
  expect(text).toContain('not retryable');
});

it('reports every conflicting ID and distinct value in submission order', async () => {
  const { result, text } = await prioritize({
    cves: [
      { cve: 'CVE-2022-0002', cvssBaseScore: 6.5 },
      { cve: malformed, cvssBaseScore: 0 },
      { cve: 'CVE-2022-0001' },
      { cve: 'cve-2022-0001', cvssBaseScore: 10 },
      { cve: malformed.toUpperCase(), cvssBaseScore: 1 },
      { cve: 'cve-2022-0002' },
      { cve: 'CVE-2022-0002', cvssBaseScore: 6.5 },
      { cve: 'CVE-2022-0002', cvssBaseScore: 5 },
    ],
  });
  expect(result.structuredContent).toMatchObject({
    error: {
      code: JsonRpcErrorCode.ValidationError,
      data: {
        reason: 'conflicting_cvss',
        retryable: false,
        conflictCount: 3,
        conflicts: [
          { cve: 'CVE-2022-0002', values: [6.5, null, 5] },
          { rows: [1, 4], values: [0, 1] },
          { cve: 'CVE-2022-0001', values: [null, 10] },
        ],
      },
    },
  });
  expect(text).toContain('3 conflicting');
  expect(text).toContain('`CVE-2022-0002`');
  expect(text).toContain('`CVE-2022-0001`');
  const rendered = new MarkdownIt().render(text);
  expect(rendered).toContain('<code>CVE-2022-0002</code>: 6.5, null, 5');
  expect(rendered).toContain('Rows 1, 4: 0, 1');
  expect(rendered).toContain('<code>CVE-2022-0001</code>: null, 10');
  expect(JSON.stringify(result).toLowerCase()).not.toContain(malformed);
});

it('retains all 2500 conflict groups on both surfaces within 65536 bytes', async () => {
  const pairs = Array.from({ length: 2500 }, (_, i) => [i * 2, i * 2 + 1]);
  const { result, text } = await prioritize({
    cves: pairs.flatMap(([i]) => {
      const cve = `CVE-2022-${String(i).padStart(119, '0')}`;
      return [{ cve, cvssBaseScore: 0 }, { cve }];
    }),
  });
  expect(result.structuredContent).toMatchObject({
    error: {
      data: { conflictCount: 2500, conflictRows: pairs },
    },
  });
  expect(text).toContain(pairs.map((pair) => pair.join(',')).join(';'));
  expect(Buffer.byteLength(JSON.stringify(result.structuredContent))).toBeLessThanOrEqual(65536);
  expect(Buffer.byteLength(JSON.stringify(result.content))).toBeLessThanOrEqual(65536);
});

it.each([false, true])(
  'redacts caller details from stdio logs with payload logging %s',
  async (enabled) => {
    const cve = 'CVE-2022-814937';
    const child = spawn('bun', ['src/index.ts'], {
      env: {
        ...process.env,
        ENVIRONMENT: 'production',
        NODE_ENV: 'production',
        MCP_AUTH_MODE: 'none',
        MCP_LOG_LEVEL: 'debug',
        MCP_TRANSPORT_TYPE: 'stdio',
        OTEL_ENABLED: 'false',
        LOG_TOOL_FAILURE_PAYLOADS: String(enabled),
      },
      signal: AbortSignal.timeout(10000),
    });
    const closed = once(child, 'close');
    const lines = createInterface({ input: child.stdout })[Symbol.asyncIterator]();
    let logs = '';
    child.stderr.setEncoding('utf8').on('data', (chunk: string) => {
      logs += chunk;
    });
    const send = (message: object) => {
      child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', ...message })}\n`);
    };
    const receive = async (id: number) => {
      for (let line = await lines.next(); !line.done; line = await lines.next()) {
        if (new RegExp(`"id":${id}(?:,|})`).test(line.value)) return line.value;
      }
      throw new Error(`STDIO ended before response ${id}`);
    };
    try {
      send({
        id: 1,
        method: 'initialize',
        params: {
          protocolVersion: '2025-11-25',
          capabilities: {},
          clientInfo: { name: 'conflict-log-test', version: '1.0.0' },
        },
      });
      expect(await receive(1)).toContain('"serverInfo"');
      send({ method: 'notifications/initialized' });
      send({
        id: 2,
        method: 'tools/call',
        params: {
          name: 'epss_prioritize_cves',
          arguments: {
            cves: [
              { cve },
              { cve, cvssBaseScore: 7 },
              { cve: malformed },
              { cve: malformed, cvssBaseScore: 0 },
            ],
          },
        },
      });
      const result = await receive(2);
      expect(result).toContain(cve);
      expect(result).toContain('conflicting_cvss');
      expect(result).not.toContain(malformed);
    } finally {
      child.stdin.end();
      expect(await closed).toEqual([0, null]);
    }
    expect(logs).toContain('Error in tool:epss_prioritize_cves');
    expect(logs.includes('Tool failure payload: epss_prioritize_cves')).toBe(enabled);
    expect(logs).not.toContain(cve);
    expect(logs).not.toContain(malformed);
  },
);
