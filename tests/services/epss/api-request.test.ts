/**
 * @fileoverview Header/body deadlines and private snapshot error handling.
 * @module tests/services/epss/api-request.test
 */
import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { requestApi } from '@/services/epss/api-request.js';

const url = 'https://api.first.org/data/v1/epss?date=2026-10-17';
afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe('FIRST API exchange', () => {
  it.each([200, 422])(
    'times out a stalled %s body as a retryable attempt failure',
    async (status) => {
      vi.useFakeTimers();
      const cancel = vi.fn();
      vi.stubGlobal(
        'fetch',
        vi.fn(async () => new Response(new ReadableStream({ cancel }), { status })),
      );
      const operation = requestApi(url, new AbortController().signal, '2026-10-17');
      const rejection = expect(operation).rejects.toMatchObject({
        code: JsonRpcErrorCode.Timeout,
        data: { retryable: true, errorSource: 'FetchTimeout' },
      });
      await vi.advanceTimersByTimeAsync(10000);
      await rejection;
      expect(cancel).toHaveBeenCalledOnce();
    },
  );
  it.each([200, 422])(
    'cancels a stalled %s body without exposing caller reason',
    async (status) => {
      const controller = new AbortController();
      const cancel = vi.fn();
      vi.stubGlobal(
        'fetch',
        vi.fn(async () => new Response(new ReadableStream({ cancel }), { status })),
      );
      const operation = requestApi(url, controller.signal, '2026-10-17');
      await Promise.resolve();
      await Promise.resolve();
      controller.abort('private');
      const error = await operation.catch((caught: unknown) => caught);
      expect(error).toMatchObject({
        code: JsonRpcErrorCode.RequestCancelled,
        data: { retryable: false },
      });
      expect(JSON.stringify(error)).not.toContain('private');
    },
  );
  it.each([
    '{',
    JSON.stringify({ 'status-code': 422, message: ['other'] }),
    JSON.stringify({ 'status-code': 422, message: ['listNoResults'], padding: 'x'.repeat(1500) }),
  ])('retains generic HTTP422 for malformed/unrecognized/oversized bodies', async (body) => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response(body, { status: 422 })),
    );
    const error = await requestApi(url, new AbortController().signal, '2026-10-17').catch(
      (caught: unknown) => caught,
    );
    expect(error).toMatchObject({ code: JsonRpcErrorCode.ValidationError, data: { status: 422 } });
    expect(error).not.toHaveProperty('data.reason');
    expect(error).not.toHaveProperty('data.body');
  });
  it('does not classify an undated listNoResults response as a missing snapshot', async () => {
    const cancel = vi.fn();
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response(new ReadableStream({ cancel }), { status: 422 })),
    );
    await expect(requestApi(url, new AbortController().signal)).rejects.toMatchObject({
      data: { status: 422 },
    });
    expect(cancel).toHaveBeenCalledOnce();
  });
});
