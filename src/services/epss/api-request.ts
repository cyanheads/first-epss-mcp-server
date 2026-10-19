/**
 * @fileoverview Deadline-bound FIRST API exchange with private error-body classification.
 * @module services/epss/api-request
 */
import { JsonRpcErrorCode, McpError } from '@cyanheads/mcp-ts-core/errors';
import { httpErrorFromResponse } from '@cyanheads/mcp-ts-core/utils';
import { checkSignal, localValidationError } from './errors.js';

/** Read an API response under one ten-second header/body deadline. */
export async function requestApi(url: string, signal: AbortSignal, date?: string): Promise<string> {
  const controller = new AbortController();
  const attemptSignal = AbortSignal.any([signal, controller.signal]);
  const timer = setTimeout(() => controller.abort(), 10000);
  let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
  let rejectAbort: () => void = () => {};
  const aborted = new Promise<never>((_resolve, reject) => {
    rejectAbort = () => {
      try {
        checkSignal(signal);
        throw new McpError(JsonRpcErrorCode.Timeout, 'FIRST EPSS request timed out.', {
          retryable: true,
          errorSource: 'FetchTimeout',
        });
      } catch (error) {
        reject(error);
      }
    };
    attemptSignal.addEventListener('abort', rejectAbort, { once: true });
  });
  try {
    checkSignal(signal);
    const response = await Promise.race([
      fetch(url, { signal: attemptSignal, redirect: 'error' }),
      aborted,
    ]);
    reader = response.body?.getReader();
    const decoder = new TextDecoder();
    let text = '';
    let bytes = 0;
    const inspectSnapshot = response.status === 422 && date !== undefined;
    if (response.ok || inspectSnapshot) {
      while (reader) {
        const chunk = await Promise.race([reader.read(), aborted]);
        if (chunk.done) {
          text += decoder.decode();
          break;
        }
        bytes += chunk.value.byteLength;
        if (inspectSnapshot && bytes > 1024) {
          text = '';
          break;
        }
        text += decoder.decode(chunk.value, { stream: true });
      }
    }
    if (!response.ok) {
      if (inspectSnapshot) {
        let body: unknown;
        try {
          body = JSON.parse(text);
        } catch {
          /* Unknown bodies retain the HTTP classification. */
        }
        if (body && typeof body === 'object' && !Array.isArray(body)) {
          const value = body as Record<string, unknown>;
          if (
            value['status-code'] === 422 &&
            Array.isArray(value.message) &&
            value.message.includes('listNoResults')
          )
            throw localValidationError(`FIRST EPSS snapshot ${date} is unavailable.`, {
              reason: 'snapshot_unavailable',
              status: 422,
            });
        }
      }
      throw await httpErrorFromResponse(response, {
        captureBody: false,
        service: 'FIRST EPSS',
        data: { errorSource: 'FetchHttpError' },
      });
    }
    return text;
  } catch (error) {
    checkSignal(signal);
    if (error instanceof McpError) throw error;
    if (controller.signal.aborted)
      throw new McpError(JsonRpcErrorCode.Timeout, 'FIRST EPSS request timed out.', {
        retryable: true,
        errorSource: 'FetchTimeout',
      });
    throw new McpError(JsonRpcErrorCode.ServiceUnavailable, 'FIRST EPSS network request failed.', {
      retryable: true,
      errorSource: 'FetchNetworkErrorWrapper',
    });
  } finally {
    clearTimeout(timer);
    attemptSignal.removeEventListener('abort', rejectAbort);
    if (reader) {
      const ownedReader = reader;
      void ownedReader
        .cancel()
        .catch(() => {})
        .finally(() => ownedReader.releaseLock());
    }
    controller.abort();
  }
}
