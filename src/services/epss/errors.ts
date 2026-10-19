/**
 * @fileoverview Safe FIRST transport error projection and cancellation.
 * @module services/epss/errors
 */
import { JsonRpcErrorCode, McpError, validationError } from '@cyanheads/mcp-ts-core/errors';

const trustedErrors = new WeakSet<McpError>();
/** Mark only errors authored by this service as safe to retain verbatim. */
export function trustedError(error: McpError): McpError {
  trustedErrors.add(error);
  return error;
}
/** Build a nonretryable local validation error. */
export function localValidationError(...args: Parameters<typeof validationError>): McpError {
  return trustedError(validationError(args[0], { ...args[1], retryable: false }));
}
/** Throw a classified cancellation/deadline without exposing the abort reason. */
export function checkSignal(signal: AbortSignal): void {
  if (!signal.aborted) return;
  const deadline = signal.reason instanceof Error && signal.reason.name === 'TimeoutError';
  throw new McpError(
    deadline ? JsonRpcErrorCode.Timeout : JsonRpcErrorCode.RequestCancelled,
    deadline ? 'FIRST EPSS call deadline expired.' : 'FIRST EPSS call cancelled.',
    {
      retryable: false,
      errorSource: deadline ? 'FetchSignalTimeout' : 'FetchAborted',
      recovery: {
        hint: deadline
          ? 'Retry with fewer CVEs or a smaller query limit.'
          : 'Call the same tool again only if the result is still needed.',
      },
    },
  );
}
/** Keep only safe classification and retry accounting from framework errors. */
export function safeError(error: unknown, endpoint: 'scores' | 'model_header'): McpError {
  const code = error instanceof McpError ? error.code : JsonRpcErrorCode.ServiceUnavailable;
  const data: Record<string, unknown> = { endpoint };
  if (error instanceof McpError) {
    for (const key of ['status', 'retryAttempts', 'deadlineMs', 'elapsedMs'])
      if (typeof error.data?.[key] === 'number' && Number.isFinite(error.data[key]))
        data[key] = error.data[key];
    if (typeof error.data?.retryable === 'boolean') data.retryable = error.data.retryable;
    if (
      [
        'FetchSignalTimeout',
        'FetchTimeout',
        'FetchAborted',
        'FetchHttpError',
        'FetchNetworkErrorWrapper',
      ].includes(String(error.data?.errorSource))
    )
      data.errorSource = error.data?.errorSource;
    if (
      [
        'upstream_shape',
        'pacer_shed',
        'retry_deadline_exceeded',
        'invalid_filter_combination',
        'snapshot_unavailable',
      ].includes(String(error.data?.reason))
    )
      data.reason = error.data?.reason;
    const retryAfter = error.data?.retryAfter;
    if (typeof retryAfter === 'number' && Number.isFinite(retryAfter) && retryAfter >= 0)
      data.retryAfter = retryAfter;
    else if (
      typeof retryAfter === 'string' &&
      (/^\d+$/.test(retryAfter) ||
        /^\w{3}, \d{2} \w{3} \d{4} \d{2}:\d{2}:\d{2} GMT$/.test(retryAfter))
    )
      data.retryAfter = retryAfter;
  }
  let hint = "Call epss_list_reference with topic='coverage' before changing the request.";
  if (code === JsonRpcErrorCode.ServiceUnavailable || code === JsonRpcErrorCode.InternalError)
    hint = 'Retry the same tool call later; no CVEs were classified as unscored.';
  if (code === JsonRpcErrorCode.RateLimited)
    hint = 'Wait for Retry-After when supplied, then retry the same tool call.';
  if (code === JsonRpcErrorCode.Timeout) hint = 'Retry with fewer CVEs or a smaller query limit.';
  if (code === JsonRpcErrorCode.RequestCancelled)
    hint = 'Call the same tool again only if the result is still needed.';
  if (data.reason === 'upstream_shape')
    hint =
      "Retry the same tool call once; if it persists, call epss_list_reference with topic='coverage' and do not interpret the response as missing scores.";
  if (data.reason === 'invalid_filter_combination')
    hint =
      "Call epss_list_reference with topic='coverage', then call epss_query_threshold with ordered bounds or a year/addition filter.";
  if (data.reason === 'snapshot_unavailable')
    hint = 'Call the same tool with another date or omit date for latest available data.';
  data.recovery = { hint };
  return trustedError(
    new McpError(
      code,
      error instanceof McpError && trustedErrors.has(error)
        ? error.message
        : `FIRST EPSS ${endpoint === 'scores' ? 'score request' : 'model metadata request'} failed${typeof data.status === 'number' ? ` (HTTP ${data.status})` : ''}.`,
      data,
    ),
  );
}
