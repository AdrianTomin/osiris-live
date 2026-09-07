import { fetch as tauriFetch, type ClientOptions } from '@tauri-apps/plugin-http';

/**
 * Drop-in replacement for `fetch` from `@tauri-apps/plugin-http`.
 *
 * The plugin wires the caller's `AbortSignal` straight through to the Rust side and
 * never unsubscribes:
 *
 *   signal.addEventListener('abort', () => void abort())              // plugin:http|fetch_cancel
 *   new ReadableStream({ start: () => signal.addEventListener('abort', dropBody) })
 *
 * Both listeners stay armed for the lifetime of the signal, and both fire-and-forget
 * their `invoke()` promise. An `AbortSignal.timeout(n)` keeps running after the
 * response has been consumed, so when it eventually fires the Rust resource table has
 * already dropped the request (`fetch_send` takes it) and the response body
 * (`fetch_read_body` closes it once the stream ends). The dead rids reject with
 * "The resource id <n> is invalid." and — being unawaited — surface as
 * `unhandledRejection`, one per completed request.
 *
 * So the signal is never handed to the plugin. It is proxied instead, and the proxy is
 * disarmed as the request moves past the point where each rid is still valid:
 *
 *   - before the response arrives: cancel through the plugin (the request rid is live);
 *   - body untouched: cancel the body stream (releases the response rid);
 *   - body being read: reject the read;
 *   - body fully read: do nothing, everything is already released.
 */
export async function fetch(
  input: URL | Request | string,
  init?: RequestInit & ClientOptions,
): Promise<Response> {
  const signal = init?.signal ?? undefined;
  if (signal?.aborted) throw new Error(ERROR_REQUEST_CANCELLED);

  // Phase 1 — request in flight. The request rid is live, so the plugin's own
  // cancellation path is safe to use; proxy the signal into it.
  const inflight = new AbortController();
  const cancelRequest = () => inflight.abort();
  signal?.addEventListener('abort', cancelRequest, { once: true });

  let res: Response;
  try {
    res = await tauriFetch(input, { ...init, signal: inflight.signal });
  } finally {
    // Phase 2 — headers are in (or the request failed) and `fetch_send` has consumed
    // the request rid. The plugin must not see this signal again.
    signal?.removeEventListener('abort', cancelRequest);
  }

  if (signal) guardBody(res, signal);
  return res;
}

const ERROR_REQUEST_CANCELLED = 'Request cancelled';

// `bytes()` is absent on older WebView2 / WebKit builds, hence the optional values.
const BODY_METHODS = ['arrayBuffer', 'blob', 'bytes', 'formData', 'json', 'text'] as const;
type BodyReaders = Record<(typeof BODY_METHODS)[number], (() => Promise<unknown>) | undefined>;

/**
 * Keeps the timeout meaningful for the body-reading phase, which is no longer covered
 * by the plugin now that it never sees the signal.
 */
function guardBody(res: Response, signal: AbortSignal): void {
  let state: 'untouched' | 'reading' | 'done' = 'untouched';
  let rejectRead: ((reason: Error) => void) | null = null;

  const onAbort = () => {
    if (state === 'untouched') {
      // Nothing has locked the stream, so cancelling it runs the plugin's `cancel`
      // algorithm and releases the Rust-side response. This is the path taken by call
      // sites that bail out on `!res.ok` without reading the body.
      void res.body?.cancel().catch(() => {});
    } else if (state === 'reading') {
      // The stream is locked by the in-flight read, so it cannot be cancelled from
      // here; reject the read and let the response resource go with the WebView.
      rejectRead?.(new Error(ERROR_REQUEST_CANCELLED));
    }
  };
  signal.addEventListener('abort', onAbort, { once: true });

  const readers = res as unknown as BodyReaders;
  for (const name of BODY_METHODS) {
    const read = readers[name];
    if (typeof read !== 'function') continue;
    Object.defineProperty(res, name, {
      configurable: true,
      writable: true,
      value: () => {
        if (signal.aborted) return Promise.reject(new Error(ERROR_REQUEST_CANCELLED));
        state = 'reading';
        return new Promise((resolve, reject) => {
          rejectRead = reject;
          read.call(res).then(resolve, reject).finally(() => {
            state = 'done';
            rejectRead = null;
            signal.removeEventListener('abort', onAbort);
          });
        });
      },
    });
  }
}
