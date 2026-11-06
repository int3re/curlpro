/// <reference types="node" />

export class CurlproError extends Error {
  /** timeout, proxy, proxy_auth, proxy_closed, configuration, profile_capability, cors,
   *  too_large, session_closed, ws_closed, ws_too_big, ws_protocol — or null. */
  readonly code: string | null;
  /** proxy/proxy_auth: { stage, status }; cors: { method, url, reason, status, headers }. */
  readonly details: Record<string, unknown> | null;
  /** Retrying the same call cannot change the outcome. */
  readonly permanent: boolean;
}

export interface SessionOptions {
  /** A registered profile name; default "chrome-157-windows". */
  profile?: string;
  /** Milliseconds for the whole request; default 30000. */
  timeout?: number;
  proxy?: string;
  defaultHeaders?: boolean;
  followRedirects?: boolean;
  maxRedirects?: number;
  cookies?: boolean;
  resume?: boolean;
  trustEnv?: boolean;
  http3?: boolean;
  forceHttp1?: boolean;
  insecure?: boolean;
  /** "navigate", "fetch" or undefined (auto). */
  mode?: string;
  /** The initiator page: Referer, Origin and Sec-Fetch-Site follow from it. */
  page?: string;
  /** Any other session field of docs/C-ABI.md, sent as is. */
  extra?: Record<string, unknown>;
}

export interface RequestOptions {
  headers?: Record<string, string>;
  body?: string | Buffer | Uint8Array;
  /** Serialised as the body with content-type: application/json. */
  json?: unknown;
  /** Milliseconds. */
  timeout?: number;
  /** "http1", "h2" or "h3" to force one. */
  protocol?: string;
  signal?: AbortSignal;
  /** Any other request field of docs/C-ABI.md, sent as is. */
  extra?: Record<string, unknown>;
}

export class Response {
  readonly status: number;
  /** "HTTP/1.1", "HTTP/2.0" or "HTTP/3.0". */
  readonly proto: string;
  readonly url: string;
  readonly headers: Record<string, string[]>;
  readonly body: Buffer;
  readonly raw: Record<string, unknown>;
  header(name: string): string | undefined;
  text(): string;
  json<T = unknown>(): T;
}

export class ResponseStream implements AsyncIterable<Buffer> {
  readonly status: number;
  readonly proto: string;
  readonly url: string;
  readonly headers: Record<string, string[]>;
  read(size?: number): Promise<Buffer | null>;
  close(): void;
  [Symbol.asyncIterator](): AsyncIterator<Buffer>;
}

export interface Message {
  binary: boolean;
  data: Buffer;
  text(): string;
}

export class WebSocket {
  send(message: string | Buffer | Uint8Array): Promise<void>;
  receive(): Promise<Message>;
  close(code?: number, reason?: string): void;
}

export class Session {
  constructor(options?: SessionOptions | string);
  readonly profile: string;
  request(method: string, url: string, options?: RequestOptions): Promise<Response>;
  /** Blocks the JS thread until the response is in. */
  requestSync(method: string, url: string, options?: RequestOptions): Response;
  get(url: string, options?: RequestOptions): Promise<Response>;
  post(url: string, options?: RequestOptions): Promise<Response>;
  put(url: string, options?: RequestOptions): Promise<Response>;
  delete(url: string, options?: RequestOptions): Promise<Response>;
  stream(method: string, url: string, options?: RequestOptions): Promise<ResponseStream>;
  websocket(url: string, options?: { headers?: Record<string, string>; subprotocols?: string[]; timeout?: number; signal?: AbortSignal }): Promise<WebSocket>;
  /** ja3, ja3n, ja4, akamai… computed without sending anything. */
  fingerprint(url: string): Record<string, any>;
  preview(method: string, url: string, headers?: Record<string, string>): { names: string[]; headers: unknown[] };
  setHeader(name: string, value: string): unknown;
  removeHeader(name: string): boolean;
  suppressHeader(name: string): unknown;
  resetHeaders(): unknown;
  setPage(url: string): unknown;
  cookies(): Array<Record<string, unknown>>;
  setCookies(list: Array<Record<string, unknown>>): unknown;
  clearCookies(): void;
  cacheInfo(): Record<string, unknown>;
  close(): void;
  [Symbol.dispose](): void;
}

export const profiles: {
  loadDir(dir: string): string[];
  loadBundle(file: string, keys?: string): Record<string, unknown>;
  register(profile: string | object): string[];
  list(): string[];
  get(name: string): Record<string, unknown>;
  capabilities(name: string): Record<string, unknown>;
  ensureLoaded(): void;
};

export function version(): string;
export function debugCounts(): Record<string, number>;
export function asyncPending(): number;
