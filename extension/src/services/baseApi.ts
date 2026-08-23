/**
 * PhishGuard AI - Base API Client
 *
 * Shared types, retry logic with exponential backoff, request timeouts,
 * and HTTP error mapping for all backend API clients.
 */

// ============================================================================
// CONFIGURATION
// ============================================================================

export const DEFAULT_BASE_URL = 'http://localhost:5000';

const DEFAULT_TIMEOUT_MS = 10_000;
const DEFAULT_MAX_RETRIES = 3;
const RETRY_DELAYS_MS = [1_000, 2_000, 4_000]; // plan: 1s / 2s / 4s

// ============================================================================
// SHARED TYPES
// ============================================================================

export interface FeatureVector {
  url_length: number;
  has_https: boolean;
  has_at_symbol: boolean;
  has_ip_address: boolean;
  dash_count: number;
  digit_ratio: number;
  special_char_count: number;
  subdomain_count: number;
  suspicious_tld: boolean;
  entropy: number;
}

export interface ScanResult {
  session_id?: string;
  analysis_id?: number;
  url: string;
  prediction: 'safe' | 'suspicious' | 'phishing' | string;
  confidence: number;
  risk_score: number; // 0-100
  risk_level: string;
  risk_breakdown?: Record<string, number>;
  reasons?: string[];
  summary?: string;
  security_tips?: string[];
  recommendation?: string;
  explanation?: string | Record<string, unknown>;
  features?: Record<string, unknown>;
  analyzed_at: string;
}

export type ScanCacheEntry = {
  session_id: string;
  url: string;
  risk_score: number;
  prediction: 'safe' | 'suspicious' | 'phishing' | string;
  summary?: string;
  timestamp: number;
};

export interface AnalysisResult {
  url: string;
  result?: ScanResult | null;
  cached: boolean;
}

export interface ScanResponse {
  scan_result: ScanResult;
}

export interface MetricsOverview {
  total_scans: number;
  risk_distribution?: Record<string, number>;
  type_distribution?: Record<string, number>;
  unique_users?: number;
  days_analyzed?: number;
}

export interface SystemHealth {
  status?: string;
  cache_entries?: number;
  config_loaded?: boolean;
  last_config_update?: string | null;
  uptime_hours?: number;
}

export interface ModelVersionInfo {
  version?: string;
  model_type?: string;
  created_at?: string | null;
  is_active?: boolean;
  metrics_json?: Record<string, unknown> | null;
}

// ============================================================================
// ERROR TYPES & HTTP ERROR MAPPING
// ============================================================================

export class BaseAPIError extends Error {
  constructor(
    message: string,
    public code: string,
    public retryAfterSeconds?: number,
    public originalError?: unknown
  ) {
    super(message);
    this.name = 'BaseAPIError';
  }
}

export class RateLimitError extends BaseAPIError {
  constructor(retryAfterSeconds: number) {
    super(
      `Rate limit exceeded, retry in ${retryAfterSeconds} seconds`,
      'RATE_LIMITED',
      retryAfterSeconds
    );
    this.name = 'RateLimitError';
  }
}

export class NotFoundError extends BaseAPIError {
  constructor(message = 'Resource not found') {
    super(message, 'NOT_FOUND');
    this.name = 'NotFoundError';
  }
}

export class ServerError extends BaseAPIError {
  constructor(message = 'Backend error, try again later') {
    super(message, 'SERVER_ERROR');
    this.name = 'ServerError';
  }
}

export class BackendUnavailableError extends BaseAPIError {
  constructor(originalError?: unknown) {
    super('Backend service is temporarily unavailable', 'BACKEND_UNAVAILABLE', undefined, originalError);
    this.name = 'BackendUnavailableError';
  }
}

export class ParseError extends BaseAPIError {
  constructor(message: string) {
    super(`Failed to parse response: ${message}`, 'PARSE_ERROR');
    this.name = 'ParseError';
  }
}

/** Map an HTTP status (or fetch failure) to a typed API error per plan spec. */
export function mapHttpError(status: number, body?: string): BaseAPIError {
  switch (status) {
    case 429: {
      // Retry-After header is handled at request level; default to 60s here.
      return new RateLimitError(60);
    }
    case 404:
      return new NotFoundError(body || undefined);
    case 500:
    case 502:
    case 503:
    case 504:
      return new ServerError(body || undefined);
    default:
      return new BaseAPIError(`HTTP ${status}: ${body || 'Unknown error'}`, `HTTP_${status}`);
  }
}

export function isBackendUnavailable(error: unknown): boolean {
  return error instanceof BackendUnavailableError;
}

// ============================================================================
// BASE API CLIENT
// ============================================================================

/**
 * Abstract base client for all API clients.
 * Provides timeout handling and retry with exponential backoff.
 */
export abstract class BaseApiClient {
  protected baseUrl: string;

  constructor(baseUrl: string = DEFAULT_BASE_URL) {
    this.baseUrl = baseUrl.replace(/\/+$/, '');
  }

  /**
   * Perform a request with timeout + exponential backoff retries.
   * Retries on network failures and 5xx responses (not on 4xx).
   */
  protected async requestWithRetry<T>(
    endpoint: string,
    options: RequestInit = {},
    {
      timeoutMs = DEFAULT_TIMEOUT_MS,
      maxRetries = DEFAULT_MAX_RETRIES,
    } = {}
  ): Promise<T> {
    let lastError: unknown;

    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      if (attempt > 0) {
        const delay = RETRY_DELAYS_MS[Math.min(attempt - 1, RETRY_DELAYS_MS.length - 1)];
        await sleep(delay);
        console.log(`[BaseAPI] Retry attempt ${attempt}/${maxRetries} for ${endpoint}`);
      }

      try {
        return await this.requestOnce<T>(endpoint, options, timeoutMs);
      } catch (error) {
        lastError = error;

        if (error instanceof BaseAPIError && !(error instanceof ServerError)) {
          throw error; // 4xx-class errors are not retryable
        }
        // Network errors and 5xx: fall through to retry
      }
    }

    throw lastError;
  }

  private async requestOnce<T>(
    endpoint: string,
    options: RequestInit,
    timeoutMs: number
  ): Promise<T> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    let response: Response;
    try {
      response = await fetch(`${this.baseUrl}${endpoint}`, {
        ...options,
        signal: controller.signal,
      });
    } catch (error) {
      throw new BackendUnavailableError(error);
    } finally {
      clearTimeout(timer);
    }

    if (!response.ok) {
      if (response.status === 429) {
        const retryAfter = Number(response.headers.get('Retry-After')) || 60;
        throw new RateLimitError(retryAfter);
      }
      const body = await safeReadBody(response);
      throw mapHttpError(response.status, body ?? undefined);
    }

    try {
      return (await response.json()) as T;
    } catch (error) {
      throw new ParseError('Response is not valid JSON');
    }
  }

  protected async get<T>(endpoint: string): Promise<T> {
    return this.requestWithRetry<T>(endpoint, { method: 'GET' });
  }

  protected async post<T>(endpoint: string, body?: unknown): Promise<T> {
    return this.requestWithRetry<T>(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
  }
}

async function safeReadBody(response: Response): Promise<string | null> {
  try {
    return await response.text();
  } catch {
    return null;
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/** Async-aware retry wrapper with exponential backoff (1s doubling). */
export async function withRetry<T>(
  fn: () => Promise<T>,
  options?: { maxRetries?: number; initialDelayMs?: number }
): Promise<T> {
  const opts = { maxRetries: 3, initialDelayMs: 1000, ...options };
  let lastError: unknown;

  for (let attempt = 0; attempt < opts.maxRetries; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error;
      if (attempt < opts.maxRetries - 1) {
        const delay = opts.initialDelayMs * Math.pow(2, attempt);
        console.log(`[Retry] Attempt ${attempt + 1} failed. Retrying in ${delay / 1000}s...`);
        await sleep(delay);
      }
    }
  }

  throw lastError;
}
