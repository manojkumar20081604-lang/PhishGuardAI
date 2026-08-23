/**
 * Services Index - Export all API clients and shared types
 */

// Client classes
export { ScanApiClient, scanApi, normalizePrediction } from './scanApi';
export { MetricsApiClient } from './metricsApi';
export { ModelApiClient } from './modelApi';
export { ThreatIntelApiClient } from './threatIntelApi';

// Base utilities, error types, and shared types
export {
  BaseApiClient,
  BaseAPIError,
  BackendUnavailableError,
  RateLimitError,
  NotFoundError,
  ServerError,
  ParseError,
  withRetry,
  mapHttpError,
  isBackendUnavailable,
  DEFAULT_BASE_URL,
  AnalysisResult,
  ScanResponse,
  ScanResult,
  ScanCacheEntry,
  FeatureVector,
  MetricsOverview,
  SystemHealth,
  ModelVersionInfo,
} from './baseApi';
