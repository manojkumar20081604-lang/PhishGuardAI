/**
 * Metrics API Client - Dashboard and system health endpoints
 */

import { BaseApiClient } from './baseApi';
import type { MetricsOverview, SystemHealth } from './baseApi';

export class MetricsApiClient extends BaseApiClient {
  constructor(baseUrl: string) {
    super(baseUrl);
  }

  /**
   * Get dashboard overview metrics
   */
  async getOverview(): Promise<MetricsOverview> {
    console.log('[MetricsAPI] Fetching overview metrics');
    
    return this.requestWithRetry<MetricsOverview>(
      '/api/v1/metrics/overview',
      { method: 'GET' }
    );
  }

  /**
   * Check system health (backend availability, response time)
   */
  async getSystemHealth(): Promise<SystemHealth> {
    console.log('[MetricsAPI] Checking system health');
    
    return this.requestWithRetry<SystemHealth>(
      '/api/v1/metrics/system/health',
      { method: 'GET' }
    );
  }

  /**
   * Quick health check (boolean) - for lightweight availability checks
   */
  async isBackendAvailable(): Promise<boolean> {
    try {
      await this.requestWithRetry('/api/v1/metrics/system/health', { method: 'GET' }, { maxRetries: 0 });
      return true;
    } catch {
      return false;
    }
  }
}
