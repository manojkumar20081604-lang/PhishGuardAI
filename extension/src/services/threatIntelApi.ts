/**
 * Threat Intel API Client - Threat intelligence cache lookups
 */

import { BaseApiClient } from './baseApi';

export class ThreatIntelApiClient extends BaseApiClient {
  constructor(baseUrl: string) {
    super(baseUrl);
  }

  /**
   * Check threat intel for a specific source type and identifier
   * e.g., source_type='domain', identifier='example.com'
   */
  async checkThreatIntel(sourceType: string, identifier: string): Promise<Record<string, any> | null> {
    console.log(`[ThreatIntelAPI] Checking threat intel for ${sourceType}: ${identifier}`);
    
    try {
      const response = await this.requestWithRetry<Record<string, any>>(
        `/api/v1/threat-intel/${encodeURIComponent(sourceType)}/${encodeURIComponent(identifier)}`,
        { method: 'GET' }
      );

      // Return null if no threat found (empty result), otherwise return the data
      if (!response || Object.keys(response).length === 0) {
        console.log('[ThreatIntelAPI] No threat intel found');
        return null;
      }

      return response;
    } catch (error: any) {
      // Handle "not found" errors gracefully - might mean no threat in cache
      if (error.message?.includes('404') || error.message?.includes('Not Found')) {
        console.log('[ThreatIntelAPI] Threat intel not found in cache');
        return null;
      }
      throw error; // Re-throw other errors
    }
  }

  /**
   * Check multiple threat intel sources (e.g., domain, ip, url)
   */
  async checkMultipleSources(sources: Array<{ sourceType: string; identifier: string }>): Promise<Record<string, any> | null> {
    const results = await Promise.all(
      sources.map(source => this.checkThreatIntel(source.sourceType, source.identifier))
    );

    // Return first non-null result (threat found) or null if all clean
    return results.find(r => r !== null) ?? null;
  }
}
