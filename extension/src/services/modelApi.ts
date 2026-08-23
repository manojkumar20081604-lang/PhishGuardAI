/**
 * Model API Client - Model version management (GET only)
 */

import { BaseApiClient } from './baseApi';
import type { ModelVersionInfo } from './baseApi';

export class ModelApiClient extends BaseApiClient {
  constructor(baseUrl: string) {
    super(baseUrl);
  }

  /**
   * List all model versions for a given model type (e.g., 'nlp', 'vision')
   */
  async listVersions(modelType: string): Promise<ModelVersionInfo[]> {
    console.log(`[ModelAPI] Listing versions for model type: ${modelType}`);
    
    const response = await this.requestWithRetry<ModelVersionInfo[]>(
      `/api/v1/models/${encodeURIComponent(modelType)}/versions`,
      { method: 'GET' }
    );

    return response;
  }

  /**
   * Get specific model version details
   */
  async getVersion(modelType: string, versionName: string): Promise<ModelVersionInfo> {
    console.log(`[ModelAPI] Getting version: ${versionName} for type: ${modelType}`);
    
    return this.requestWithRetry<ModelVersionInfo>(
      `/api/v1/models/${encodeURIComponent(modelType)}/versions/${encodeURIComponent(versionName)}`,
      { method: 'GET' }
    );
  }

  /**
   * Check if a specific model version exists (for validation)
   */
  async checkVersionExists(modelType: string, versionName: string): Promise<boolean> {
    try {
      await this.getVersion(modelType, versionName);
      return true;
    } catch {
      return false;
    }
  }
}
