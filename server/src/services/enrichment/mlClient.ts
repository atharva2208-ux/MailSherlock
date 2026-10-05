import type { MlAssessment, MlSignal } from '../../models/analysis.js';

interface MlServiceResponse {
  model_name: string;
  model_version: string;
  probability: number;
  threshold: number;
  label: 'phishing' | 'legitimate';
  confidence: 'high' | 'medium' | 'low';
  vocabulary_coverage: number;
  signals: MlSignal[];
  inference_ms: number;
}

export interface MlClient {
  predict(raw: Buffer): Promise<MlAssessment>;
  health(): Promise<{ up: boolean; detail: string; latencyMs?: number; modelVersion?: string }>;
  modelInfo(): Promise<unknown | null>;
}

export function createMlClient(baseUrl: string, timeoutMs: number): MlClient {
  const url = (path: string) => new URL(path, baseUrl).toString();

  return {
    async predict(raw) {
      try {
        const response = await fetch(url('/predict'), {
          method: 'POST',
          headers: { 'content-type': 'application/octet-stream' },
          body: new Uint8Array(raw),
          signal: AbortSignal.timeout(timeoutMs),
        });
        if (!response.ok) {
          const detail = await response.text().catch(() => '');
          return {
            available: false,
            reason: `ML service returned HTTP ${response.status}${detail ? `: ${detail.slice(0, 160)}` : ''}`,
          };
        }
        const body = (await response.json()) as MlServiceResponse;
        return {
          available: true,
          modelName: body.model_name,
          modelVersion: body.model_version,
          probability: body.probability,
          threshold: body.threshold,
          label: body.label,
          confidence: body.confidence,
          vocabularyCoverage: body.vocabulary_coverage,
          signals: body.signals.slice(0, 20),
          inferenceMs: body.inference_ms,
        };
      } catch (error) {
        const reason =
          error instanceof Error && error.name === 'TimeoutError'
            ? `ML service did not respond within ${timeoutMs} ms`
            : 'ML service is not reachable';
        return { available: false, reason };
      }
    },

    async health() {
      const started = performance.now();
      try {
        const response = await fetch(url('/health'), {
          signal: AbortSignal.timeout(Math.min(timeoutMs, 2000)),
        });
        const latencyMs = Math.round(performance.now() - started);
        if (!response.ok) return { up: false, detail: `HTTP ${response.status}`, latencyMs };
        const body = (await response.json()) as { model_version: string };
        return {
          up: true,
          detail: `Model v${body.model_version} loaded`,
          latencyMs,
          modelVersion: body.model_version,
        };
      } catch {
        return { up: false, detail: 'Inference service not reachable' };
      }
    },

    async modelInfo() {
      try {
        const response = await fetch(url('/model'), { signal: AbortSignal.timeout(timeoutMs) });
        return response.ok ? await response.json() : null;
      } catch {
        return null;
      }
    },
  };
}
