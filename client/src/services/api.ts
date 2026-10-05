import type {
  AnalysisEvent,
  AnalysisResult,
  AnalysisSummary,
  AnalystFeedback,
  ApiErrorBody,
  DashboardStats,
  FeedbackVerdict,
  HealthReport,
  IntelResponse,
  ModelInfoResponse,
  Paginated,
  SampleEmail,
} from '../types';

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
  ) {
    super(message);
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`/api${path}`, {
      ...init,
      headers: { accept: 'application/json', ...init?.headers },
    });
  } catch {
    throw new ApiError(
      0,
      'network_error',
      'The MailSherlock API is not reachable. Check that the server is running.',
    );
  }
  const body = (await response.json().catch(() => null)) as
    ({ success?: boolean; error?: ApiErrorBody } & T) | null;
  if (!response.ok || !body || body.success === false) {
    throw new ApiError(
      response.status,
      body?.error?.code ?? 'http_error',
      body?.error?.message ?? `Request failed (HTTP ${response.status})`,
    );
  }
  return body;
}

export interface ListParams {
  page?: number;
  pageSize?: number;
  search?: string;
  riskLevel?: string[];
  classification?: string[];
  from?: string;
  to?: string;
  sort?: string;
  order?: 'asc' | 'desc';
}

function toQuery(params: ListParams): string {
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === '' || (Array.isArray(value) && !value.length)) continue;
    query.set(key, Array.isArray(value) ? value.join(',') : String(value));
  }
  const text = query.toString();
  return text ? `?${text}` : '';
}

export const api = {
  health: () => request<HealthReport>('/health'),
  stats: () => request<DashboardStats>('/stats'),
  model: () => request<ModelInfoResponse>('/model'),
  listAnalyses: (params: ListParams) =>
    request<Paginated<AnalysisSummary>>(`/analyses${toQuery(params)}`),
  getAnalysis: (id: string) =>
    request<{ analysis: AnalysisResult }>(`/analyses/${encodeURIComponent(id)}`).then(
      (r) => r.analysis,
    ),
  deleteAnalysis: (id: string) =>
    request<{ success: true }>(`/analyses/${encodeURIComponent(id)}`, { method: 'DELETE' }),
  async getRaw(id: string): Promise<string> {
    const response = await fetch(`/api/analyses/${encodeURIComponent(id)}/raw`);
    if (!response.ok) {
      const body = (await response.json().catch(() => null)) as { error?: ApiErrorBody } | null;
      throw new ApiError(
        response.status,
        body?.error?.code ?? 'http_error',
        body?.error?.message ?? 'Raw source unavailable',
      );
    }
    return response.text();
  },
  reportUrl: (id: string) => `/api/analyses/${encodeURIComponent(id)}/report`,
  submitFeedback: (analysisId: string, verdict: FeedbackVerdict, notes?: string) =>
    request<{ feedback: AnalystFeedback }>('/feedback', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ analysisId, verdict, notes: notes || undefined }),
    }).then((r) => r.feedback),
  threatIntel: (indicator: string) =>
    request<IntelResponse>(`/threat-intel/${encodeURIComponent(indicator)}`),
  samples: () => request<{ samples: SampleEmail[] }>('/samples').then((r) => r.samples),
  async sample(name: string): Promise<string> {
    const response = await fetch(
      `/api/samples/${name.split('/').map(encodeURIComponent).join('/')}`,
    );
    if (!response.ok)
      throw new ApiError(response.status, 'sample_unavailable', 'Sample could not be loaded');
    return response.text();
  },
};

export type AnalyzeInput =
  { kind: 'file'; file: File } | { kind: 'raw'; raw: string; sourceName?: string };

/**
 * Submit an email and consume the Server-Sent Events stream from the POST
 * response. Each stage event is a real backend stage completing; the final
 * event carries the result or a structured error.
 */
export async function analyzeWithProgress(
  input: AnalyzeInput,
  onEvent: (event: AnalysisEvent) => void,
  signal?: AbortSignal,
): Promise<AnalysisResult> {
  let body: BodyInit;
  const headers: Record<string, string> = { accept: 'text/event-stream' };
  if (input.kind === 'file') {
    const form = new FormData();
    form.append('email', input.file);
    body = form;
  } else {
    body = JSON.stringify({ raw: input.raw, sourceName: input.sourceName });
    headers['content-type'] = 'application/json';
  }

  let response: Response;
  try {
    response = await fetch(input.kind === 'file' ? '/api/analyze' : '/api/analyze/raw', {
      method: 'POST',
      body,
      headers,
      signal,
    });
  } catch (error) {
    if ((error as Error).name === 'AbortError') throw error;
    throw new ApiError(
      0,
      'network_error',
      'The MailSherlock API is not reachable. Check that the server is running.',
    );
  }
  if (!response.ok || !response.body) {
    const errorBody = (await response.json().catch(() => null)) as { error?: ApiErrorBody } | null;
    throw new ApiError(
      response.status,
      errorBody?.error?.code ?? 'http_error',
      errorBody?.error?.message ?? `Analysis failed (HTTP ${response.status})`,
    );
  }

  const reader = response.body.pipeThrough(new TextDecoderStream()).getReader();
  let buffer = '';
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    buffer += value;
    let boundary: number;
    while ((boundary = buffer.indexOf('\n\n')) >= 0) {
      const block = buffer.slice(0, boundary);
      buffer = buffer.slice(boundary + 2);
      const data = block.split('\n').find((line) => line.startsWith('data: '));
      if (!data) continue;
      const event = JSON.parse(data.slice(6)) as AnalysisEvent;
      onEvent(event);
      if (event.type === 'result') return event.analysis;
      if (event.type === 'error') throw new ApiError(422, event.error.code, event.error.message);
    }
  }
  throw new ApiError(0, 'stream_ended', 'The analysis stream ended before a result was received.');
}
