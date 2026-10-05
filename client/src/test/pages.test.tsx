import { fireEvent, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { AnalyzePage } from '../pages/AnalyzePage';
import { InvestigationsPage } from '../pages/InvestigationsPage';
import type * as ApiModule from '../services/api';
import { ApiError } from '../services/api';
import { analysis, summary } from './fixtures';
import { renderWithProviders } from './render';

const mocks = vi.hoisted(() => ({
  analyzeWithProgress: vi.fn(),
  listAnalyses: vi.fn(),
  samples: vi.fn(),
}));

vi.mock('../services/api', async () => {
  const actual = await vi.importActual<typeof ApiModule>('../services/api');
  return {
    ...actual,
    analyzeWithProgress: mocks.analyzeWithProgress,
    api: { ...actual.api, listAnalyses: mocks.listAnalyses, samples: mocks.samples },
  };
});

beforeEach(() => {
  vi.clearAllMocks();
  mocks.samples.mockResolvedValue([
    { name: 'phishing/paypal-alert.eml', label: 'phishing', title: 'paypal alert' },
  ]);
});

describe('upload workflow', () => {
  it('uploads a file, shows real stages and opens the investigation', async () => {
    mocks.analyzeWithProgress.mockImplementation(async (_input, onEvent) => {
      onEvent({
        type: 'stage',
        stage: { id: 'parse', label: 'Email parsed', status: 'done', durationMs: 4 },
      });
      return analysis();
    });
    renderWithProviders(<AnalyzePage />, { route: '/analyze' });
    const file = new File(['From: a@b.c\nSubject: x\n\nbody'], 'suspicious.eml', {
      type: 'message/rfc822',
    });
    await userEvent.upload(screen.getByLabelText('Choose an email file'), file);
    await waitFor(() => expect(screen.getByText('Investigation page')).toBeInTheDocument());
    expect(mocks.analyzeWithProgress).toHaveBeenCalledWith(
      { kind: 'file', file },
      expect.any(Function),
    );
  });

  it('rejects oversized files before uploading', async () => {
    renderWithProviders(<AnalyzePage />, { route: '/analyze' });
    const big = new File(['x'], 'big.eml');
    Object.defineProperty(big, 'size', { value: 11 * 1024 * 1024 });
    fireEvent.change(screen.getByLabelText('Choose an email file'), { target: { files: [big] } });
    expect(await screen.findByText('File too large')).toBeInTheDocument();
    expect(mocks.analyzeWithProgress).not.toHaveBeenCalled();
  });

  it('reports a failed analysis clearly and offers a retry', async () => {
    mocks.analyzeWithProgress.mockRejectedValue(
      new ApiError(
        422,
        'mime_parse_failed',
        'The email could not be parsed because its MIME structure is malformed.',
      ),
    );
    renderWithProviders(<AnalyzePage />, { route: '/analyze' });
    await userEvent.click(screen.getByRole('tab', { name: 'Paste raw email' }));
    await userEvent.type(screen.getByLabelText('Raw email source'), 'From: x@y.z');
    await userEvent.click(screen.getByRole('button', { name: 'Analyze email' }));
    expect(
      await screen.findByText(/MIME structure is malformed\. No data was modified\./),
    ).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Try again' })).toBeInTheDocument();
  });
});

describe('investigation history', () => {
  it('renders rows from the API and passes filters through', async () => {
    mocks.listAnalyses.mockResolvedValue({
      items: [
        summary(),
        summary({
          id: 'an_test0000000002',
          subject: 'Weekly digest',
          riskLevel: 'safe',
          riskScore: 2,
          classification: 'legitimate',
        }),
      ],
      total: 2,
      page: 1,
      pageSize: 25,
    });
    renderWithProviders(<InvestigationsPage />, { route: '/investigations' });
    expect(await screen.findByText('Weekly digest')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Phishing' }));
    await waitFor(() =>
      expect(mocks.listAnalyses).toHaveBeenLastCalledWith(
        expect.objectContaining({ classification: ['phishing'] }),
      ),
    );
  });

  it('guides the analyst when there are no investigations', async () => {
    mocks.listAnalyses.mockResolvedValue({ items: [], total: 0, page: 1, pageSize: 25 });
    renderWithProviders(<InvestigationsPage />, { route: '/investigations' });
    expect(await screen.findByText('No investigations yet')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Analyze email' })).toHaveAttribute('href', '/analyze');
  });
});
