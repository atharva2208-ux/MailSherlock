import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { VerdictBand } from '../components/analysis/VerdictBand';
import { HighlightedContent } from '../components/email/HighlightedContent';
import { segmentText } from '../utils/segments';
import { FindingsPanel } from '../components/findings/FindingsPanel';
import { MlPanel } from '../components/ml/MlPanel';
import { analysis, finding } from './fixtures';
import { renderWithProviders } from './render';

describe('VerdictBand', () => {
  it('shows score, level, classification and ML probability from the analysis', () => {
    render(<VerdictBand analysis={analysis()} />);
    expect(screen.getByLabelText('Risk score 87 out of 100')).toBeInTheDocument();
    expect(screen.getByText('Critical risk')).toBeInTheDocument();
    expect(screen.getByText('Phishing')).toBeInTheDocument();
    expect(screen.getByText('91%')).toBeInTheDocument();
  });

  it('states when the verdict is rule-based only', () => {
    render(<VerdictBand analysis={analysis({ ml: { available: false, reason: 'offline' } })} />);
    expect(screen.getByText(/Unavailable · rule-based verdict/)).toBeInTheDocument();
  });
});

describe('evidence highlighting', () => {
  it('splits text into highlighted and plain segments, merging overlaps', () => {
    const text = 'abcdefghij';
    const segments = segmentText(text, [
      finding({ id: 'a', spans: [{ start: 2, end: 6, text: 'cdef' }] }),
      finding({ id: 'b', spans: [{ start: 4, end: 8, text: 'efgh' }] }),
    ]);
    expect(segments.map((s) => [s.text, s.findingIds])).toEqual([
      ['ab', []],
      ['cd', ['a']],
      ['ef', ['a', 'b']],
      ['gh', ['b']],
      ['ij', []],
    ]);
    expect(segments.map((s) => s.text).join('')).toBe(text);
  });

  it('ignores spans outside the text', () => {
    expect(segmentText('short', [finding({ spans: [{ start: 2, end: 99, text: 'x' }] })])).toEqual([
      { text: 'short', findingIds: [] },
    ]);
  });

  it('opens the finding behind a highlight on click and keyboard', async () => {
    const onSelect = vi.fn();
    const a = analysis();
    render(<HighlightedContent text={a.body.text} findings={a.findings} onSelect={onSelect} />);
    const mark = screen.getByRole('button', { name: /Evidence for: Urgency language/ });
    expect(mark).toHaveTextContent('within 24 hours');
    await userEvent.click(mark);
    mark.focus();
    await userEvent.keyboard('{Enter}');
    expect(onSelect).toHaveBeenCalledTimes(2);
    expect(onSelect).toHaveBeenCalledWith('f1');
  });
});

describe('FindingsPanel', () => {
  it('orders by severity and filters by level', async () => {
    const a = analysis();
    renderWithProviders(<FindingsPanel findings={a.findings} risk={a.risk} />);
    const toolbar = screen.getByRole('toolbar', { name: /filter findings/i });
    const titles = () =>
      screen.getAllByRole('button', { expanded: false }).map((b) => b.textContent);
    expect(titles()[0]).toContain('DMARC failed');
    await userEvent.click(within(toolbar).getByRole('button', { name: /Low/ }));
    expect(screen.queryByText('DMARC failed for the From domain')).not.toBeInTheDocument();
    expect(screen.getByText('Return-Path differs')).toBeInTheDocument();
  });

  it('expands a finding to show evidence, rationale and its score contribution', async () => {
    const a = analysis();
    renderWithProviders(<FindingsPanel findings={a.findings} risk={a.risk} />);
    await userEvent.click(screen.getByRole('button', { name: /DMARC failed for the From domain/ }));
    expect(screen.getByText('Why it matters')).toBeInTheDocument();
    expect(screen.getByText(/Feeds Sender authentication \(\+40\)/)).toBeInTheDocument();
  });

  it('opens and scrolls to a focused finding', () => {
    const a = analysis();
    renderWithProviders(<FindingsPanel findings={a.findings} risk={a.risk} focusId="f3" />);
    expect(screen.getByRole('button', { name: /Return-Path differs/ })).toHaveAttribute(
      'aria-expanded',
      'true',
    );
  });
});

describe('MlPanel', () => {
  it('explains the fallback when the model is unavailable', () => {
    renderWithProviders(
      <MlPanel ml={{ available: false, reason: 'ML service is not reachable' }} />,
    );
    expect(screen.getByText('Machine learning enrichment unavailable.')).toBeInTheDocument();
    expect(screen.getByText(/Results are based on rule-based analysis/)).toBeInTheDocument();
  });

  it('shows masked tokens in readable form', () => {
    renderWithProviders(
      <MlPanel
        ml={{
          ...analysis().ml,
          signals: [{ kind: 'term', feature: 'click urltoken', weight: 0.4 }],
        }}
      />,
    );
    expect(screen.getByText('click [link]')).toBeInTheDocument();
  });
});
