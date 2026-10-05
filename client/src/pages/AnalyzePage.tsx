import { useQuery, useQueryClient } from '@tanstack/react-query';
import { FileUp, FlaskConical, ShieldAlert, ShieldCheck, Upload } from 'lucide-react';
import { useCallback, useEffect, useRef, useState, type DragEvent } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { AnalysisProgress } from '../components/analysis/AnalysisProgress';
import { Button } from '../components/common/Button';
import { Panel } from '../components/common/Panel';
import { ErrorState } from '../components/common/States';
import { useToast } from '../components/common/Toast';
import { analyzeWithProgress, api, type AnalyzeInput } from '../services/api';
import type { StageTiming } from '../types';
import { cx, formatBytes } from '../utils/format';

const MAX_BYTES = 10 * 1024 * 1024;
type Mode = 'upload' | 'paste';
type Run =
  | { status: 'idle' }
  | { status: 'running'; name: string; stages: StageTiming[] }
  | { status: 'failed'; name: string; stages: StageTiming[]; message: string; input: AnalyzeInput };

export function AnalyzePage() {
  const navigate = useNavigate();
  const location = useLocation();
  const queryClient = useQueryClient();
  const { notify } = useToast();
  const fileInput = useRef<HTMLInputElement>(null);
  const [mode, setMode] = useState<Mode>('upload');
  const pickerRequest = (location.state as { openFilePicker?: number } | null)?.openFilePicker;
  const [raw, setRaw] = useState('');
  const [dragging, setDragging] = useState(false);
  const [run, setRun] = useState<Run>({ status: 'idle' });
  const samples = useQuery({ queryKey: ['samples'], queryFn: api.samples, staleTime: Infinity });

  // Ctrl+U navigates here with a request to open the file picker. The input
  // is always mounted, so this works whichever tab is showing.
  useEffect(() => {
    if (pickerRequest) requestAnimationFrame(() => fileInput.current?.click());
  }, [pickerRequest]);

  const start = useCallback(
    async (input: AnalyzeInput) => {
      const name = input.kind === 'file' ? input.file.name : (input.sourceName ?? 'Pasted email');
      setRun({ status: 'running', name, stages: [] });
      const stages: StageTiming[] = [];
      try {
        const analysis = await analyzeWithProgress(input, (event) => {
          if (event.type === 'stage') {
            stages.push(event.stage);
            setRun({ status: 'running', name, stages: [...stages] });
          }
        });
        void queryClient.invalidateQueries({ queryKey: ['analyses'] });
        void queryClient.invalidateQueries({ queryKey: ['stats'] });
        queryClient.setQueryData(['analysis', analysis.id], analysis);
        if (!analysis.ml.available)
          notify(
            'warning',
            'Analysis completed without ML',
            'The classifier is offline; the verdict is rule-based.',
          );
        else
          notify(
            'success',
            'Email analysis completed',
            `${analysis.risk.score}/100 · ${analysis.risk.classification}`,
          );
        navigate(`/investigations/${analysis.id}`);
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Unknown error';
        setRun({ status: 'failed', name, stages, message, input });
        notify('error', 'Analysis failed', message);
      }
    },
    [navigate, notify, queryClient],
  );

  const acceptFile = (file: File | undefined) => {
    if (!file) return;
    if (file.size > MAX_BYTES) {
      notify(
        'error',
        'File too large',
        `${file.name} is ${formatBytes(file.size)}; the limit is ${formatBytes(MAX_BYTES)}.`,
      );
      return;
    }
    if (/\.msg$/i.test(file.name)) {
      notify('error', 'Outlook .msg is not supported', 'Save the message as .eml and upload that.');
      return;
    }
    void start({ kind: 'file', file });
  };

  const onDrop = (event: DragEvent) => {
    event.preventDefault();
    setDragging(false);
    acceptFile(event.dataTransfer.files[0]);
  };

  const loadSample = async (name: string) => {
    try {
      setRaw(await api.sample(name));
      setMode('paste');
    } catch (error) {
      notify('error', 'Sample unavailable', (error as Error).message);
    }
  };

  if (run.status !== 'idle') {
    return (
      <div className="mx-auto max-w-2xl pt-6">
        <Panel
          title={run.status === 'failed' ? 'Analysis failed' : 'Investigating'}
          description={run.name}
        >
          {run.status === 'failed' && (
            <div className="mb-5">
              <ErrorState
                title="Analysis failed"
                message={`${run.message} No data was modified.`}
              />
            </div>
          )}
          <AnalysisProgress stages={run.stages} failed={run.status === 'failed'} />
          {run.status === 'failed' && (
            <div className="mt-5 flex gap-2">
              <Button variant="primary" onClick={() => void start(run.input)}>
                Try again
              </Button>
              <Button onClick={() => setRun({ status: 'idle' })}>Analyze a different email</Button>
            </div>
          )}
        </Panel>
      </div>
    );
  }

  return (
    <div>
      <section className="pt-2 pb-7">
        <h1 className="text-[clamp(40px,6vw,68px)] leading-[0.95] font-semibold tracking-[-0.035em]">
          They bait,
          <br />
          we investigate.
        </h1>
        <p className="mt-4 max-w-[52ch] text-[15px] leading-relaxed text-muted">
          Analyze suspicious emails, uncover deception, and understand the evidence behind every
          detection.
        </p>
      </section>
      <div className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_300px]">
        <div className="min-w-0">
          <div className="rounded-lg border border-line bg-surface">
            <input
              ref={fileInput}
              type="file"
              accept=".eml,.txt,message/rfc822"
              className="sr-only"
              aria-label="Choose an email file"
              onChange={(e) => acceptFile(e.target.files?.[0] ?? undefined)}
            />
            <div
              role="tablist"
              aria-label="Input method"
              className="flex border-b border-line px-2"
            >
              {(
                [
                  ['upload', 'Upload .eml'],
                  ['paste', 'Paste raw email'],
                ] as const
              ).map(([id, label]) => (
                <button
                  key={id}
                  role="tab"
                  aria-selected={mode === id}
                  onClick={() => setMode(id)}
                  className={cx(
                    '-mb-px h-11 border-b-2 px-3 text-[13.5px]',
                    mode === id
                      ? 'border-accent font-medium text-text'
                      : 'border-transparent text-muted hover:text-text',
                  )}
                >
                  {label}
                </button>
              ))}
            </div>
            {mode === 'upload' ? (
              <div className="p-4">
                <div
                  onDragOver={(e) => {
                    e.preventDefault();
                    setDragging(true);
                  }}
                  onDragLeave={() => setDragging(false)}
                  onDrop={onDrop}
                  className={cx(
                    'flex flex-col items-center justify-center gap-3 rounded-md border border-dashed px-6 py-14 text-center transition-colors',
                    dragging ? 'border-accent bg-accent-soft' : 'border-line-strong bg-sunken',
                  )}
                >
                  <FileUp size={28} className={dragging ? 'text-accent' : 'text-faint'} />
                  <div>
                    <p className="text-[15px] font-medium">Drop an .eml file here</p>
                    <p className="mt-1 text-[13px] text-muted">
                      or browse your files · up to {formatBytes(MAX_BYTES)} · nothing in the email
                      is opened or visited
                    </p>
                  </div>
                  <Button
                    variant="primary"
                    icon={<Upload size={15} />}
                    onClick={() => fileInput.current?.click()}
                  >
                    Browse files
                  </Button>
                </div>
              </div>
            ) : (
              <form
                className="p-4"
                onSubmit={(e) => {
                  e.preventDefault();
                  if (raw.trim()) void start({ kind: 'raw', raw });
                }}
              >
                <textarea
                  value={raw}
                  onChange={(e) => setRaw(e.target.value)}
                  spellCheck={false}
                  aria-label="Raw email source"
                  placeholder={
                    'Return-Path: <...>\nReceived: from ...\nFrom: "Sender" <sender@example.com>\nSubject: ...\n\nPaste the complete message source, or just its headers.'
                  }
                  className="h-80 w-full resize-y rounded-md border border-line bg-sunken p-3 font-mono text-[12.5px] leading-relaxed text-text placeholder:text-faint focus:border-accent focus:outline-none"
                />
                <div className="mt-3 flex flex-wrap items-center justify-between gap-3">
                  <p className="text-[12.5px] text-muted">
                    In Gmail use “Show original”; in Outlook, “View message source”. Headers alone
                    are enough for header and authentication analysis.
                  </p>
                  <div className="flex items-center gap-3">
                    <span className="text-[12px] tabular-nums text-faint">
                      {formatBytes(new Blob([raw]).size)}
                    </span>
                    <Button type="submit" variant="primary" disabled={!raw.trim()}>
                      Analyze email
                    </Button>
                  </div>
                </div>
              </form>
            )}
          </div>
        </div>

        <aside>
          <Panel
            title="Sample emails"
            description="Fictional messages that exercise the detection engine"
            bodyClassName="p-2"
          >
            {samples.isError && (
              <p className="p-2 text-[13px] text-muted">Samples could not be loaded.</p>
            )}
            {(['phishing', 'legitimate'] as const).map((label) => (
              <div key={label} className="mb-2">
                <p className="flex items-center gap-1.5 px-2 pt-2 pb-1 text-[12.5px] font-medium text-muted">
                  {label === 'phishing' ? (
                    <ShieldAlert size={13} className="text-critical" />
                  ) : (
                    <ShieldCheck size={13} className="text-safe" />
                  )}
                  {label === 'phishing' ? 'Phishing' : 'Legitimate'}
                </p>
                <ul>
                  {samples.data
                    ?.filter((s) => s.label === label)
                    .map((s) => (
                      <li key={s.name}>
                        <button
                          type="button"
                          onClick={() => void loadSample(s.name)}
                          className="flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-left text-[13px] text-text hover:bg-raised"
                        >
                          <FlaskConical size={13} className="text-faint" />
                          {s.title.charAt(0).toUpperCase() + s.title.slice(1)}
                        </button>
                      </li>
                    ))}
                </ul>
              </div>
            ))}
          </Panel>
        </aside>
      </div>
    </div>
  );
}
