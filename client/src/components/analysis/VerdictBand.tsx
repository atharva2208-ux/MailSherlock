import { useEffect, useState } from 'react';
import {
  CLASSIFICATION_COLOR,
  CLASSIFICATION_LABEL,
  LEVEL_COLOR,
  RISK_BANDS,
  RISK_LABEL,
  SEVERITY_LABEL,
  SEVERITY_ORDER,
} from '../../constants/severity';
import type { AnalysisResult } from '../../types';
import { pct } from '../../utils/format';

const prefersReducedMotion = () =>
  Boolean(window.matchMedia?.('(prefers-reduced-motion: reduce)').matches);

function useCountUp(target: number, duration = 700) {
  const [reduced] = useState(prefersReducedMotion);
  const [value, setValue] = useState(0);
  useEffect(() => {
    if (reduced) return;
    let frame = 0;
    const start = performance.now();
    const tick = (now: number) => {
      const t = Math.min(1, (now - start) / duration);
      setValue(Math.round(target * (1 - (1 - t) ** 3)));
      if (t < 1) frame = requestAnimationFrame(tick);
    };
    frame = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(frame);
  }, [target, duration, reduced]);
  return reduced ? target : value;
}

/**
 * The verdict at a glance: classification, score on the five-band scale, and
 * the ML probability on the same axis so rule and model evidence can be
 * compared visually.
 */
export function VerdictBand({ analysis }: { analysis: AnalysisResult }) {
  const { risk, ml, findings } = analysis;
  const score = useCountUp(risk.score);
  const color = LEVEL_COLOR[risk.level];
  const counts = SEVERITY_ORDER.map((s) => ({
    s,
    n: findings.filter((f) => f.severity === s).length,
  })).filter((c) => c.n > 0 && c.s !== 'info');
  const mlPosition = ml.available && ml.probability !== undefined ? ml.probability * 100 : null;

  return (
    <section
      aria-label="Final verdict"
      className="relative overflow-hidden rounded-lg border border-line bg-surface"
    >
      <span aria-hidden className="absolute inset-y-0 left-0 w-1" style={{ background: color }} />
      <div className="grid gap-6 p-5 pl-6 lg:grid-cols-[minmax(0,1fr)_260px]">
        <div className="min-w-0">
          <p className="text-[13px] text-muted">
            Final verdict ·{' '}
            <span
              className="font-semibold"
              style={{ color: CLASSIFICATION_COLOR[risk.classification] }}
            >
              {CLASSIFICATION_LABEL[risk.classification]}
            </span>
          </p>
          <div className="mt-1 flex items-end gap-4">
            <p
              className="text-[64px] leading-[0.95] font-semibold tracking-[-0.03em] tabular-nums"
              style={{ color }}
              aria-label={`Risk score ${risk.score} out of 100`}
            >
              {score}
            </p>
            <div className="pb-1.5">
              <p className="text-[22px] font-semibold leading-none" style={{ color }}>
                {RISK_LABEL[risk.level]} risk
              </p>
              <p className="mt-1 text-[12.5px] text-muted">
                score out of 100 · {risk.rawPoints} raw evidence points
              </p>
            </div>
          </div>

          <div
            className="mt-5"
            role="img"
            aria-label={`Score ${risk.score} on a scale from safe to critical${mlPosition !== null ? `; ML probability ${Math.round(mlPosition)} percent` : ''}`}
          >
            <div className="relative">
              <div className="flex h-2.5 gap-[3px]">
                {RISK_BANDS.map((band) => (
                  <div
                    key={band.level}
                    className="flex-1 rounded-[2px]"
                    style={{
                      background: LEVEL_COLOR[band.level],
                      opacity: risk.score >= band.from ? 0.95 : 0.22,
                    }}
                  />
                ))}
              </div>
              <span
                aria-hidden
                className="absolute -top-1.5 h-[22px] w-[3px] -translate-x-1/2 rounded-full bg-text shadow-[0_0_0_2px_var(--surface)] transition-[left] duration-700"
                style={{ left: `${score}%` }}
              />
              {mlPosition !== null && (
                <span
                  aria-hidden
                  className="absolute top-4 -translate-x-1/2 text-[11px] whitespace-nowrap text-muted"
                  style={{ left: `${Math.min(96, Math.max(4, mlPosition))}%` }}
                >
                  ▲ ML {pct(ml.probability!, 0)}
                </span>
              )}
            </div>
            <div className="mt-6 flex text-[11px] text-faint">
              {RISK_BANDS.map((band) => (
                <span key={band.level} className="flex-1">
                  {RISK_LABEL[band.level]}
                </span>
              ))}
            </div>
          </div>
          <p className="mt-4 max-w-[78ch] text-[13.5px] leading-relaxed text-text">
            {risk.summary}
          </p>
        </div>

        <dl className="grid content-start gap-3 border-t border-line pt-4 text-[13px] lg:border-t-0 lg:border-l lg:pt-0 lg:pl-6">
          <div>
            <dt className="text-muted">Findings</dt>
            <dd className="mt-1 text-[22px] font-semibold tabular-nums">
              {findings.filter((f) => f.severity !== 'info').length}
            </dd>
            <dd className="mt-1 flex flex-wrap gap-x-3 gap-y-1">
              {counts.length === 0 && <span className="text-muted">No indicators</span>}
              {counts.map(({ s, n }) => (
                <span key={s} className="tabular-nums" style={{ color: LEVEL_COLOR[s] }}>
                  {n} {SEVERITY_LABEL[s].toLowerCase()}
                </span>
              ))}
            </dd>
          </div>
          <div>
            <dt className="text-muted">ML phishing probability</dt>
            <dd className="mt-0.5">
              {ml.available ? (
                <span>
                  <span className="text-[17px] font-semibold tabular-nums">
                    {pct(ml.probability, 0)}
                  </span>{' '}
                  <span className="text-muted">({ml.confidence} confidence)</span>
                </span>
              ) : (
                <span className="text-muted">Unavailable · rule-based verdict</span>
              )}
            </dd>
          </div>
          <div>
            <dt className="text-muted">Sender context</dt>
            <dd className="mt-0.5">
              {risk.trustedContext ? (
                <span className="text-safe">Authenticated, links stay on own domain</span>
              ) : (
                <span>Not established</span>
              )}
            </dd>
          </div>
        </dl>
      </div>
    </section>
  );
}
