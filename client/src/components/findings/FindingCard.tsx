import { ChevronRight } from 'lucide-react';
import { forwardRef } from 'react';
import { CATEGORY_LABEL } from '../../constants/severity';
import type { Finding } from '../../types';
import { cx, pct } from '../../utils/format';
import { SeverityBadge, SourceTag } from '../common/Badge';
import { Indicator } from '../common/Indicator';

export const FindingCard = forwardRef<
  HTMLDivElement,
  { finding: Finding; open: boolean; onToggle: () => void; contribution?: string }
>(function FindingCard({ finding, open, onToggle, contribution }, ref) {
  return (
    <div
      ref={ref}
      className={cx('scroll-mt-24 border-b border-line last:border-b-0', open && 'bg-raised/60')}
      data-finding={finding.id}
    >
      <button
        type="button"
        onClick={onToggle}
        aria-expanded={open}
        className="grid w-full grid-cols-[76px_minmax(0,1fr)_auto] items-center gap-3 px-4 py-2.5 text-left hover:bg-raised"
      >
        <SeverityBadge severity={finding.severity} />
        <span className="min-w-0">
          <span className="block truncate text-[13.5px] font-medium">{finding.title}</span>
          <span className="block truncate text-[12.5px] text-muted">{finding.description}</span>
        </span>
        <span className="flex items-center gap-3 text-[12px] text-muted">
          <span className="hidden sm:inline">
            {CATEGORY_LABEL[finding.category] ?? finding.category}
          </span>
          <span className="hidden tabular-nums md:inline" title="Detector confidence">
            {pct(finding.confidence, 0)}
          </span>
          <ChevronRight size={15} className={cx('transition-transform', open && 'rotate-90')} />
        </span>
      </button>
      {open && (
        <div className="grid gap-5 px-4 pt-1 pb-4 md:pl-[104px] lg:grid-cols-[minmax(0,1.3fr)_minmax(0,1fr)]">
          <div className="min-w-0 space-y-4">
            <div>
              <h4 className="mb-1.5 text-[12.5px] font-semibold text-muted">Evidence</h4>
              <dl className="divide-y divide-line rounded-md border border-line bg-sunken">
                {finding.evidence.map((item, i) => (
                  <div
                    key={i}
                    className="grid grid-cols-[minmax(80px,150px)_1fr] gap-3 px-3 py-1.5 text-[12.5px]"
                  >
                    <dt className="truncate text-muted" title={item.label}>
                      {item.label}
                    </dt>
                    <dd className="min-w-0 font-mono text-[12px] break-all">{item.value}</dd>
                  </div>
                ))}
              </dl>
            </div>
            {finding.relatedUrls && finding.relatedUrls.length > 0 && (
              <div>
                <h4 className="mb-1.5 text-[12.5px] font-semibold text-muted">Related URLs</h4>
                <ul className="space-y-1">
                  {finding.relatedUrls.slice(0, 5).map((url) => (
                    <li key={url}>
                      <Indicator value={url} />
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
          <div className="min-w-0 space-y-3 text-[13px]">
            <div>
              <h4 className="text-[12.5px] font-semibold text-muted">Why it matters</h4>
              <p className="mt-0.5">{finding.whyItMatters}</p>
            </div>
            <div>
              <h4 className="text-[12.5px] font-semibold text-muted">Recommendation</h4>
              <p className="mt-0.5">{finding.recommendation}</p>
            </div>
            <div>
              <h4 className="text-[12.5px] font-semibold text-muted">Detection method</h4>
              <p className="mt-0.5 text-muted">{finding.method}</p>
            </div>
            {finding.adjustment && (
              <p className="rounded-md border border-line bg-sunken px-3 py-2 text-[12.5px] text-muted">
                Severity lowered from{' '}
                <strong className="text-text">{finding.adjustment.from}</strong> to{' '}
                <strong className="text-text">{finding.adjustment.to}</strong>.{' '}
                {finding.adjustment.reason}
              </p>
            )}
            <div className="flex flex-wrap items-center gap-2 pt-1 text-[12px] text-muted">
              <SourceTag source={finding.source} />
              <code className="font-mono text-[11.5px]">{finding.detector}</code>
              {finding.attack?.map((t) => (
                <a
                  key={t}
                  href={`https://attack.mitre.org/techniques/${t.replace('.', '/')}/`}
                  target="_blank"
                  rel="noreferrer noopener"
                  className="rounded border border-line px-1.5 py-px font-mono text-[11px] hover:border-accent hover:text-text"
                >
                  ATT&CK {t}
                </a>
              ))}
              {contribution && <span>Feeds {contribution}</span>}
            </div>
          </div>
        </div>
      )}
    </div>
  );
});
