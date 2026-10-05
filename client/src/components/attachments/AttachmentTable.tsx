import { ChevronRight, Paperclip } from 'lucide-react';
import { Fragment, useState } from 'react';
import type { AttachmentInfo, Severity } from '../../types';
import { cx, formatBytes } from '../../utils/format';
import { LevelDot, SeverityBadge } from '../common/Badge';
import { CopyButton } from '../common/CopyButton';
import { EmptyState } from '../common/States';

function Hash({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex min-w-0 items-center gap-2">
      <span className="w-14 shrink-0 text-muted">{label}</span>
      <code className="min-w-0 truncate font-mono text-[12px]" title={value}>
        {value}
      </code>
      <CopyButton value={value} label={`Copy ${label}`} />
    </div>
  );
}

/** Attachment metadata and hashes. Files are hashed in memory and never executed or written to disk. */
export function AttachmentTable({ attachments }: { attachments: AttachmentInfo[] }) {
  const [open, setOpen] = useState<string | null>(
    attachments.find((a) => a.risk !== 'none')?.id ?? null,
  );
  if (!attachments.length)
    return <EmptyState icon={<Paperclip size={22} />} title="No attachments" />;
  return (
    <div className="overflow-x-auto rounded-lg border border-line bg-surface">
      <table className="w-full min-w-[760px] text-left text-[13px]">
        <thead className="text-[12px] text-muted">
          <tr className="border-b border-line">
            <th scope="col" className="w-8" />
            <th scope="col" className="w-24 px-2 py-2 font-medium">
              Risk
            </th>
            <th scope="col" className="px-2 py-2 font-medium">
              Filename
            </th>
            <th scope="col" className="px-2 py-2 font-medium">
              Type
            </th>
            <th scope="col" className="w-24 px-2 py-2 font-medium">
              Size
            </th>
            <th scope="col" className="w-44 px-2 py-2 font-medium">
              SHA-256
            </th>
            <th scope="col" className="px-2 py-2 font-medium">
              Indicators
            </th>
          </tr>
        </thead>
        <tbody>
          {attachments.map((a) => (
            <Fragment key={a.id}>
              <tr
                className="cursor-pointer border-b border-line hover:bg-raised"
                onClick={() => setOpen(open === a.id ? null : a.id)}
              >
                <td className="pl-3">
                  <ChevronRight
                    size={14}
                    className={cx('text-muted transition-transform', open === a.id && 'rotate-90')}
                  />
                </td>
                <td className="px-2 py-2">
                  {a.risk === 'none' ? (
                    <LevelDot level="none" label="None" />
                  ) : (
                    <SeverityBadge severity={a.risk as Severity} />
                  )}
                </td>
                <td className="px-2 py-2 font-mono text-[12.5px] break-all">{a.filename}</td>
                <td className="px-2 py-2 text-[12.5px]">
                  {a.declaredType}
                  {a.detectedType && a.detectedType !== a.declaredType && (
                    <span className="block text-high">content: {a.detectedType}</span>
                  )}
                </td>
                <td className="px-2 py-2 tabular-nums">{formatBytes(a.size)}</td>
                <td className="px-2 py-2 font-mono text-[12px]" title={a.sha256}>
                  {a.sha256.slice(0, 16)}…
                </td>
                <td className="px-2 py-2 text-[12.5px]">
                  {a.indicators.length ? (
                    a.indicators.map((i) => i.label).join('; ')
                  ) : (
                    <span className="text-faint">-</span>
                  )}
                </td>
              </tr>
              {open === a.id && (
                <tr className="border-b border-line bg-sunken">
                  <td />
                  <td colSpan={6} className="space-y-1 px-2 py-3 text-[12.5px]">
                    <Hash label="SHA-256" value={a.sha256} />
                    <Hash label="MD5" value={a.md5} />
                    {a.archiveEntries && (
                      <div className="pt-2">
                        <p className="text-muted">
                          Archive contents ({a.archiveEntries.length}, listed without extraction)
                        </p>
                        <ul className="mt-1 font-mono text-[12px]">
                          {a.archiveEntries.slice(0, 30).map((e) => (
                            <li key={e}>{e}</li>
                          ))}
                        </ul>
                      </div>
                    )}
                    <p className="pt-2 text-muted">
                      Search these hashes in your sandbox or threat-intelligence platform.
                      MailSherlock never opens or executes attachments.
                    </p>
                  </td>
                </tr>
              )}
            </Fragment>
          ))}
        </tbody>
      </table>
    </div>
  );
}
