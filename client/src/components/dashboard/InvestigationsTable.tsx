import { ArrowDown, ArrowUp } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { FEEDBACK_LABEL } from '../../constants/severity';
import type { AnalysisSummary } from '../../types';
import { cx, formatDateTime, pct } from '../../utils/format';
import { ClassificationTag, SeverityBadge } from '../common/Badge';

export type SortField =
  'created_at' | 'risk_score' | 'finding_count' | 'sender_address' | 'subject' | 'classification';

interface Props {
  items: AnalysisSummary[];
  sort?: { field: SortField; order: 'asc' | 'desc' };
  onSort?: (field: SortField) => void;
  compact?: boolean;
}

function SortHeader({
  label,
  field,
  sort,
  onSort,
  className,
}: {
  label: string;
  field: SortField;
  sort?: Props['sort'];
  onSort?: Props['onSort'];
  className?: string;
}) {
  const active = sort?.field === field;
  return (
    <th
      scope="col"
      className={cx('px-3 py-2 font-medium', className)}
      aria-sort={active ? (sort!.order === 'asc' ? 'ascending' : 'descending') : undefined}
    >
      {onSort ? (
        <button
          type="button"
          onClick={() => onSort(field)}
          className={cx('inline-flex items-center gap-1 hover:text-text', active && 'text-text')}
        >
          {label}
          {active && (sort!.order === 'asc' ? <ArrowUp size={12} /> : <ArrowDown size={12} />)}
        </button>
      ) : (
        label
      )}
    </th>
  );
}

/** Investigation history table. Rows are links to the full analysis. */
export function InvestigationsTable({ items, sort, onSort, compact }: Props) {
  const navigate = useNavigate();
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[880px] text-left text-[13px]">
        <thead className="text-[12px] text-muted">
          <tr className="border-b border-line">
            <SortHeader
              label="Risk"
              field="risk_score"
              sort={sort}
              onSort={onSort}
              className="w-28"
            />
            <SortHeader
              label="Classification"
              field="classification"
              sort={sort}
              onSort={onSort}
              className="w-32"
            />
            <SortHeader
              label="Sender"
              field="sender_address"
              sort={sort}
              onSort={onSort}
              className="w-60"
            />
            <SortHeader label="Subject" field="subject" sort={sort} onSort={onSort} />
            <SortHeader
              label="Analysed"
              field="created_at"
              sort={sort}
              onSort={onSort}
              className="w-40"
            />
            <SortHeader
              label="Findings"
              field="finding_count"
              sort={sort}
              onSort={onSort}
              className="w-24"
            />
            {!compact && (
              <th scope="col" className="w-28 px-3 py-2 font-medium">
                Model
              </th>
            )}
            {!compact && (
              <th scope="col" className="w-32 px-3 py-2 font-medium">
                Analyst
              </th>
            )}
          </tr>
        </thead>
        <tbody>
          {items.map((item) => (
            <tr
              key={item.id}
              tabIndex={0}
              onClick={() => navigate(`/investigations/${item.id}`)}
              onKeyDown={(e) => e.key === 'Enter' && navigate(`/investigations/${item.id}`)}
              className="cursor-pointer border-b border-line last:border-b-0 hover:bg-raised focus-visible:bg-raised"
              aria-label={`Open investigation: ${item.subject || 'no subject'}`}
            >
              <td className="px-3 py-2">
                <span className="flex items-center gap-2">
                  <SeverityBadge severity={item.riskLevel} />
                  <span className="tabular-nums text-muted">{item.riskScore}</span>
                </span>
              </td>
              <td className="px-3 py-2">
                <ClassificationTag value={item.classification} />
              </td>
              <td className="max-w-0 truncate px-3 py-2" title={item.sender}>
                {item.sender || <span className="text-faint">unknown</span>}
              </td>
              <td className="max-w-0 truncate px-3 py-2" title={item.subject}>
                {item.subject || <span className="text-faint">(no subject)</span>}
              </td>
              <td className="px-3 py-2 whitespace-nowrap text-muted">
                {formatDateTime(item.createdAt)}
              </td>
              <td className="px-3 py-2 tabular-nums">
                {item.findingCount}
                {item.criticalCount > 0 && (
                  <span className="ml-1.5 text-[12px] text-critical">
                    {item.criticalCount} crit
                  </span>
                )}
              </td>
              {!compact && (
                <td className="px-3 py-2 text-[12.5px] text-muted">
                  {item.modelVersion
                    ? `v${item.modelVersion} · ${pct(item.mlProbability, 0)}`
                    : 'rules only'}
                </td>
              )}
              {!compact && (
                <td className="px-3 py-2 text-[12.5px] text-muted">
                  {item.feedback ? FEEDBACK_LABEL[item.feedback] : '-'}
                </td>
              )}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
