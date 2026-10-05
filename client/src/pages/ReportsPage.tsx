import { keepPreviousData, useQuery } from '@tanstack/react-query';
import { FileText } from 'lucide-react';
import { useState } from 'react';
import { Link } from 'react-router-dom';
import { ClassificationTag, SeverityBadge } from '../components/common/Badge';
import { Button, LinkButton } from '../components/common/Button';
import { EmptyState, Skeleton } from '../components/common/States';
import { useToast } from '../components/common/Toast';
import { api } from '../services/api';
import { formatDateTime } from '../utils/format';
import { PageHeader } from './PageHeader';

export default function ReportsPage() {
  const [page, setPage] = useState(1);
  const { notify } = useToast();
  const query = useQuery({
    queryKey: ['analyses', 'reports', page],
    queryFn: () => api.listAnalyses({ page, pageSize: 20 }),
    placeholderData: keepPreviousData,
  });
  return (
    <div>
      <PageHeader
        title="Reports"
        description="Generate a printable investigation report or export the full evidence as JSON for a ticket, SIEM or case file."
      />
      <div className="rounded-lg border border-line bg-surface">
        {query.isLoading ? (
          <Skeleton className="m-4 h-48" />
        ) : !query.data?.items.length ? (
          <EmptyState
            icon={<FileText size={24} />}
            title="No investigations to report on"
            action={
              <Link to="/analyze" className="text-accent hover:underline">
                Analyze an email
              </Link>
            }
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[760px] text-left text-[13px]">
              <thead className="text-[12px] text-muted">
                <tr className="border-b border-line">
                  <th scope="col" className="px-4 py-2 font-medium">
                    Investigation
                  </th>
                  <th scope="col" className="w-28 px-3 py-2 font-medium">
                    Risk
                  </th>
                  <th scope="col" className="w-32 px-3 py-2 font-medium">
                    Classification
                  </th>
                  <th scope="col" className="w-44 px-3 py-2 font-medium">
                    Analysed
                  </th>
                  <th scope="col" className="w-64 px-3 py-2 font-medium">
                    <span className="sr-only">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {query.data.items.map((item) => (
                  <tr key={item.id} className="border-b border-line last:border-b-0">
                    <td className="max-w-0 px-4 py-2">
                      <Link
                        to={`/investigations/${item.id}`}
                        className="block truncate font-medium hover:text-accent"
                      >
                        {item.subject || '(no subject)'}
                      </Link>
                      <span className="block truncate text-[12px] text-muted">{item.sender}</span>
                    </td>
                    <td className="px-3 py-2">
                      <SeverityBadge severity={item.riskLevel} />{' '}
                      <span className="tabular-nums text-muted">{item.riskScore}</span>
                    </td>
                    <td className="px-3 py-2">
                      <ClassificationTag value={item.classification} />
                    </td>
                    <td className="px-3 py-2 text-muted">{formatDateTime(item.createdAt)}</td>
                    <td className="px-3 py-2">
                      <div className="flex justify-end gap-2">
                        <Link
                          to={`/reports/${item.id}/print`}
                          className="inline-flex h-7 items-center rounded-md border border-line-strong bg-raised px-2.5 text-[12.5px] hover:border-faint"
                        >
                          Printable report
                        </Link>
                        <LinkButton
                          size="sm"
                          variant="ghost"
                          href={api.reportUrl(item.id)}
                          download
                          onClick={() => notify('success', 'Report exported', item.subject)}
                        >
                          JSON
                        </LinkButton>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            <div className="flex justify-end gap-2 border-t border-line px-3 py-2">
              <Button
                size="sm"
                variant="ghost"
                disabled={page <= 1}
                onClick={() => setPage((p) => p - 1)}
              >
                Previous
              </Button>
              <Button
                size="sm"
                variant="ghost"
                disabled={page * 20 >= query.data.total}
                onClick={() => setPage((p) => p + 1)}
              >
                Next
              </Button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
