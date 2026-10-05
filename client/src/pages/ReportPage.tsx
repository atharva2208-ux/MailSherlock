import { useQuery } from '@tanstack/react-query';
import { ArrowLeft, Printer } from 'lucide-react';
import { Link, useParams } from 'react-router-dom';
import { Button } from '../components/common/Button';
import { ErrorState, Skeleton } from '../components/common/States';
import { PrintableReport } from '../components/reports/PrintableReport';
import { api } from '../services/api';

export default function ReportPage() {
  const { id = '' } = useParams();
  const { data, error, isLoading } = useQuery({
    queryKey: ['analysis', id],
    queryFn: () => api.getAnalysis(id),
  });
  return (
    <div data-theme="light" className="min-h-screen bg-bg py-6 text-text print:bg-white print:py-0">
      <div className="no-print mx-auto mb-4 flex max-w-[800px] items-center justify-between px-4">
        <Link
          to={`/investigations/${id}`}
          className="inline-flex items-center gap-1.5 text-[13px] text-muted hover:text-text"
        >
          <ArrowLeft size={14} /> Back to investigation
        </Link>
        <Button
          variant="primary"
          icon={<Printer size={15} />}
          onClick={() => window.print()}
          disabled={!data}
        >
          Print or save as PDF
        </Button>
      </div>
      {isLoading && <Skeleton className="mx-auto h-[600px] max-w-[800px]" />}
      {error && (
        <div className="mx-auto max-w-[800px] px-4">
          <ErrorState title="Report unavailable" message={(error as Error).message} />
        </div>
      )}
      {data && (
        <div className="rounded-lg border border-line shadow-[var(--shadow)] print:border-0 print:shadow-none sm:mx-auto sm:max-w-[800px]">
          <PrintableReport analysis={data} />
        </div>
      )}
    </div>
  );
}
