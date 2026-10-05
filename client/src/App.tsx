import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { lazy, Suspense } from 'react';
import { BrowserRouter, Route, Routes } from 'react-router-dom';
import { Skeleton } from './components/common/States';
import { ToastProvider } from './components/common/Toast';
import { AppShell } from './components/layout/AppShell';
import { AnalyzePage } from './pages/AnalyzePage';
import { InvestigationPage } from './pages/InvestigationPage';
import { InvestigationsPage } from './pages/InvestigationsPage';
import { NotFoundPage } from './pages/NotFoundPage';

// Chart-heavy and secondary pages are split out of the initial bundle.
const DashboardPage = lazy(() => import('./pages/DashboardPage'));
const ModelPage = lazy(() => import('./pages/ModelPage'));
const ThreatIntelPage = lazy(() => import('./pages/ThreatIntelPage'));
const ReportsPage = lazy(() => import('./pages/ReportsPage'));
const ReportPage = lazy(() => import('./pages/ReportPage'));
const SettingsPage = lazy(() => import('./pages/SettingsPage'));

function createQueryClient() {
  return new QueryClient({
    defaultOptions: { queries: { staleTime: 15_000, retry: 1, refetchOnWindowFocus: false } },
  });
}

const queryClient = createQueryClient();

function PageFallback() {
  return (
    <div className="space-y-4" aria-busy="true" aria-label="Loading page">
      <Skeleton className="h-8 w-64" />
      <Skeleton className="h-40" />
      <Skeleton className="h-72" />
    </div>
  );
}

export function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <ToastProvider>
        <BrowserRouter>
          <Suspense fallback={<PageFallback />}>
            <Routes>
              <Route path="/reports/:id/print" element={<ReportPage />} />
              <Route element={<AppShell />}>
                <Route index element={<DashboardPage />} />
                <Route path="analyze" element={<AnalyzePage />} />
                <Route path="investigations" element={<InvestigationsPage />} />
                <Route path="investigations/:id" element={<InvestigationPage />} />
                <Route path="intel" element={<ThreatIntelPage />} />
                <Route path="reports" element={<ReportsPage />} />
                <Route path="model" element={<ModelPage />} />
                <Route path="settings" element={<SettingsPage />} />
                <Route path="*" element={<NotFoundPage />} />
              </Route>
            </Routes>
          </Suspense>
        </BrowserRouter>
      </ToastProvider>
    </QueryClientProvider>
  );
}
