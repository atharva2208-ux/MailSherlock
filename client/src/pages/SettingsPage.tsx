import { Moon, Sun } from 'lucide-react';
import { Button } from '../components/common/Button';
import { Panel } from '../components/common/Panel';
import { Kbd, Skeleton } from '../components/common/States';
import { StatusLine } from '../components/layout/SystemStatus';
import { useHealth } from '../hooks/useHealth';
import { useTheme } from '../hooks/useTheme';
import { PageHeader } from './PageHeader';

const SHORTCUTS: [string, string][] = [
  ['Ctrl K', 'Open the command palette'],
  ['Ctrl U', 'Upload an email'],
  ['Ctrl /', 'Focus search'],
  ['Esc', 'Close dialogs and menus'],
  ['← →', 'Move between investigation tabs'],
];

export default function SettingsPage() {
  const { theme, setTheme } = useTheme();
  const health = useHealth();
  return (
    <div className="space-y-4">
      <PageHeader
        title="Settings"
        description="Appearance, system health and integrations. Server configuration lives in the .env file; secrets are never sent to the browser."
      />
      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Appearance">
          <div className="flex gap-2">
            <Button
              variant={theme === 'dark' ? 'secondary' : 'ghost'}
              aria-pressed={theme === 'dark'}
              icon={<Moon size={15} />}
              onClick={() => setTheme('dark')}
            >
              Dark
            </Button>
            <Button
              variant={theme === 'light' ? 'secondary' : 'ghost'}
              aria-pressed={theme === 'light'}
              icon={<Sun size={15} />}
              onClick={() => setTheme('light')}
            >
              Light
            </Button>
          </div>
        </Panel>
        <Panel title="Keyboard shortcuts">
          <ul className="space-y-1.5 text-[13px]">
            {SHORTCUTS.map(([keys, label]) => (
              <li key={keys} className="flex items-center justify-between">
                <span>{label}</span>
                <Kbd>{keys}</Kbd>
              </li>
            ))}
          </ul>
        </Panel>
        <Panel
          title="System health"
          description={
            health.data
              ? `Engine v${health.data.version} · up ${Math.round(health.data.uptimeSeconds / 60)} min`
              : undefined
          }
        >
          {health.isLoading && <Skeleton className="h-40" />}
          {health.isError && (
            <p className="text-[13px] text-critical">The API is not responding.</p>
          )}
          {health.data && (
            <ul>
              <StatusLine name="API / analysis engine" health={health.data.components.api} />
              <StatusLine name="Database" health={health.data.components.database} />
              <StatusLine name="ML engine" health={health.data.components.ml} />
              <StatusLine name="Storage" health={health.data.components.storage} />
            </ul>
          )}
        </Panel>
        <Panel
          title="Threat intelligence providers"
          description="Optional. Configure keys in .env and restart the server."
        >
          {health.data && (
            <ul>
              {Object.entries(health.data.components.threatIntel).map(([name, h]) => (
                <StatusLine key={name} name={name} health={h} />
              ))}
            </ul>
          )}
          <p className="mt-3 text-[12.5px] text-muted">
            Variables: <code className="font-mono">VIRUSTOTAL_API_KEY</code>,{' '}
            <code className="font-mono">ABUSEIPDB_API_KEY</code>,{' '}
            <code className="font-mono">URLSCAN_API_KEY</code>,{' '}
            <code className="font-mono">GOOGLE_SAFE_BROWSING_API_KEY</code>,{' '}
            <code className="font-mono">RDAP_ENABLED</code>,{' '}
            <code className="font-mono">ENRICH_ON_ANALYZE</code>.
          </p>
        </Panel>
      </div>
    </div>
  );
}
