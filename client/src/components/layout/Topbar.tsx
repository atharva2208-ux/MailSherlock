import { Command, Moon, Search, Settings, Sun } from 'lucide-react';
import { forwardRef, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Kbd } from '../common/States';
import { Notifications } from './Notifications';
import { SystemStatus } from './SystemStatus';

interface TopbarProps {
  onOpenPalette: () => void;
  theme: 'dark' | 'light';
  onToggleTheme: () => void;
}

export const Topbar = forwardRef<HTMLInputElement, TopbarProps>(function Topbar(
  { onOpenPalette, theme, onToggleTheme },
  searchRef,
) {
  const navigate = useNavigate();
  const [query, setQuery] = useState('');
  return (
    <header className="no-print sticky top-0 z-30 flex h-[52px] items-center gap-3 border-b border-line bg-[color-mix(in_srgb,var(--bg)_88%,transparent)] px-4 backdrop-blur">
      <form
        role="search"
        className="relative w-full max-w-md"
        onSubmit={(e) => {
          e.preventDefault();
          navigate(
            `/investigations${query.trim() ? `?search=${encodeURIComponent(query.trim())}` : ''}`,
          );
        }}
      >
        <Search
          size={15}
          className="pointer-events-none absolute top-1/2 left-3 -translate-y-1/2 text-faint"
        />
        <input
          ref={searchRef}
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search sender, subject, ID or SHA-256"
          aria-label="Search investigations"
          className="h-8 w-full rounded-md border border-line bg-surface pr-16 pl-9 text-[13px] text-text placeholder:text-faint focus:border-accent focus:outline-none"
        />
        <span className="pointer-events-none absolute top-1/2 right-2 hidden -translate-y-1/2 lg:block">
          <Kbd>Ctrl /</Kbd>
        </span>
      </form>
      <div className="ml-auto flex items-center gap-1">
        <button
          type="button"
          onClick={onOpenPalette}
          className="hidden h-8 items-center gap-2 rounded-md px-2.5 text-[12.5px] text-muted hover:bg-raised hover:text-text lg:flex"
          aria-label="Open command palette"
        >
          <Command size={14} />
          <Kbd>Ctrl K</Kbd>
        </button>
        <SystemStatus />
        <Notifications />
        <button
          type="button"
          onClick={onToggleTheme}
          className="flex h-8 w-8 items-center justify-center rounded-md text-muted hover:bg-raised hover:text-text"
          aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`}
        >
          {theme === 'dark' ? <Sun size={16} /> : <Moon size={16} />}
        </button>
        <Link
          to="/settings"
          className="flex h-8 w-8 items-center justify-center rounded-md text-muted hover:bg-raised hover:text-text"
          aria-label="Settings"
        >
          <Settings size={16} />
        </Link>
      </div>
    </header>
  );
});
