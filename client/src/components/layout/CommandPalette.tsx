import {
  CornerDownLeft,
  FileText,
  FolderSearch,
  Globe2,
  LayoutDashboard,
  ScanSearch,
  Search,
  Settings,
  Upload,
  BrainCircuit,
  SunMoon,
} from 'lucide-react';
import { useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { cx } from '../../utils/format';

interface Action {
  id: string;
  label: string;
  hint?: string;
  icon: typeof Search;
  run: () => void;
}

/** Mounted only while open, so each opening starts with an empty query. */
export function CommandPalette({
  onClose,
  onUpload,
  onToggleTheme,
}: {
  onClose: () => void;
  onUpload: () => void;
  onToggleTheme: () => void;
}) {
  const navigate = useNavigate();
  const [query, setQuery] = useState('');
  const [index, setIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  const actions = useMemo<Action[]>(() => {
    const go = (path: string) => () => navigate(path);
    const list: Action[] = [
      {
        id: 'analyze',
        label: 'Analyze email',
        hint: 'Paste or upload',
        icon: ScanSearch,
        run: go('/analyze'),
      },
      { id: 'upload', label: 'Upload .eml file', hint: 'Ctrl U', icon: Upload, run: onUpload },
      { id: 'dashboard', label: 'Open dashboard', icon: LayoutDashboard, run: go('/') },
      {
        id: 'investigations',
        label: 'Search investigations',
        icon: FolderSearch,
        run: go('/investigations'),
      },
      { id: 'intel', label: 'Open threat intelligence', icon: Globe2, run: go('/intel') },
      { id: 'reports', label: 'Generate report', icon: FileText, run: go('/reports') },
      { id: 'model', label: 'View model performance', icon: BrainCircuit, run: go('/model') },
      { id: 'settings', label: 'Open settings', icon: Settings, run: go('/settings') },
      { id: 'theme', label: 'Toggle light/dark theme', icon: SunMoon, run: onToggleTheme },
    ];
    const q = query.trim().toLowerCase();
    const filtered = q ? list.filter((a) => a.label.toLowerCase().includes(q)) : list;
    if (q) {
      filtered.push({
        id: 'search',
        label: `Search investigations for "${query.trim()}"`,
        icon: Search,
        run: () => navigate(`/investigations?search=${encodeURIComponent(query.trim())}`),
      });
      if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(q))
        filtered.push({
          id: 'lookup',
          label: `Look up ${q} in threat intelligence`,
          icon: Globe2,
          run: () => navigate(`/intel?q=${encodeURIComponent(q)}`),
        });
    }
    return filtered;
  }, [query, navigate, onUpload, onToggleTheme]);

  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  const select = (action: Action | undefined) => {
    if (!action) return;
    onClose();
    action.run();
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center bg-[rgb(0_0_0/0.5)] px-4 pt-[14vh]"
      onMouseDown={onClose}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-label="Command palette"
        className="w-full max-w-lg overflow-hidden rounded-xl border border-line-strong bg-surface shadow-[var(--shadow)]"
        onMouseDown={(e) => e.stopPropagation()}
      >
        <div className="flex items-center gap-2 border-b border-line px-4">
          <Search size={16} className="text-faint" />
          <input
            ref={inputRef}
            value={query}
            role="combobox"
            aria-expanded="true"
            aria-controls="palette-list"
            aria-activedescendant={actions[index] ? `palette-${actions[index].id}` : undefined}
            onChange={(e) => {
              setQuery(e.target.value);
              setIndex(0);
            }}
            onKeyDown={(e) => {
              if (e.key === 'ArrowDown') {
                e.preventDefault();
                setIndex((i) => Math.min(i + 1, actions.length - 1));
              } else if (e.key === 'ArrowUp') {
                e.preventDefault();
                setIndex((i) => Math.max(i - 1, 0));
              } else if (e.key === 'Enter') {
                e.preventDefault();
                select(actions[index]);
              } else if (e.key === 'Escape') onClose();
            }}
            placeholder="Type a command, a search term or a domain"
            className="h-12 flex-1 bg-transparent text-[14px] text-text placeholder:text-faint focus:outline-none"
          />
        </div>
        <ul id="palette-list" role="listbox" className="max-h-80 overflow-y-auto p-1.5">
          {actions.map((action, i) => (
            <li
              key={action.id}
              id={`palette-${action.id}`}
              role="option"
              aria-selected={i === index}
              onMouseEnter={() => setIndex(i)}
              onClick={() => select(action)}
              className={cx(
                'flex h-10 cursor-pointer items-center gap-3 rounded-md px-3 text-[13.5px]',
                i === index ? 'bg-accent-soft text-text' : 'text-muted',
              )}
            >
              <action.icon size={16} className={i === index ? 'text-accent' : undefined} />
              <span className="flex-1 truncate">{action.label}</span>
              {action.hint && <span className="text-[12px] text-faint">{action.hint}</span>}
              {i === index && <CornerDownLeft size={14} className="text-faint" />}
            </li>
          ))}
          {!actions.length && (
            <li className="px-3 py-6 text-center text-[13px] text-muted">No matching commands</li>
          )}
        </ul>
      </div>
    </div>
  );
}
