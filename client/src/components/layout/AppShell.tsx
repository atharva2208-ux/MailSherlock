import { useCallback, useRef, useState } from 'react';
import { Outlet, useNavigate } from 'react-router-dom';
import { useHotkeys } from '../../hooks/useHotkeys';
import { useTheme } from '../../hooks/useTheme';
import { CommandPalette } from './CommandPalette';
import { Sidebar } from './Sidebar';
import { Topbar } from './Topbar';

const COLLAPSE_KEY = 'mailsherlock.sidebar';

export function AppShell() {
  const navigate = useNavigate();
  const { theme, toggle } = useTheme();
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [collapsed, setCollapsed] = useState(() => {
    try {
      const stored = localStorage.getItem(COLLAPSE_KEY);
      if (stored !== null) return stored === '1';
    } catch {
      // fall through to the width-based default
    }
    return window.innerWidth < 1100;
  });
  const searchRef = useRef<HTMLInputElement>(null);

  const toggleSidebar = () =>
    setCollapsed((c) => {
      try {
        localStorage.setItem(COLLAPSE_KEY, c ? '0' : '1');
      } catch {
        // non-critical preference
      }
      return !c;
    });
  const openUpload = useCallback(
    () => navigate('/analyze', { state: { openFilePicker: Date.now() } }),
    [navigate],
  );

  useHotkeys({
    'mod+k': () => setPaletteOpen((o) => !o),
    'mod+u': openUpload,
    'mod+/': () => searchRef.current?.focus(),
    escape: () => setPaletteOpen(false),
  });

  return (
    <div className="flex min-h-screen">
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:fixed focus:top-2 focus:left-2 focus:z-50 focus:rounded focus:bg-accent focus:px-3 focus:py-2 focus:text-[#120d2e]"
      >
        Skip to content
      </a>
      <Sidebar collapsed={collapsed} onToggle={toggleSidebar} />
      <div className="flex min-w-0 flex-1 flex-col">
        <Topbar
          ref={searchRef}
          onOpenPalette={() => setPaletteOpen(true)}
          theme={theme}
          onToggleTheme={toggle}
        />
        <main id="main" className="mx-auto w-full max-w-[1480px] flex-1 px-4 py-5 md:px-6">
          <Outlet />
        </main>
      </div>
      {paletteOpen && (
        <CommandPalette
          onClose={() => setPaletteOpen(false)}
          onUpload={openUpload}
          onToggleTheme={toggle}
        />
      )}
    </div>
  );
}
