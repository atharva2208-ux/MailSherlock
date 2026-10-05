import { PanelLeftClose, PanelLeftOpen } from 'lucide-react';
import { NavLink } from 'react-router-dom';
import { NAV_ITEMS } from '../../constants/navigation';
import { cx } from '../../utils/format';
import { Logo } from './Logo';

export function Sidebar({ collapsed, onToggle }: { collapsed: boolean; onToggle: () => void }) {
  return (
    <aside
      className={cx(
        'no-print sticky top-0 flex h-screen shrink-0 flex-col border-r border-line bg-surface transition-[width] duration-200',
        collapsed ? 'w-[60px]' : 'w-[224px]',
      )}
    >
      <div
        className={cx(
          'flex h-[52px] items-center border-b border-line',
          collapsed ? 'justify-center' : 'px-4',
        )}
      >
        <Logo compact={collapsed} />
      </div>
      <nav aria-label="Primary" className="flex-1 overflow-y-auto px-2 py-3">
        <ul className="space-y-0.5">
          {NAV_ITEMS.map(({ to, label, icon: Icon, ...rest }) => (
            <li key={to}>
              <NavLink
                to={to}
                end={'end' in rest}
                title={collapsed ? label : undefined}
                className={({ isActive }) =>
                  cx(
                    'relative flex h-9 items-center gap-3 rounded-md text-[13.5px] transition-colors',
                    collapsed ? 'justify-center' : 'px-3',
                    isActive
                      ? 'bg-accent-soft font-medium text-text'
                      : 'text-muted hover:bg-raised hover:text-text',
                  )
                }
              >
                {({ isActive }) => (
                  <>
                    {isActive && (
                      <span
                        aria-hidden
                        className="absolute top-2 bottom-2 left-0 w-[3px] rounded-r bg-accent"
                      />
                    )}
                    <Icon size={17} className={isActive ? 'text-accent' : undefined} />
                    {!collapsed && <span>{label}</span>}
                  </>
                )}
              </NavLink>
            </li>
          ))}
        </ul>
      </nav>
      <button
        type="button"
        onClick={onToggle}
        aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        aria-expanded={!collapsed}
        className={cx(
          'm-2 flex h-9 items-center gap-3 rounded-md text-[13px] text-faint hover:bg-raised hover:text-text',
          collapsed ? 'justify-center' : 'px-3',
        )}
      >
        {collapsed ? <PanelLeftOpen size={17} /> : <PanelLeftClose size={17} />}
        {!collapsed && 'Collapse'}
      </button>
    </aside>
  );
}
