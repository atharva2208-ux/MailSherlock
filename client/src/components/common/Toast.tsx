import { AlertTriangle, CheckCircle2, X, XCircle } from 'lucide-react';
import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react';

export type ToastTone = 'success' | 'warning' | 'error';
export interface ToastItem {
  id: number;
  tone: ToastTone;
  title: string;
  message?: string;
  at: number;
}

interface ToastApi {
  notify: (tone: ToastTone, title: string, message?: string) => void;
  history: ToastItem[];
  clearHistory: () => void;
}

const ToastContext = createContext<ToastApi | null>(null);
const ICON = { success: CheckCircle2, warning: AlertTriangle, error: XCircle };
const COLOR = { success: 'var(--safe)', warning: 'var(--medium)', error: 'var(--critical)' };

export function ToastProvider({ children }: { children: ReactNode }) {
  const [visible, setVisible] = useState<ToastItem[]>([]);
  const [history, setHistory] = useState<ToastItem[]>([]);
  const nextId = useRef(1);

  const dismiss = useCallback(
    (id: number) => setVisible((list) => list.filter((t) => t.id !== id)),
    [],
  );
  const notify = useCallback(
    (tone: ToastTone, title: string, message?: string) => {
      const item = { id: nextId.current++, tone, title, message, at: Date.now() };
      // Identical consecutive toasts are collapsed rather than stacked.
      setVisible((list) => [...list.filter((t) => t.title !== title).slice(-2), item]);
      setHistory((list) => [item, ...list].slice(0, 30));
      setTimeout(() => dismiss(item.id), tone === 'error' ? 8000 : 4500);
    },
    [dismiss],
  );
  const api = useMemo(
    () => ({ notify, history, clearHistory: () => setHistory([]) }),
    [notify, history],
  );

  return (
    <ToastContext.Provider value={api}>
      {children}
      <div
        aria-live="polite"
        className="no-print pointer-events-none fixed right-4 bottom-4 z-50 flex w-[min(380px,calc(100vw-2rem))] flex-col gap-2"
      >
        {visible.map((toast) => {
          const Icon = ICON[toast.tone];
          return (
            <div
              key={toast.id}
              role={toast.tone === 'error' ? 'alert' : 'status'}
              className="pointer-events-auto flex gap-3 rounded-lg border border-line-strong bg-surface p-3 shadow-[var(--shadow)]"
            >
              <Icon size={17} className="mt-0.5 shrink-0" style={{ color: COLOR[toast.tone] }} />
              <div className="min-w-0 flex-1">
                <p className="text-[13.5px] font-medium">{toast.title}</p>
                {toast.message && (
                  <p className="mt-0.5 text-[12.5px] text-muted">{toast.message}</p>
                )}
              </div>
              <button
                type="button"
                onClick={() => dismiss(toast.id)}
                aria-label="Dismiss notification"
                className="h-6 w-6 shrink-0 rounded text-faint hover:text-text"
              >
                <X size={14} className="mx-auto" />
              </button>
            </div>
          );
        })}
      </div>
    </ToastContext.Provider>
  );
}

// eslint-disable-next-line react-refresh/only-export-components
export function useToast(): ToastApi {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error('useToast must be used inside ToastProvider');
  return ctx;
}
