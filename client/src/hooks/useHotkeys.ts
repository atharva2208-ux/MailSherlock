import { useEffect, useRef } from 'react';

type Handler = (event: KeyboardEvent) => void;

/** Global shortcuts such as "mod+k". `mod` is Ctrl, or Cmd on macOS. */
export function useHotkeys(bindings: Record<string, Handler>) {
  const ref = useRef(bindings);
  useEffect(() => {
    ref.current = bindings;
  });
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      const mod = event.ctrlKey || event.metaKey;
      for (const [combo, handler] of Object.entries(ref.current)) {
        const [first, second] = combo.split('+');
        const wantsMod = first === 'mod';
        const key = (wantsMod ? second : first)?.toLowerCase();
        if (wantsMod === mod && event.key.toLowerCase() === key) {
          event.preventDefault();
          handler(event);
          return;
        }
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);
}
