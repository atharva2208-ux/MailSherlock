import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './App';
import './styles/index.css';

try {
  const stored = localStorage.getItem('mailsherlock.theme');
  if (stored === 'light' || stored === 'dark') document.documentElement.dataset.theme = stored;
} catch {
  // keep the default theme
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
