export function Logo({ compact = false }: { compact?: boolean }) {
  return (
    <span className="flex items-center gap-2.5" aria-label="MailSherlock">
      <svg viewBox="0 0 32 32" width="26" height="26" aria-hidden>
        <rect
          x="4"
          y="7"
          width="20"
          height="15"
          rx="2.5"
          fill="none"
          stroke="var(--text)"
          strokeWidth="2"
        />
        <path
          d="M5 9.5 14 16l9-6.5"
          fill="none"
          stroke="var(--accent)"
          strokeWidth="2.2"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
        <circle
          cx="22"
          cy="21"
          r="4.6"
          fill="var(--surface)"
          stroke="var(--accent)"
          strokeWidth="2.2"
        />
        <path
          d="m25.3 24.3 3.2 3.2"
          stroke="var(--accent)"
          strokeWidth="2.4"
          strokeLinecap="round"
        />
      </svg>
      {!compact && (
        <span className="text-[15px] font-semibold tracking-[-0.01em]">MailSherlock</span>
      )}
    </span>
  );
}
