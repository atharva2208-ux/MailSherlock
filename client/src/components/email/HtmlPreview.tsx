/**
 * Displays server-sanitised HTML in a fully sandboxed frame: no scripts, no
 * same-origin access, no forms, and a CSP that blocks every network request.
 * Two independent layers, so a sanitiser bypass still cannot execute.
 */
export function HtmlPreview({ html }: { html: string }) {
  const doc = `<!doctype html><html><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<style>body{font:14px/1.55 system-ui,sans-serif;color:#1d2733;background:#fff;margin:16px;word-break:break-word}
a{color:#3949ab;text-decoration:underline dotted;cursor:help}table{max-width:100%}</style></head><body>${html}</body></html>`;
  return (
    <iframe
      title="Sanitised HTML rendering of the email"
      sandbox=""
      srcDoc={doc}
      referrerPolicy="no-referrer"
      className="h-[520px] w-full rounded-md border border-line bg-white"
    />
  );
}
