import { Link } from 'react-router-dom';
import { EmptyState } from '../components/common/States';

export function NotFoundPage() {
  return (
    <EmptyState
      title="Page not found"
      action={
        <Link to="/" className="text-accent hover:underline">
          Go to the dashboard
        </Link>
      }
    >
      The address you followed does not match any MailSherlock page.
    </EmptyState>
  );
}
