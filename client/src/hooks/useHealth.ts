import { useQuery } from '@tanstack/react-query';
import { api } from '../services/api';

/** Real component health, polled every 30 seconds. */
export function useHealth() {
  return useQuery({
    queryKey: ['health'],
    queryFn: api.health,
    refetchInterval: 30_000,
    retry: false,
  });
}
