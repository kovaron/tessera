import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/invoke";

export function useStatus() {
  return useQuery({
    queryKey: ["status"],
    queryFn: () => api.getStatus(),
    refetchInterval: 2000,
    refetchIntervalInBackground: true,
    retry: false,
    gcTime: 0,
  });
}

export function useUnlock() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (passphrase: string) => api.unlock(passphrase),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["status"] }),
  });
}

export function useLock() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => api.lock(),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["status"] }),
  });
}
