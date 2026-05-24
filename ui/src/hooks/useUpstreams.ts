import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/invoke";
import type { UpsertUpstreamReq } from "@/types/bindings";

export function useUpstreams() {
  return useQuery({ queryKey: ["upstreams"], queryFn: () => api.listUpstreams() });
}

export function useUpsertUpstream() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (req: UpsertUpstreamReq) => api.upsertUpstream(req),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["upstreams"] }),
  });
}

export function useDeleteUpstream() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.deleteUpstream(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["upstreams"] }),
  });
}
