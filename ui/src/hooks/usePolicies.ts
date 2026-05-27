import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/invoke";
import type { CreatePolicyReq, Policy } from "@/types/bindings";

export function useListPolicies() {
  return useQuery<Policy[]>({
    queryKey: ["policies"],
    queryFn: () => api.listPolicies(),
  });
}

export function useGetPolicy(id: string | null) {
  return useQuery<Policy>({
    queryKey: ["policies", id],
    queryFn: () => api.getPolicy(id!),
    enabled: !!id,
  });
}

export function useCreatePolicy() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (req: CreatePolicyReq) => api.createPolicy(req),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["policies"] });
      qc.invalidateQueries({ queryKey: ["tokens"] });
    },
  });
}

export function useUpdatePolicy() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, req }: { id: string; req: CreatePolicyReq }) => api.updatePolicy(id, req),
    onSuccess: (_, { id }) => {
      qc.invalidateQueries({ queryKey: ["policies"] });
      qc.invalidateQueries({ queryKey: ["policies", id] });
    },
  });
}

export function useDeletePolicy() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.deletePolicy(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["policies"] }),
  });
}
