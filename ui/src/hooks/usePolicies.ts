import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/invoke";
import type { CreatePolicyReq } from "@/types/bindings";

export function useCreatePolicy() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (req: CreatePolicyReq) => api.createPolicy(req),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["tokens"] }),
  });
}
