import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/invoke";
import type { MintTokenReq, AttenuateReq } from "@/types/bindings";

export function useTokens() {
  return useQuery({ queryKey: ["tokens"], queryFn: () => api.listTokens() });
}

export function useMintToken() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (req: MintTokenReq) => api.mintToken(req),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["tokens"] }),
  });
}

export function useRevokeToken() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.revokeToken(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["tokens"] }),
  });
}

export function useAttenuateToken() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (req: AttenuateReq) => api.attenuateToken(req),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["tokens"] }),
  });
}
