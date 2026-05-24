import { useState } from "react";
import { useCreatePolicy } from "@/hooks/usePolicies";
import RegoEditor from "@/components/RegoEditor";
import { Button } from "@/components/ui/button";
import { quickValidate } from "@/lib/rego-compile";

const STARTER = `package proxy.authz
default allow := false

allow if {
    input.request.method == "GET"
}
`;

export default function Policies() {
  const [src, setSrc] = useState(STARTER);
  const create = useCreatePolicy();
  const v = quickValidate(src);
  const [createdId, setCreatedId] = useState<string | null>(null);

  return (
    <div className="p-6 space-y-4">
      <h1 className="text-xl font-semibold">Policies</h1>
      <RegoEditor value={src} onChange={setSrc} />
      <div className="flex items-center gap-3">
        <Button
          disabled={!v.ok || create.isPending}
          onClick={() => create.mutate({ engine: "opa", source: src }, { onSuccess: (r) => setCreatedId(r.id) })}
        >
          Save policy
        </Button>
        {createdId && <span className="text-xs text-green-600">Created: {createdId}</span>}
        {create.isError && <span className="text-xs text-red-600">{String(create.error)}</span>}
      </div>
    </div>
  );
}
