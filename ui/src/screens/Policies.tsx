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
    <div className="flex flex-col h-full p-6 gap-4">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold">Policies</h1>
        <div className="flex items-center gap-3">
          {createdId && <span className="text-xs text-green-600 dark:text-green-400">Created: {createdId}</span>}
          {create.isError && <span className="text-xs text-red-500 break-all max-w-md">{String(create.error)}</span>}
          <Button
            disabled={!v.ok || create.isPending}
            onClick={() => create.mutate({ engine: "opa", source: src }, { onSuccess: (r) => setCreatedId(r.id) })}
          >
            {create.isPending ? "Saving…" : "Save policy"}
          </Button>
        </div>
      </div>
      <div className="flex-1 min-h-0">
        <RegoEditor value={src} onChange={setSrc} />
      </div>
    </div>
  );
}
