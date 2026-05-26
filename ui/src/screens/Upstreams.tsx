import { useState } from "react";
import { useUpstreams, useUpsertUpstream, useDeleteUpstream } from "@/hooks/useUpstreams";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Sheet, SheetContent, SheetHeader, SheetTitle, SheetTrigger } from "@/components/ui/sheet";
import InjectRuleBuilder from "@/components/InjectRuleBuilder";
import type { InjectRule, UpsertUpstreamReq } from "@/types/bindings";

const emptyInject: InjectRule = { type: "bearer", secret_ref: "" };

export default function Upstreams() {
  const upstreams = useUpstreams();
  const data = upstreams.data ?? [];
  const upsert = useUpsertUpstream();
  const del = useDeleteUpstream();
  const [editing, setEditing] = useState<UpsertUpstreamReq | null>(null);

  return (
    <div className="p-6 space-y-4">
      <div className="flex justify-between">
        <h1 className="text-xl font-semibold">Upstreams</h1>
        <Sheet>
          <SheetTrigger asChild>
            <Button onClick={() => setEditing({ id: "", base_url: "", inject: emptyInject })}>Add</Button>
          </SheetTrigger>
          {editing && (
            <SheetContent>
              <SheetHeader><SheetTitle>{editing.id ? "Edit" : "New"} upstream</SheetTitle></SheetHeader>
              <div className="space-y-4 mt-4">
                <div><Label>ID</Label><Input value={editing.id} onChange={(e) => setEditing({ ...editing, id: e.target.value })} /></div>
                <div><Label>Base URL</Label><Input value={editing.base_url} onChange={(e) => setEditing({ ...editing, base_url: e.target.value })} /></div>
                <InjectRuleBuilder value={editing.inject} onChange={(inject) => setEditing({ ...editing, inject })} />
                <Button disabled={upsert.isPending} onClick={() => upsert.mutate(editing, { onSuccess: () => setEditing(null) })}>
                  {upsert.isPending ? "Saving…" : "Save"}
                </Button>
                {upsert.isError && (
                  <p className="text-xs text-red-500 break-all">save failed: {String(upsert.error)}</p>
                )}
              </div>
            </SheetContent>
          )}
        </Sheet>
      </div>
      {upstreams.isError && (
        <p className="text-xs text-red-500">list failed: {String(upstreams.error)}</p>
      )}
      <p className="text-xs text-muted-foreground">{data.length} upstream(s)</p>
      <table className="w-full text-sm">
        <thead>
          <tr className="text-left text-muted-foreground"><th>ID</th><th>Base URL</th><th>Inject</th><th></th></tr>
        </thead>
        <tbody>
          {data.map((u) => (
            <tr key={u.ID} className="border-t">
              <td className="py-2">{u.ID}</td>
              <td>{u.BaseURL}</td>
              <td><code className="text-xs">{JSON.stringify(u.InjectJSON)}</code></td>
              <td><Button size="sm" variant="ghost" onClick={() => del.mutate(u.ID)}>Delete</Button></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
