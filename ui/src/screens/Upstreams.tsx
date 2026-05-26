import { useState } from "react";
import { useUpstreams, useUpsertUpstream, useDeleteUpstream } from "@/hooks/useUpstreams";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import InjectRuleBuilder from "@/components/InjectRuleBuilder";
import type { InjectRule, UpsertUpstreamReq, Upstream } from "@/types/bindings";

const emptyInject: InjectRule = { type: "bearer", secret_ref: "" };

function toInjectRule(raw: unknown): InjectRule {
  if (raw && typeof raw === "object") {
    const obj = raw as Record<string, unknown>;
    return {
      type: typeof obj.type === "string" ? obj.type : "bearer",
      name: typeof obj.name === "string" ? obj.name : undefined,
      value_template: typeof obj.value_template === "string" ? obj.value_template : undefined,
      secret_ref: typeof obj.secret_ref === "string" ? obj.secret_ref : "",
    };
  }
  return { ...emptyInject };
}

export default function Upstreams() {
  const upstreams = useUpstreams();
  const data = upstreams.data ?? [];
  const upsert = useUpsertUpstream();
  const del = useDeleteUpstream();
  const [editing, setEditing] = useState<UpsertUpstreamReq | null>(null);
  const [isEdit, setIsEdit] = useState(false);

  const openAdd = () => {
    setIsEdit(false);
    setEditing({ id: "", base_url: "", inject: { ...emptyInject } });
  };

  const openEdit = (u: Upstream) => {
    setIsEdit(true);
    setEditing({
      id: u.ID,
      base_url: u.BaseURL,
      inject: toInjectRule(u.InjectJSON),
    });
  };

  const close = () => setEditing(null);

  return (
    <div className="p-6 space-y-4">
      <div className="flex justify-between">
        <h1 className="text-xl font-semibold">Upstreams</h1>
        <Button onClick={openAdd}>Add</Button>
      </div>

      <Sheet open={editing !== null} onOpenChange={(o) => { if (!o) close(); }}>
        {editing && (
          <SheetContent>
            <SheetHeader>
              <SheetTitle>{isEdit ? `Edit ${editing.id}` : "New upstream"}</SheetTitle>
            </SheetHeader>
            <div className="space-y-4 mt-4">
              <div>
                <Label>ID</Label>
                <Input
                  value={editing.id}
                  disabled={isEdit}
                  onChange={(e) => setEditing({ ...editing, id: e.target.value })}
                />
                {isEdit && <p className="text-xs text-muted-foreground">ID is the primary key. To rename, delete and recreate.</p>}
              </div>
              <div>
                <Label>Base URL</Label>
                <Input value={editing.base_url} onChange={(e) => setEditing({ ...editing, base_url: e.target.value })} />
              </div>
              <InjectRuleBuilder value={editing.inject} onChange={(inject) => setEditing({ ...editing, inject })} />
              <Button
                disabled={upsert.isPending || !editing.id || !editing.base_url}
                onClick={() => upsert.mutate(editing, { onSuccess: close })}
              >
                {upsert.isPending ? "Saving…" : "Save"}
              </Button>
              {upsert.isError && (
                <p className="text-xs text-red-500 break-all">save failed: {String(upsert.error)}</p>
              )}
            </div>
          </SheetContent>
        )}
      </Sheet>

      {upstreams.isError && (
        <p className="text-xs text-red-500">list failed: {String(upstreams.error)}</p>
      )}
      <p className="text-xs text-muted-foreground">{data.length} upstream(s)</p>

      <table className="w-full text-sm">
        <thead>
          <tr className="text-left text-muted-foreground">
            <th>ID</th><th>Base URL</th><th>Inject</th><th></th>
          </tr>
        </thead>
        <tbody>
          {data.map((u) => (
            <tr key={u.ID} className="border-t">
              <td className="py-2">{u.ID}</td>
              <td>{u.BaseURL}</td>
              <td><code className="text-xs">{JSON.stringify(u.InjectJSON)}</code></td>
              <td className="text-right space-x-1">
                <Button size="sm" variant="outline" onClick={() => openEdit(u)}>Edit</Button>
                <Button size="sm" variant="ghost" onClick={() => del.mutate(u.ID)}>Delete</Button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
