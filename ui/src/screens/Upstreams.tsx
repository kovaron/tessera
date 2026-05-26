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

function InjectCell({ raw }: { raw: unknown }) {
  const r = toInjectRule(raw);
  return (
    <div className="flex flex-col gap-0.5 font-mono text-[11px] leading-tight">
      <div>
        <span className="text-muted-foreground">type</span>{" "}
        <span className="text-foreground">{r.type}</span>
        {r.name && (
          <>
            {" · "}
            <span className="text-muted-foreground">name</span>{" "}
            <span className="text-foreground">{r.name}</span>
          </>
        )}
      </div>
      <div className="truncate" title={r.secret_ref}>
        <span className="text-muted-foreground">ref</span>{" "}
        <span className="text-foreground">{r.secret_ref}</span>
      </div>
      {r.value_template && (
        <div className="truncate" title={r.value_template}>
          <span className="text-muted-foreground">tmpl</span>{" "}
          <span className="text-foreground">{r.value_template}</span>
        </div>
      )}
    </div>
  );
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
      <div className="flex justify-between items-center">
        <h1 className="text-xl font-semibold">Upstreams</h1>
        <Button onClick={openAdd}>Add upstream</Button>
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
                {isEdit && <p className="text-xs text-muted-foreground mt-1">ID is the primary key. To rename, delete and recreate.</p>}
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

      <div className="rounded-md border overflow-hidden">
        <table className="w-full text-sm" style={{ tableLayout: "fixed" }}>
          <colgroup>
            <col style={{ width: "14%" }} />
            <col style={{ width: "32%" }} />
            <col style={{ width: "34%" }} />
            <col style={{ width: "20%", minWidth: "180px" }} />
          </colgroup>
          <thead className="bg-muted/40">
            <tr className="text-left text-xs uppercase tracking-wide text-muted-foreground">
              <th className="px-3 py-2">ID</th>
              <th className="px-3 py-2">Base URL</th>
              <th className="px-3 py-2">Inject</th>
              <th className="px-3 py-2"></th>
            </tr>
          </thead>
          <tbody>
            {data.length === 0 && (
              <tr>
                <td className="px-3 py-6 text-center text-muted-foreground" colSpan={4}>
                  No upstreams yet. Click <em>Add upstream</em>.
                </td>
              </tr>
            )}
            {data.map((u) => (
              <tr key={u.ID} className="border-t hover:bg-muted/30">
                <td className="px-3 py-2 font-mono text-xs truncate" title={u.ID}>{u.ID}</td>
                <td className="px-3 py-2 font-mono text-xs truncate" title={u.BaseURL}>{u.BaseURL}</td>
                <td className="px-3 py-2"><InjectCell raw={u.InjectJSON} /></td>
                <td className="px-3 py-2">
                  <div className="flex justify-end gap-2 whitespace-nowrap">
                    <Button size="sm" variant="outline" className="h-7 px-3" onClick={() => openEdit(u)}>Edit</Button>
                    <Button size="sm" variant="outline" className="h-7 px-3 border-red-500/30 text-red-500 hover:bg-red-500/10" onClick={() => del.mutate(u.ID)}>Delete</Button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <p className="text-xs text-muted-foreground">{data.length} upstream(s)</p>
    </div>
  );
}
