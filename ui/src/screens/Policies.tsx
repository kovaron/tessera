import { useState, useMemo, useEffect } from "react";
import {
  useListPolicies,
  useCreatePolicy,
  useUpdatePolicy,
  useDeletePolicy,
  useGetPolicy,
} from "@/hooks/usePolicies";
import { useUpstreams } from "@/hooks/useUpstreams";
import RegoEditor from "@/components/RegoEditor";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import ConfirmDialog from "@/components/ConfirmDialog";
import { quickValidate } from "@/lib/rego-compile";
import type { Policy } from "@/types/bindings";

const STARTER = `package proxy.authz
default allow := false

allow if {
    input.request.method == "GET"
}
`;

interface EditorState {
  mode: "create" | "edit";
  id: string | null;
  name: string;
  upstreamId: string;
  source: string;
}

export default function Policies() {
  const { data: policies = [], isLoading } = useListPolicies();
  const { data: upstreams = [] } = useUpstreams();
  const create = useCreatePolicy();
  const update = useUpdatePolicy();
  const del = useDeletePolicy();

  const [open, setOpen] = useState(false);
  const [toDelete, setToDelete] = useState<Policy | null>(null);
  const [editor, setEditor] = useState<EditorState>({
    mode: "create",
    id: null,
    name: "",
    upstreamId: "",
    source: STARTER,
  });

  const fetched = useGetPolicy(editor.mode === "edit" ? editor.id : null);
  useEffect(() => {
    if (editor.mode === "edit" && fetched.data) {
      setEditor((e) => ({ ...e, source: fetched.data.source || e.source }));
    }
  }, [fetched.data, editor.mode]);

  const grouped = useMemo(() => {
    const byUpstream: Record<string, Policy[]> = { __global__: [] };
    for (const p of policies) {
      const k = p.upstream_id || "__global__";
      byUpstream[k] = byUpstream[k] || [];
      byUpstream[k].push(p);
    }
    return byUpstream;
  }, [policies]);

  const openCreate = () => {
    setEditor({ mode: "create", id: null, name: "", upstreamId: "", source: STARTER });
    setOpen(true);
  };
  const openEdit = (p: Policy) => {
    setEditor({
      mode: "edit",
      id: p.id,
      name: p.name,
      upstreamId: p.upstream_id || "",
      source: "",
    });
    setOpen(true);
  };

  const v = quickValidate(editor.source);
  const saving = create.isPending || update.isPending;
  const save = () => {
    const req = {
      name: editor.name,
      upstream_id: editor.upstreamId || null,
      engine: "opa",
      source: editor.source,
    };
    if (editor.mode === "create") {
      create.mutate(req, { onSuccess: () => setOpen(false) });
    } else if (editor.id) {
      update.mutate({ id: editor.id, req }, { onSuccess: () => setOpen(false) });
    }
  };

  const renderGroup = (key: string, list: Policy[]) => (
    <div key={key} className="space-y-2">
      <h2 className="text-sm font-medium text-muted-foreground">
        {key === "__global__" ? "Global (any upstream)" : key}
      </h2>
      {list.length === 0 ? (
        <p className="text-xs text-muted-foreground">No policies.</p>
      ) : (
        <ul className="divide-y border rounded">
          {list.map((p) => (
            <li key={p.id} className="p-3 flex items-center justify-between">
              <div className="min-w-0">
                <div className="font-medium truncate">{p.name || p.id.slice(0, 12)}</div>
                <div className="text-xs text-muted-foreground font-mono truncate">{p.id}</div>
              </div>
              <div className="flex gap-2 shrink-0">
                <Button size="sm" variant="outline" onClick={() => openEdit(p)}>Edit</Button>
                <Button
                  size="sm"
                  variant="outline"
                  className="text-red-600 hover:text-red-700"
                  onClick={() => setToDelete(p)}
                >
                  Delete
                </Button>
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  );

  const groupKeys = useMemo(() => {
    const keys = Object.keys(grouped).filter((k) => k !== "__global__").sort();
    return ["__global__", ...keys];
  }, [grouped]);

  return (
    <div className="flex flex-col h-full p-6 gap-4 overflow-auto">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold">Policies</h1>
        <Button onClick={openCreate}>New policy</Button>
      </div>

      {isLoading ? (
        <p className="text-sm text-muted-foreground">Loading…</p>
      ) : policies.length === 0 ? (
        <p className="text-sm text-muted-foreground">No policies yet. Click "New policy" to create one.</p>
      ) : (
        <div className="space-y-6">
          {groupKeys.map((k) => grouped[k] && renderGroup(k, grouped[k]))}
        </div>
      )}

      {del.isError && (
        <p className="text-xs text-red-500 break-all">delete failed: {String(del.error)}</p>
      )}

      <ConfirmDialog
        open={toDelete !== null}
        title={`Delete policy ${toDelete?.name || toDelete?.id || ""}?`}
        description="Tokens already minted under this policy will fail authz on the next request (proxy returns deny: policy_unavailable)."
        confirmLabel="Delete"
        destructive
        onConfirm={() => {
          const id = toDelete!.id;
          setToDelete(null);
          del.mutate(id);
        }}
        onCancel={() => setToDelete(null)}
      />

      <Sheet open={open} onOpenChange={setOpen}>
        <SheetContent side="right" className="w-[800px] sm:max-w-[800px] flex flex-col">
          <SheetHeader>
            <SheetTitle>{editor.mode === "create" ? "New policy" : "Edit policy"}</SheetTitle>
          </SheetHeader>
          <div className="flex flex-col gap-3 flex-1 min-h-0 mt-4">
            <div className="grid grid-cols-2 gap-3">
              <div>
                <Label>Name</Label>
                <Input
                  value={editor.name}
                  onChange={(e) => setEditor((s) => ({ ...s, name: e.target.value }))}
                  placeholder="read-only"
                />
              </div>
              <div>
                <Label>Upstream</Label>
                <select
                  className="w-full border rounded p-2 bg-background text-foreground"
                  value={editor.upstreamId}
                  onChange={(e) => setEditor((s) => ({ ...s, upstreamId: e.target.value }))}
                >
                  <option value="">Global (any upstream)</option>
                  {upstreams.map((u) => (
                    <option key={u.ID} value={u.ID}>{u.ID}</option>
                  ))}
                </select>
              </div>
            </div>
            <div className="flex-1 min-h-0">
              <RegoEditor
                value={editor.source}
                onChange={(s) => setEditor((e) => ({ ...e, source: s }))}
              />
            </div>
            <div className="flex items-center justify-between">
              <div className="text-xs">
                {create.isError && <span className="text-red-500 break-all">{String(create.error)}</span>}
                {update.isError && <span className="text-red-500 break-all">{String(update.error)}</span>}
                {!v.ok && <span className="text-amber-600">{v.errors.map((e) => e.message).join("; ")}</span>}
              </div>
              <div className="flex gap-2">
                <Button variant="outline" onClick={() => setOpen(false)}>Cancel</Button>
                <Button disabled={!v.ok || !editor.name || saving} onClick={save}>
                  {saving ? "Saving…" : editor.mode === "create" ? "Create" : "Save"}
                </Button>
              </div>
            </div>
          </div>
        </SheetContent>
      </Sheet>
    </div>
  );
}
