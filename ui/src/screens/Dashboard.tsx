import { useUpstreams } from "@/hooks/useUpstreams";
import { useTokens } from "@/hooks/useTokens";
import { useAuditBuffer } from "@/hooks/useAudit";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

export default function Dashboard() {
  const ups = useUpstreams();
  const toks = useTokens();
  const events = useAuditBuffer();
  const active = (toks.data ?? []).filter((t) => !t.RevokedAt).length;
  const recent = events.slice(0, 10);

  return (
    <div className="p-6 grid grid-cols-3 gap-4">
      <Card><CardHeader><CardTitle className="text-sm">Upstreams</CardTitle></CardHeader><CardContent className="text-3xl">{ups.data?.length ?? "—"}</CardContent></Card>
      <Card><CardHeader><CardTitle className="text-sm">Active tokens</CardTitle></CardHeader><CardContent className="text-3xl">{active}</CardContent></Card>
      <Card><CardHeader><CardTitle className="text-sm">Total events seen</CardTitle></CardHeader><CardContent className="text-3xl">{events.length}</CardContent></Card>
      <Card className="col-span-3">
        <CardHeader><CardTitle className="text-sm">Recent activity</CardTitle></CardHeader>
        <CardContent className="text-xs font-mono space-y-1">
          {recent.length === 0 && <div className="text-muted-foreground">No events yet</div>}
          {recent.map((e, i) => (
            <div key={i}>
              <span className={e.decision === "allow" ? "text-green-600" : "text-red-600"}>{e.decision}</span>{" "}
              {e.method} {e.path} → {e.upstream_status}
            </div>
          ))}
        </CardContent>
      </Card>
    </div>
  );
}
