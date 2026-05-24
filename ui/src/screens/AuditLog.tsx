import { useMemo, useRef, useState } from "react";
import { useAuditBuffer } from "@/hooks/useAudit";
import { useVirtualizer } from "@tanstack/react-virtual";
import { Input } from "@/components/ui/input";

export default function AuditLog() {
  const events = useAuditBuffer();
  const [filter, setFilter] = useState("");
  const [decision, setDecision] = useState<"all" | "allow" | "deny">("all");
  const parentRef = useRef<HTMLDivElement>(null);

  const rows = useMemo(() => {
    return events.filter((e) =>
      (decision === "all" || e.decision === decision) &&
      (!filter || JSON.stringify(e).toLowerCase().includes(filter.toLowerCase()))
    );
  }, [events, filter, decision]);

  const v = useVirtualizer({
    count: rows.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 32,
    overscan: 12,
  });

  return (
    <div className="p-6 space-y-3 h-full flex flex-col">
      <h1 className="text-xl font-semibold">Audit log</h1>
      <div className="flex gap-2">
        <Input placeholder="Filter…" value={filter} onChange={(e) => setFilter(e.target.value)} />
        <select className="border rounded p-2 text-sm" value={decision} onChange={(e) => setDecision(e.target.value as any)}>
          <option value="all">all</option>
          <option value="allow">allow</option>
          <option value="deny">deny</option>
        </select>
      </div>
      <div ref={parentRef} className="flex-1 overflow-auto border rounded">
        <div style={{ height: v.getTotalSize(), position: "relative" }}>
          {v.getVirtualItems().map((vi) => {
            const e = rows[vi.index];
            return (
              <div key={vi.key} style={{ position: "absolute", top: vi.start, height: vi.size, left: 0, right: 0 }} className="px-3 py-1 text-xs font-mono border-b">
                <span className={e.decision === "allow" ? "text-green-600" : "text-red-600"}>{e.decision}</span>{" "}
                <span className="text-muted-foreground">{e.ts}</span>{" "}
                {e.method} {e.path} → {e.upstream_status} ({e.latency_ms}ms)
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
