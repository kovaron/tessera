import { useEffect, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { getBuffer, pushEvent, subscribe } from "@/state/audit-buffer";
import type { AuditEvent } from "@/types/bindings";

export function useAuditBuffer() {
  const [, force] = useState(0);
  useEffect(() => subscribe(() => force((n) => n + 1)), []);
  return getBuffer();
}

let mounted = false;
export function mountAuditListener() {
  if (mounted) return;
  mounted = true;
  listen<AuditEvent>("audit:event", (e) => pushEvent(e.payload));
}
