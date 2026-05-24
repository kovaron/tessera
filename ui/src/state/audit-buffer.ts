import type { AuditEvent } from "@/types/bindings";

const MAX = 5000;
const buf: AuditEvent[] = [];
const subscribers = new Set<() => void>();

export function pushEvent(ev: AuditEvent) {
  buf.unshift(ev);
  if (buf.length > MAX) buf.length = MAX;
  subscribers.forEach((cb) => cb());
}

export function getBuffer() { return buf; }

export function subscribe(cb: () => void) {
  subscribers.add(cb);
  return () => subscribers.delete(cb);
}
