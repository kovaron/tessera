import { useStatus, useLock } from "@/hooks/useStatus";
import { Button } from "@/components/ui/button";

export default function StatusBadge() {
  const { data, isError } = useStatus();
  const lock = useLock();

  if (isError) {
    return <div className="text-xs text-red-500">● proxyd unreachable</div>;
  }
  if (!data) return <div className="text-xs">connecting…</div>;
  return (
    <div className="flex flex-col gap-1 text-xs">
      <div>{data.locked ? "○ locked" : "● unlocked"}</div>
      {!data.locked && (
        <Button size="sm" variant="outline" onClick={() => lock.mutate()}>
          Lock
        </Button>
      )}
    </div>
  );
}
