import { useStatus, useLock } from "@/hooks/useStatus";
import { Button } from "@/components/ui/button";

export default function StatusBadge() {
  const { data, isError } = useStatus();
  const lock = useLock();

  let label = "connecting…";
  let cls = "bg-muted text-muted-foreground border-border";

  if (isError) {
    label = "● unreachable";
    cls = "bg-red-500/15 text-red-500 border-red-500/30";
  } else if (data?.locked) {
    label = "● locked";
    cls = "bg-red-500/15 text-red-500 border-red-500/30";
  } else if (data && !data.locked) {
    label = "● unlocked";
    cls = "bg-green-500/15 text-green-600 dark:text-green-400 border-green-500/30";
  }

  return (
    <div className="space-y-2">
      <div
        className={`rounded-md border px-3 py-2 text-sm font-semibold tracking-wide ${cls}`}
      >
        {label}
      </div>
      {data && !data.locked && (
        <Button size="sm" variant="outline" className="w-full" onClick={() => lock.mutate()}>
          Lock
        </Button>
      )}
    </div>
  );
}
