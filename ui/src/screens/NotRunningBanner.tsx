export default function NotRunningBanner() {
  return (
    <div className="flex h-screen items-center justify-center">
      <div className="max-w-md space-y-2 text-center">
        <h1 className="text-lg font-semibold">Tessera is not running</h1>
        <p className="text-sm text-muted-foreground">
          Start it from a terminal:
        </p>
        <code className="block bg-muted p-2 rounded text-xs">
          tessera &amp;
        </code>
        <p className="text-xs text-muted-foreground">
          This window will reconnect automatically.
        </p>
      </div>
    </div>
  );
}
