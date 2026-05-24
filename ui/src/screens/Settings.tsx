import { useState } from "react";
import { api } from "@/lib/invoke";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";

export default function Settings() {
  const [keychain, setKeychain] = useState(false);
  const [status, setStatus] = useState("");

  return (
    <div className="p-6 space-y-6 max-w-xl">
      <h1 className="text-xl font-semibold">Settings</h1>
      <section className="space-y-2">
        <Label>Admin socket path</Label>
        <Input defaultValue="$HOME/.proxyd/admin.sock" disabled />
        <p className="text-xs text-muted-foreground">Configurable in future versions.</p>
      </section>
      <section className="space-y-2">
        <Label>Audit log path</Label>
        <Input defaultValue="$HOME/.proxyd/audit.log" disabled />
      </section>
      <section className="space-y-2">
        <div className="flex items-center justify-between">
          <Label htmlFor="kc">Store passphrase in macOS Keychain</Label>
          <Switch id="kc" checked={keychain} onCheckedChange={setKeychain} />
        </div>
        <div className="flex gap-2">
          <Button size="sm" variant="outline" onClick={async () => { await api.keychainDelete(); setStatus("Keychain entry deleted"); }}>
            Delete keychain entry
          </Button>
        </div>
        {status && <p className="text-xs text-muted-foreground">{status}</p>}
      </section>
    </div>
  );
}
