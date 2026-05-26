import { useState } from "react";
import { api } from "@/lib/invoke";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import logo from "@/assets/logo.png";

interface Props { onDone: () => void; }

export default function BootstrapWizard({ onDone }: Props) {
  const [step, setStep] = useState<"welcome" | "passphrase" | "running" | "done">("welcome");
  const [pw, setPw] = useState("");
  const [pw2, setPw2] = useState("");
  const [save, setSave] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const submit = async () => {
    if (pw !== pw2) { setErr("Passphrases do not match"); return; }
    if (pw.length < 12) { setErr("Use at least 12 characters"); return; }
    setStep("running");
    try {
      await api.runBootstrap(pw, null);
      if (save) await api.keychainSave(pw);
      setStep("done");
    } catch (e: any) {
      setErr(String(e));
      setStep("passphrase");
    }
  };

  return (
    <div className="flex h-screen items-center justify-center p-6">
      <div className="max-w-md w-full space-y-4">
        <img src={logo} alt="" className="w-20 h-20 rounded-2xl mx-auto" />
        {step === "welcome" && (
          <>
            <h1 className="text-xl font-semibold">Welcome to Tessera</h1>
            <p className="text-sm text-muted-foreground">
              Tessera has not been bootstrapped. Set a passphrase to create the keystore at
              <code className="text-xs"> $HOME/.tessera/data.db</code>.
            </p>
            <Button onClick={() => setStep("passphrase")}>Continue</Button>
          </>
        )}
        {step === "passphrase" && (
          <>
            <h1 className="text-xl font-semibold">Choose a passphrase</h1>
            <div><Label>Passphrase (min 12 chars)</Label><Input type="password" value={pw} onChange={(e) => setPw(e.target.value)} /></div>
            <div><Label>Confirm</Label><Input type="password" value={pw2} onChange={(e) => setPw2(e.target.value)} /></div>
            <div className="flex items-center justify-between">
              <Label htmlFor="kc">Store in Keychain</Label>
              <Switch id="kc" checked={save} onCheckedChange={setSave} />
            </div>
            {err && <p className="text-xs text-red-500">{err}</p>}
            <Button onClick={submit}>Bootstrap</Button>
          </>
        )}
        {step === "running" && <p className="text-sm">Creating keystore…</p>}
        {step === "done" && (
          <>
            <h1 className="text-xl font-semibold">Done</h1>
            <p className="text-sm">Now start tessera. Run from a terminal:</p>
            <code className="block bg-muted p-2 rounded text-xs">tessera &amp;</code>
            <Button onClick={onDone}>Continue</Button>
          </>
        )}
      </div>
    </div>
  );
}
