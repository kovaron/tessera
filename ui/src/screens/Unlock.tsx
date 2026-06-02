import { useEffect, useState } from "react";
import { useUnlock } from "@/hooks/useStatus";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { api } from "@/lib/invoke";
import logo from "@/assets/logo.png";

export default function Unlock() {
  const [pw, setPw] = useState("");
  const [bioAvailable, setBioAvailable] = useState(false);
  const [bioError, setBioError] = useState<string | null>(null);
  const [bioStep, setBioStep] = useState<string>("");
  const [bioInFlight, setBioInFlight] = useState(false);
  const unlock = useUnlock();

  useEffect(() => {
    api.biometryAvailable()
      .then((v) => { console.log("[bio] available =", v); setBioAvailable(v); })
      .catch((e) => { console.error("[bio] availability check failed", e); setBioAvailable(false); });
  }, []);

  const tryBiometry = async () => {
    console.log("[bio] button clicked");
    setBioError(null);
    setBioStep("calling keychain…");
    setBioInFlight(true);
    try {
      console.log("[bio] -> keychainLoad()");
      const pass = await api.keychainLoad();
      console.log("[bio] <- keychainLoad returned", typeof pass, pass === null ? "null" : pass === undefined ? "undefined" : `${pass.length} chars`);
      setBioStep(pass ? `loaded ${pass.length}-char passphrase, unlocking…` : "keychain returned null");
      if (!pass) {
        setBioError("No passphrase stored, or stored without biometry. Re-bootstrap with both 'Store in Keychain' and 'Require Touch ID' toggled on.");
        return;
      }
      unlock.mutate(pass, {
        onSuccess: () => setBioStep("unlocked"),
        onError: (e) => setBioError(`unlock failed: ${String(e)}`),
      });
    } catch (e) {
      console.error("[bio] error", e);
      setBioError(`keychain error: ${String(e)}`);
    } finally {
      setBioInFlight(false);
    }
  };

  return (
    <div className="flex h-screen items-center justify-center">
      <form
        className="flex flex-col gap-3 w-80 items-stretch"
        onSubmit={(e) => {
          e.preventDefault();
          unlock.mutate(pw);
        }}
      >
        <img src={logo} alt="" className="w-20 h-20 rounded-2xl self-center mb-2" />
        <h1 className="text-lg font-semibold text-center">Unlock Tessera</h1>

        {bioAvailable && (
          <>
            <Button
              type="button"
              variant="outline"
              disabled={bioInFlight || unlock.isPending}
              onClick={tryBiometry}
            >
              {bioInFlight ? "Waiting for Touch ID…" : "Unlock with Touch ID"}
            </Button>
            {bioStep && <div className="text-xs text-muted-foreground break-all">step: {bioStep}</div>}
            {bioError && <div className="text-xs text-amber-500 break-all">{bioError}</div>}
            <div className="text-center text-xs text-muted-foreground">— or —</div>
          </>
        )}

        <Input
          autoFocus
          type="password"
          placeholder="Passphrase"
          value={pw}
          onChange={(e) => setPw(e.target.value)}
        />
        <Button type="submit" disabled={!pw || unlock.isPending}>
          {unlock.isPending ? "Unlocking…" : "Unlock"}
        </Button>
        {unlock.isError && (
          <div className="text-xs text-red-500 break-all">{String(unlock.error)}</div>
        )}
      </form>
    </div>
  );
}
