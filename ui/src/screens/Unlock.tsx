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
  const [bioInFlight, setBioInFlight] = useState(false);
  const unlock = useUnlock();

  useEffect(() => {
    api.biometryAvailable().then(setBioAvailable).catch(() => setBioAvailable(false));
  }, []);

  const tryBiometry = async () => {
    setBioError(null);
    setBioInFlight(true);
    try {
      const pass = await api.keychainLoad();
      if (!pass) {
        setBioError("No passphrase stored. Enter it once below; check 'Use Touch ID' next bootstrap.");
        return;
      }
      unlock.mutate(pass);
    } catch (e) {
      setBioError(String(e));
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
