import { useState } from "react";
import { useUnlock } from "@/hooks/useStatus";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import logo from "@/assets/logo.png";

export default function Unlock() {
  const [pw, setPw] = useState("");
  const unlock = useUnlock();

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
        <Input
          autoFocus
          type="password"
          placeholder="Passphrase"
          value={pw}
          onChange={(e) => setPw(e.target.value)}
        />
        <Button type="submit" disabled={!pw || unlock.isPending}>
          Unlock
        </Button>
        {unlock.isError && (
          <div className="text-xs text-red-500">{String(unlock.error)}</div>
        )}
      </form>
    </div>
  );
}
