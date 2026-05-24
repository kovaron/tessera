import { useState } from "react";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import { Slider } from "@/components/ui/slider";
import { api } from "@/lib/invoke";
import { useMintToken } from "@/hooks/useTokens";
import { useUpstreams } from "@/hooks/useUpstreams";

interface Props { open: boolean; onClose: () => void; }

export default function MintTokenModal({ open, onClose }: Props) {
  const [label, setLabel] = useState("");
  const [upstreamId, setUpstreamId] = useState("");
  const [policyId, setPolicyId] = useState("");
  const [ttl, setTtl] = useState(3600);
  const [secret, setSecret] = useState<string | null>(null);
  const [revealed, setRevealed] = useState(false);
  const { data: upstreams = [] } = useUpstreams();
  const mint = useMintToken();

  const submit = () => {
    mint.mutate(
      { label, upstream_id: upstreamId, policy_id: policyId, ttl_seconds: ttl },
      {
        onSuccess: async (resp) => {
          setSecret(resp.secret);
          setRevealed(true);
          await api.clipboardSetWithClear(resp.secret, 60);
        },
      }
    );
  };

  return (
    <Dialog open={open} onOpenChange={(o) => { if (!o) { setSecret(null); setRevealed(false); onClose(); } }}>
      <DialogContent>
        <DialogHeader><DialogTitle>Mint token</DialogTitle></DialogHeader>
        {secret ? (
          <div className="space-y-3">
            <p className="text-xs text-muted-foreground">
              Copied to clipboard. Clipboard auto-clears in 60 seconds. Shown once.
            </p>
            <div className="bg-muted p-2 rounded font-mono text-sm break-all">
              {revealed ? secret : "••••••••••••••••••••••••"}
            </div>
            <div className="flex gap-2">
              <Button variant="outline" onClick={() => setRevealed((r) => !r)}>
                {revealed ? "Hide" : "Reveal"}
              </Button>
              <Button onClick={() => { setSecret(null); setRevealed(false); onClose(); }}>Done</Button>
            </div>
          </div>
        ) : (
          <div className="space-y-3">
            <div><Label>Label</Label><Input value={label} onChange={(e) => setLabel(e.target.value)} /></div>
            <div>
              <Label>Upstream</Label>
              <select className="w-full border rounded p-2" value={upstreamId} onChange={(e) => setUpstreamId(e.target.value)}>
                <option value="">— pick —</option>
                {upstreams.map((u) => <option key={u.ID} value={u.ID}>{u.ID}</option>)}
              </select>
            </div>
            <div>
              <Label>Policy ID</Label>
              <Input value={policyId} onChange={(e) => setPolicyId(e.target.value)} placeholder="ULID" />
            </div>
            <div>
              <Label>TTL: {ttl}s ({Math.round(ttl / 60)}min)</Label>
              <Slider min={60} max={86400} step={60} value={[ttl]} onValueChange={(v) => setTtl(v[0])} />
            </div>
            <Button disabled={!label || !upstreamId || !policyId || mint.isPending} onClick={submit}>
              Mint
            </Button>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}
