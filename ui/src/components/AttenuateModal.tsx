import { useState } from "react";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import { Slider } from "@/components/ui/slider";
import { api } from "@/lib/invoke";
import { useAttenuateToken } from "@/hooks/useTokens";

interface Props { open: boolean; onClose: () => void; }

export default function AttenuateModal({ open, onClose }: Props) {
  const [parentToken, setParent] = useState("");
  const [label, setLabel] = useState("");
  const [policyId, setPolicyId] = useState("");
  const [ttl, setTtl] = useState(600);
  const [secret, setSecret] = useState<string | null>(null);
  const [revealed, setRevealed] = useState(false);
  const att = useAttenuateToken();

  const submit = () => {
    att.mutate(
      { parent_token: parentToken, label, policy_id: policyId, ttl_seconds: ttl },
      {
        onSuccess: async (r) => {
          setSecret(r.secret);
          setRevealed(true);
          await api.clipboardSetWithClear(r.secret, 60);
        },
      }
    );
  };

  return (
    <Dialog open={open} onOpenChange={(o) => { if (!o) { setSecret(null); setRevealed(false); onClose(); } }}>
      <DialogContent>
        <DialogHeader><DialogTitle>Attenuate token</DialogTitle></DialogHeader>
        {secret ? (
          <div className="space-y-3">
            <p className="text-xs text-muted-foreground">Copied. Auto-clear in 60s.</p>
            <div className="bg-muted p-2 rounded font-mono text-sm break-all">{revealed ? secret : "••••••••"}</div>
            <div className="flex gap-2">
              <Button variant="outline" onClick={() => setRevealed((r) => !r)}>{revealed ? "Hide" : "Reveal"}</Button>
              <Button onClick={() => { setSecret(null); onClose(); }}>Done</Button>
            </div>
          </div>
        ) : (
          <div className="space-y-3">
            <div><Label>Parent token (paste plaintext)</Label><Input type="password" value={parentToken} onChange={(e) => setParent(e.target.value)} /></div>
            <div><Label>Label</Label><Input value={label} onChange={(e) => setLabel(e.target.value)} /></div>
            <div><Label>Policy ID (subset of parent's policy)</Label><Input value={policyId} onChange={(e) => setPolicyId(e.target.value)} /></div>
            <div><Label>TTL: {ttl}s</Label><Slider min={60} max={86400} step={60} value={[ttl]} onValueChange={(v) => setTtl(v[0])} /></div>
            <Button disabled={!parentToken || !label || !policyId || att.isPending} onClick={submit}>Attenuate</Button>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}
