import { useMemo, useState } from "react";
import { useTokens, useRevokeToken } from "@/hooks/useTokens";
import { Button } from "@/components/ui/button";
import MintTokenModal from "@/components/MintTokenModal";
import AttenuateModal from "@/components/AttenuateModal";
import type { Token } from "@/types/bindings";

interface Node { tok: Token; children: Node[] }

function buildTree(rows: Token[]): Node[] {
  const byId = new Map<string, Node>();
  rows.forEach((t) => byId.set(t.ID, { tok: t, children: [] }));
  const roots: Node[] = [];
  byId.forEach((n) => {
    if (n.tok.ParentID && byId.has(n.tok.ParentID)) byId.get(n.tok.ParentID)!.children.push(n);
    else roots.push(n);
  });
  return roots;
}

function Row({ node, depth, onRevoke }: { node: Node; depth: number; onRevoke: (id: string) => void }) {
  const expIn = node.tok.ExpiresAt ? node.tok.ExpiresAt - Math.floor(Date.now() / 1000) : null;
  return (
    <>
      <tr className="border-t">
        <td style={{ paddingLeft: depth * 16 }} className="py-2">{node.tok.Label || node.tok.ID.slice(0, 8)}</td>
        <td>{node.tok.UpstreamID}</td>
        <td>{node.tok.RevokedAt ? <span className="text-red-500">revoked</span> : expIn !== null ? `${expIn}s` : "—"}</td>
        <td>
          {!node.tok.RevokedAt && (
            <Button size="sm" variant="ghost" onClick={() => onRevoke(node.tok.ID)}>Revoke</Button>
          )}
        </td>
      </tr>
      {node.children.map((c) => <Row key={c.tok.ID} node={c} depth={depth + 1} onRevoke={onRevoke} />)}
    </>
  );
}

export default function Tokens() {
  const { data = [] } = useTokens();
  const tree = useMemo(() => buildTree(data), [data]);
  const revoke = useRevokeToken();
  const [mintOpen, setMintOpen] = useState(false);
  const [attOpen, setAttOpen] = useState(false);

  return (
    <div className="p-6 space-y-4">
      <div className="flex justify-between">
        <h1 className="text-xl font-semibold">Tokens</h1>
        <div className="flex gap-2">
          <Button onClick={() => setMintOpen(true)}>Mint</Button>
          <Button variant="outline" onClick={() => setAttOpen(true)}>Attenuate</Button>
        </div>
      </div>
      <table className="w-full text-sm">
        <thead>
          <tr className="text-left text-muted-foreground"><th>Label</th><th>Upstream</th><th>Expires</th><th></th></tr>
        </thead>
        <tbody>
          {tree.map((n) => <Row key={n.tok.ID} node={n} depth={0} onRevoke={(id) => {
            if (confirm("Revoke this token and all its children?")) revoke.mutate(id);
          }} />)}
        </tbody>
      </table>
      <MintTokenModal open={mintOpen} onClose={() => setMintOpen(false)} />
      <AttenuateModal open={attOpen} onClose={() => setAttOpen(false)} />
    </div>
  );
}
