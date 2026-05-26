import Editor from "@monaco-editor/react";
import { useMemo } from "react";
import { quickValidate } from "@/lib/rego-compile";

interface Props {
  value: string;
  onChange: (v: string) => void;
}

export default function RegoEditor({ value, onChange }: Props) {
  const v = useMemo(() => quickValidate(value), [value]);
  return (
    <div className="flex h-[60vh] gap-4">
      <div className="flex-1 border rounded">
        <Editor
          height="100%"
          defaultLanguage="ruby"
          value={value}
          onChange={(v) => onChange(v ?? "")}
          options={{ minimap: { enabled: false }, fontSize: 13 }}
        />
      </div>
      <div className="w-80 border rounded p-3 text-xs space-y-3 overflow-auto">
        <div>
          <div className={v.ok ? "text-green-600" : "text-red-600"}>
            {v.ok ? "✓ basic structure OK" : "✗ issues"}
          </div>
          <ul className="space-y-1 mt-1">
            {v.errors.map((e, i) => <li key={i}>{e.message}</li>)}
          </ul>
          <p className="text-muted-foreground mt-2">
            Full OPA compile runs server-side on save.
          </p>
        </div>

        <hr className="border-border" />

        <div className="space-y-2">
          <div className="font-semibold text-foreground">Rego cheatsheet</div>

          <div>
            <div className="text-muted-foreground">Skeleton</div>
            <pre className="bg-muted p-2 rounded text-[11px] leading-tight whitespace-pre-wrap">{`package proxy.authz
default allow := false

allow if {
  input.request.method == "GET"
}`}</pre>
          </div>

          <div>
            <div className="text-muted-foreground">Input shape</div>
            <pre className="bg-muted p-2 rounded text-[11px] leading-tight whitespace-pre-wrap">{`input.token.id
input.token.label
input.token.parent_chain
input.upstream            // upstream_id
input.request.method      // GET, POST, ...
input.request.path        // "/repos/x/y"
input.request.path_segments
input.request.query       // {"k":["v"]}
input.request.headers     // {"X-Trace":"abc"}`}</pre>
          </div>

          <div>
            <div className="text-muted-foreground">Path prefix match</div>
            <pre className="bg-muted p-2 rounded text-[11px] leading-tight whitespace-pre-wrap">{`allow if {
  input.request.method == "GET"
  startswith(input.request.path, "/repos/acme/")
}`}</pre>
          </div>

          <div>
            <div className="text-muted-foreground">Method allowlist</div>
            <pre className="bg-muted p-2 rounded text-[11px] leading-tight whitespace-pre-wrap">{`allowed_methods := {"GET", "HEAD"}

allow if {
  allowed_methods[input.request.method]
}`}</pre>
          </div>

          <div>
            <div className="text-muted-foreground">Regex path</div>
            <pre className="bg-muted p-2 rounded text-[11px] leading-tight whitespace-pre-wrap">{`allow if {
  regex.match("^/users/[0-9]+$", input.request.path)
}`}</pre>
          </div>

          <div>
            <div className="text-muted-foreground">Label-scoped</div>
            <pre className="bg-muted p-2 rounded text-[11px] leading-tight whitespace-pre-wrap">{`allow if {
  input.token.label == "ci"
  input.request.method == "POST"
}`}</pre>
          </div>

          <div>
            <div className="text-muted-foreground">Deny override</div>
            <pre className="bg-muted p-2 rounded text-[11px] leading-tight whitespace-pre-wrap">{`default allow := false

allow if { input.request.method == "GET" }

# explicit deny wins
allow := false if {
  contains(input.request.path, "/admin")
}`}</pre>
          </div>

          <div>
            <div className="text-muted-foreground">Built-ins</div>
            <pre className="bg-muted p-2 rounded text-[11px] leading-tight whitespace-pre-wrap">{`startswith(s, prefix)
endswith(s, suffix)
contains(s, needle)
regex.match(pat, s)
count(arr)
to_number(s)
time.now_ns()`}</pre>
          </div>

          <p className="text-muted-foreground">
            Reference: <span className="font-mono">openpolicyagent.org/docs/policy-language</span>
          </p>
        </div>
      </div>
    </div>
  );
}
