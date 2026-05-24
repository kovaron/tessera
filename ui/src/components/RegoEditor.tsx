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
      <div className="w-80 border rounded p-3 text-xs space-y-2">
        <div className={v.ok ? "text-green-600" : "text-red-600"}>
          {v.ok ? "✓ basic structure OK" : "✗ issues"}
        </div>
        <ul className="space-y-1">
          {v.errors.map((e, i) => <li key={i}>{e.message}</li>)}
        </ul>
        <p className="text-muted-foreground mt-3">
          Full OPA compile runs on save (server-side). Errors surface as a save failure.
        </p>
      </div>
    </div>
  );
}
