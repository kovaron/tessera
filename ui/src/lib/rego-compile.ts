import { loadPolicy } from "@open-policy-agent/opa-wasm";

export interface CompileResult {
  ok: boolean;
  errors: { line?: number; message: string }[];
}

// Heuristic local validation; full OPA compile happens server-side on POST.
export function quickValidate(source: string): CompileResult {
  const errors: CompileResult["errors"] = [];
  if (!/^package\s+\S+/m.test(source)) errors.push({ message: "missing 'package' declaration" });
  if (!/default\s+allow\s*[:=]/.test(source)) errors.push({ message: "missing 'default allow' rule (recommended)" });
  return { ok: errors.length === 0, errors };
}

export { loadPolicy };
