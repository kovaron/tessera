import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import type { InjectRule } from "@/types/bindings";

interface Props {
  value: InjectRule;
  onChange: (v: InjectRule) => void;
}

export default function InjectRuleBuilder({ value, onChange }: Props) {
  return (
    <div className="flex flex-col gap-3">
      <div>
        <Label>Type</Label>
        <select
          className="w-full border rounded p-2"
          value={value.type}
          onChange={(e) => onChange({ ...value, type: e.target.value })}
        >
          <option value="bearer">bearer</option>
          <option value="header">header</option>
          <option value="query">query</option>
        </select>
      </div>
      {value.type !== "bearer" && (
        <div>
          <Label>Header / Query name</Label>
          <Input value={value.name ?? ""} onChange={(e) => onChange({ ...value, name: e.target.value })} />
        </div>
      )}
      {value.type === "header" && (
        <div>
          <Label>Value template (use ${"{secret}"} placeholder)</Label>
          <Input
            value={value.value_template ?? ""}
            onChange={(e) => onChange({ ...value, value_template: e.target.value })}
          />
        </div>
      )}
      <div>
        <Label>Secret ref</Label>
        <Input
          placeholder="env://NAME / 1password://… / doppler://…"
          value={value.secret_ref}
          onChange={(e) => onChange({ ...value, secret_ref: e.target.value })}
        />
      </div>
    </div>
  );
}
