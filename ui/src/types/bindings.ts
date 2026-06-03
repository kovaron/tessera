import { invoke } from "@tauri-apps/api/core";

// ============== Types ==============

export type Status = { locked: boolean; version: string; initialized: boolean };

export type Upstream = {
  ID: string;
  BaseURL: string;
  InjectJSON: unknown;
  Hostnames: string[];
  CreatedAt: number;
};

export type InjectRule = {
  type: string;
  name?: string | null;
  value_template?: string | null;
  secret_ref: string;
};

export type UpsertUpstreamReq = {
  id: string;
  base_url: string;
  inject: InjectRule;
  hostnames: string[];
};

export type Token = {
  ID: string;
  ParentID: string | null;
  Label: string;
  PolicyID: string;
  UpstreamID: string;
  CreatedAt: number;
  ExpiresAt: number | null;
  RevokedAt: number | null;
};

export type MintTokenReq = {
  label: string;
  upstream_id: string;
  policy_id: string;
  ttl_seconds: number;
};

export type MintTokenResp = { id: string; secret: string };

export type AttenuateReq = {
  parent_token: string;
  label: string;
  policy_id: string;
  ttl_seconds: number;
};

export type CreatePolicyReq = {
  name: string;
  upstream_id?: string | null;
  engine: string;
  source: string;
  subset_of?: string | null;
};

export type CreatePolicyResp = { id: string };

export type Policy = {
  id: string;
  name: string;
  upstream_id?: string | null;
  engine: string;
  subset_of?: string | null;
  created_at: number;
  source?: string;
};

export type AuditEvent = {
  ts: string;
  token_id: string;
  token_label: string;
  upstream_id: string;
  method: string;
  path: string;
  decision: string;
  deny_reason?: string;
  upstream_status: number;
  status: number;
  latency_ms: number;
  remote_addr: string;
};

export type DetectResult = { db_exists: boolean; socket_exists: boolean };

// ============== Commands ==============

export const commands = {
  getStatus: (): Promise<Status> => invoke("get_status"),
  unlock: (passphrase: string): Promise<void> => invoke("unlock", { passphrase }),
  lock: (): Promise<void> => invoke("lock"),

  listUpstreams: (): Promise<Upstream[]> => invoke("list_upstreams"),
  upsertUpstream: (req: UpsertUpstreamReq): Promise<void> => invoke("upsert_upstream", { req }),
  deleteUpstream: (id: string): Promise<void> => invoke("delete_upstream", { id }),

  createPolicy: (req: CreatePolicyReq): Promise<CreatePolicyResp> => invoke("create_policy", { req }),
  listPolicies: (): Promise<Policy[]> => invoke("list_policies"),
  getPolicy: (id: string): Promise<Policy> => invoke("get_policy", { id }),
  updatePolicy: (id: string, req: CreatePolicyReq): Promise<void> => invoke("update_policy", { id, req }),
  deletePolicy: (id: string): Promise<void> => invoke("delete_policy", { id }),

  listTokens: (): Promise<Token[]> => invoke("list_tokens"),
  mintToken: (req: MintTokenReq): Promise<MintTokenResp> => invoke("mint_token", { req }),
  revokeToken: (id: string): Promise<void> => invoke("revoke_token", { id }),
  attenuateToken: (req: AttenuateReq): Promise<MintTokenResp> => invoke("attenuate_token", { req }),

  detectState: (): Promise<DetectResult> => invoke("detect_state"),
  runBootstrap: (passphrase: string, db_path: string | null): Promise<void> =>
    invoke("run_bootstrap", { passphrase, dbPath: db_path }),

  keychainSave: (passphrase: string): Promise<void> => invoke("keychain_save", { passphrase }),
  keychainSaveWithBiometry: (passphrase: string): Promise<void> => invoke("keychain_save_with_biometry", { passphrase }),
  keychainLoad: (): Promise<string | null> => invoke("keychain_load"),
  keychainDelete: (): Promise<void> => invoke("keychain_delete"),
  biometryAvailable: (): Promise<boolean> => invoke("biometry_available"),
  biometryAuthenticate: (reason: string): Promise<boolean> => invoke("biometry_authenticate", { reason }),

  clipboardSetWithClear: (value: string, clear_after_seconds: number): Promise<void> =>
    invoke("clipboard_set_with_clear", { value, clearAfterSeconds: clear_after_seconds }),
};
