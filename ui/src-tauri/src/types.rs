use serde::{Deserialize, Serialize};
use specta::Type;

#[derive(Serialize, Deserialize, Type, Debug, Clone)]
pub struct Status {
    pub locked: bool,
    pub version: String,
    #[serde(default)]
    pub initialized: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Upstream {
    #[serde(rename = "ID")]
    pub id: String,
    #[serde(rename = "BaseURL")]
    pub base_url: String,
    #[serde(rename = "InjectJSON")]
    pub inject_json: serde_json::Value,
    #[serde(rename = "CreatedAt")]
    pub created_at: i64,
}

#[derive(Serialize, Deserialize, Type, Debug, Clone)]
pub struct InjectRule {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default, rename = "value_template")]
    pub value_template: Option<String>,
    #[serde(rename = "secret_ref")]
    pub secret_ref: String,
}

#[derive(Serialize, Deserialize, Type, Debug, Clone)]
pub struct UpsertUpstreamReq {
    pub id: String,
    pub base_url: String,
    pub inject: InjectRule,
}

#[derive(Serialize, Deserialize, Type, Debug, Clone)]
pub struct Token {
    #[serde(rename = "ID")]
    pub id: String,
    #[serde(rename = "Hash")]
    pub hash: Vec<u8>,
    #[serde(rename = "ParentID")]
    pub parent_id: Option<String>,
    #[serde(rename = "Label")]
    pub label: String,
    #[serde(rename = "PolicyID")]
    pub policy_id: String,
    #[serde(rename = "UpstreamID")]
    pub upstream_id: String,
    #[serde(rename = "CreatedAt")]
    pub created_at: i64,
    #[serde(rename = "ExpiresAt")]
    pub expires_at: Option<i64>,
    #[serde(rename = "RevokedAt")]
    pub revoked_at: Option<i64>,
}

#[derive(Serialize, Deserialize, Type, Debug, Clone)]
pub struct MintTokenReq {
    pub label: String,
    pub upstream_id: String,
    pub policy_id: String,
    pub ttl_seconds: i64,
}

#[derive(Serialize, Deserialize, Type, Debug, Clone)]
pub struct MintTokenResp {
    pub id: String,
    pub secret: String,
}

#[derive(Serialize, Deserialize, Type, Debug, Clone)]
pub struct AttenuateReq {
    pub parent_token: String,
    pub label: String,
    pub policy_id: String,
    pub ttl_seconds: i64,
}

#[derive(Serialize, Deserialize, Type, Debug, Clone)]
pub struct CreatePolicyReq {
    pub engine: String,
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subset_of: Option<String>,
}

#[derive(Serialize, Deserialize, Type, Debug, Clone)]
pub struct CreatePolicyResp {
    pub id: String,
}

#[derive(Serialize, Deserialize, Type, Debug, Clone)]
pub struct AuditEvent {
    pub ts: String,
    pub token_id: String,
    pub token_label: String,
    pub upstream_id: String,
    pub method: String,
    pub path: String,
    pub decision: String,
    #[serde(default)]
    pub deny_reason: String,
    pub upstream_status: i32,
    pub status: i32,
    pub latency_ms: i64,
    pub remote_addr: String,
}
