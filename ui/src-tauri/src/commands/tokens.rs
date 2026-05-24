use crate::{
    commands::AppState,
    error::AppError,
    types::{AttenuateReq, MintTokenReq, MintTokenResp, Token},
};
use tauri::State;

#[tauri::command]
#[specta::specta]
pub async fn list_tokens(state: State<'_, AppState>) -> Result<Vec<Token>, AppError> {
    let path = state.socket.read().await.clone();
    let c = crate::socket::SocketClient::new(path);
    c.get("/v1/tokens").await
}

#[tauri::command]
#[specta::specta]
pub async fn mint_token(state: State<'_, AppState>, req: MintTokenReq) -> Result<MintTokenResp, AppError> {
    let path = state.socket.read().await.clone();
    let c = crate::socket::SocketClient::new(path);
    c.post("/v1/tokens", &req).await
}

#[tauri::command]
#[specta::specta]
pub async fn revoke_token(state: State<'_, AppState>, id: String) -> Result<(), AppError> {
    let path = state.socket.read().await.clone();
    let c = crate::socket::SocketClient::new(path);
    c.delete(&format!("/v1/tokens/{}", id)).await
}

#[derive(serde::Serialize)]
struct AttenuateBody<'a> {
    label: &'a str,
    policy_id: &'a str,
    ttl_seconds: i64,
}

#[tauri::command]
#[specta::specta]
pub async fn attenuate_token(
    state: State<'_, AppState>,
    req: AttenuateReq,
) -> Result<MintTokenResp, AppError> {
    use http_body_util::{BodyExt, Full};
    use hyper::body::Bytes;
    use hyper::{Method, Request};
    use hyper_util::client::legacy::Client;
    use hyperlocal::{UnixClientExt, Uri as UnixUri};

    let path = state.socket.read().await.clone();
    let client = Client::unix();
    let uri: hyper::Uri = UnixUri::new(&path, "/v1/tokens/attenuate").into();
    let body = AttenuateBody {
        label: &req.label,
        policy_id: &req.policy_id,
        ttl_seconds: req.ttl_seconds,
    };
    let body_bytes = Full::new(Bytes::from(serde_json::to_vec(&body)?));
    let http_req = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header("Authorization", format!("Bearer {}", req.parent_token))
        .header("Content-Type", "application/json")
        .body(body_bytes)
        .map_err(|e| AppError::Http(e.to_string()))?;
    let resp = client
        .request(http_req)
        .await
        .map_err(|e| AppError::Hyper(e.to_string()))?;
    let status = resp.status();
    let bytes = resp
        .into_body()
        .collect()
        .await
        .map_err(|e| AppError::Hyper(e.to_string()))?
        .to_bytes();
    if !status.is_success() {
        return Err(AppError::Status(
            status.as_u16(),
            String::from_utf8_lossy(&bytes).into_owned(),
        ));
    }
    Ok(serde_json::from_slice(&bytes)?)
}
