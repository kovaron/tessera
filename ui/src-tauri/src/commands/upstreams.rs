use crate::{commands::AppState, error::AppError, types::{Upstream, UpsertUpstreamReq}};
use tauri::State;

#[tauri::command]
#[specta::specta]
pub async fn list_upstreams(state: State<'_, AppState>) -> Result<Vec<Upstream>, AppError> {
    let path = state.socket.read().await.clone();
    let c = crate::socket::SocketClient::new(path);
    c.get("/v1/upstreams").await
}

#[tauri::command]
#[specta::specta]
pub async fn upsert_upstream(state: State<'_, AppState>, req: UpsertUpstreamReq) -> Result<(), AppError> {
    let path = state.socket.read().await.clone();
    let c = crate::socket::SocketClient::new(path);
    c.post_no_body("/v1/upstreams", &req).await
}

#[tauri::command]
#[specta::specta]
pub async fn delete_upstream(state: State<'_, AppState>, id: String) -> Result<(), AppError> {
    let path = state.socket.read().await.clone();
    let c = crate::socket::SocketClient::new(path);
    c.delete(&format!("/v1/upstreams/{}", id)).await
}
