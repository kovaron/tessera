use crate::{commands::AppState, error::AppError, types::{CreatePolicyReq, CreatePolicyResp, Policy}};
use tauri::State;

#[tauri::command]
#[specta::specta]
pub async fn create_policy(state: State<'_, AppState>, req: CreatePolicyReq) -> Result<CreatePolicyResp, AppError> {
    let path = state.socket.read().await.clone();
    let c = crate::socket::SocketClient::new(path);
    c.post("/v1/policies", &req).await
}

#[tauri::command]
#[specta::specta]
pub async fn list_policies(state: State<'_, AppState>) -> Result<Vec<Policy>, AppError> {
    let path = state.socket.read().await.clone();
    let c = crate::socket::SocketClient::new(path);
    c.get("/v1/policies").await
}

#[tauri::command]
#[specta::specta]
pub async fn get_policy(state: State<'_, AppState>, id: String) -> Result<Policy, AppError> {
    let path = state.socket.read().await.clone();
    let c = crate::socket::SocketClient::new(path);
    c.get(&format!("/v1/policies/{}", id)).await
}

#[tauri::command]
#[specta::specta]
pub async fn update_policy(state: State<'_, AppState>, id: String, req: CreatePolicyReq) -> Result<(), AppError> {
    let path = state.socket.read().await.clone();
    let c = crate::socket::SocketClient::new(path);
    c.put(&format!("/v1/policies/{}", id), &req).await
}

#[tauri::command]
#[specta::specta]
pub async fn delete_policy(state: State<'_, AppState>, id: String) -> Result<(), AppError> {
    let path = state.socket.read().await.clone();
    let c = crate::socket::SocketClient::new(path);
    c.delete(&format!("/v1/policies/{}", id)).await
}
