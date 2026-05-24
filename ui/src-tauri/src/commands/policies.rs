use crate::{commands::AppState, error::AppError, types::{CreatePolicyReq, CreatePolicyResp}};
use tauri::State;

#[tauri::command]
#[specta::specta]
pub async fn create_policy(state: State<'_, AppState>, req: CreatePolicyReq) -> Result<CreatePolicyResp, AppError> {
    let path = state.socket.read().await.clone();
    let c = crate::socket::SocketClient::new(path);
    c.post("/v1/policies", &req).await
}
