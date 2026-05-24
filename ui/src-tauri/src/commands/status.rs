use crate::{commands::AppState, error::AppError, types::Status};
use tauri::State;

#[tauri::command]
#[specta::specta]
pub async fn get_status(state: State<'_, AppState>) -> Result<Status, AppError> {
    let path = state.socket.read().await.clone();
    let c = crate::socket::SocketClient::new(path);
    c.get("/v1/status").await
}

#[derive(serde::Serialize)]
struct UnlockBody<'a> {
    passphrase: &'a str,
}

#[tauri::command]
#[specta::specta]
pub async fn unlock(state: State<'_, AppState>, passphrase: String) -> Result<(), AppError> {
    let path = state.socket.read().await.clone();
    let c = crate::socket::SocketClient::new(path);
    c.post_no_body("/v1/unlock", &UnlockBody { passphrase: &passphrase }).await
}

#[tauri::command]
#[specta::specta]
pub async fn lock(state: State<'_, AppState>) -> Result<(), AppError> {
    let path = state.socket.read().await.clone();
    let c = crate::socket::SocketClient::new(path);
    c.post_no_body::<serde_json::Value>("/v1/lock", &serde_json::Value::Null).await
}
