use crate::error::AppError;
use tauri::AppHandle;
use tauri_plugin_clipboard_manager::ClipboardExt;

#[tauri::command]
#[specta::specta]
pub async fn clipboard_set_with_clear(
    app: AppHandle,
    value: String,
    clear_after_seconds: u64,
) -> Result<(), AppError> {
    app.clipboard()
        .write_text(value.clone())
        .map_err(|e| AppError::Http(e.to_string()))?;

    let app_handle = app.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(clear_after_seconds)).await;
        if let Ok(current) = app_handle.clipboard().read_text() {
            if current == value {
                let _ = app_handle.clipboard().write_text(String::new());
            }
        }
    });
    Ok(())
}
