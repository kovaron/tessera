use crate::error::AppError;
use std::path::PathBuf;
use tauri_plugin_shell::process::CommandEvent;
use tauri_plugin_shell::ShellExt;

#[derive(serde::Serialize, specta::Type)]
pub struct DetectResult {
    pub db_exists: bool,
    pub socket_exists: bool,
}

fn home() -> PathBuf {
    dirs::home_dir().unwrap_or_else(|| PathBuf::from("/tmp"))
}

fn default_db() -> PathBuf {
    home().join(".proxyd").join("data.db")
}

fn default_sock() -> PathBuf {
    home().join(".proxyd").join("admin.sock")
}

#[tauri::command]
#[specta::specta]
pub async fn detect_state() -> Result<DetectResult, AppError> {
    Ok(DetectResult {
        db_exists: default_db().exists(),
        socket_exists: default_sock().exists(),
    })
}

#[tauri::command]
#[specta::specta]
pub async fn run_bootstrap(
    app: tauri::AppHandle,
    passphrase: String,
    db_path: Option<String>,
) -> Result<(), AppError> {
    let db = db_path.unwrap_or_else(|| default_db().to_string_lossy().into_owned());
    let sidecar = app
        .shell()
        .sidecar("proxyctl")
        .map_err(|e| AppError::Http(e.to_string()))?;
    let (mut rx, mut child) = sidecar
        .args(["bootstrap", "--db", &db])
        .spawn()
        .map_err(|e| AppError::Http(e.to_string()))?;

    let payload = format!("{0}\n{0}\n", passphrase);
    child
        .write(payload.as_bytes())
        .map_err(|e| AppError::Http(e.to_string()))?;

    let mut stderr = Vec::new();
    let mut exit_code: Option<i32> = None;
    while let Some(event) = rx.recv().await {
        match event {
            CommandEvent::Stderr(bytes) => stderr.extend_from_slice(&bytes),
            CommandEvent::Terminated(payload) => {
                exit_code = payload.code;
                break;
            }
            _ => {}
        }
    }

    if exit_code != Some(0) {
        return Err(AppError::Http(format!(
            "proxyctl bootstrap failed (exit {:?}): {}",
            exit_code,
            String::from_utf8_lossy(&stderr)
        )));
    }
    Ok(())
}
