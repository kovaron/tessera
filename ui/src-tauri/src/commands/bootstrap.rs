use crate::error::AppError;
use std::path::PathBuf;
use std::process::Stdio;
use tauri_plugin_shell::ShellExt;
use tokio::io::AsyncWriteExt;

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
    let mut child = sidecar
        .args(["bootstrap", "--db", &db])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| AppError::Http(e.to_string()))?;
    if let Some(mut stdin) = child.stdin.take() {
        let payload = format!("{0}\n{0}\n", passphrase);
        stdin.write_all(payload.as_bytes()).await?;
    }
    let out = child.wait_with_output().await?;
    if !out.status.success() {
        return Err(AppError::Http(format!(
            "proxyctl bootstrap failed: {}",
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    Ok(())
}
