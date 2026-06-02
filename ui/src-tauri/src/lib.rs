mod audit;
mod clipboard;
mod commands;
mod error;
mod keychain;
mod socket;
mod types;

use commands::AppState;
use tokio::sync::RwLock;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_fs::init())
        .manage(AppState {
            socket: RwLock::new(socket::default_socket_path()),
            audit_path: RwLock::new(default_audit_path()),
        })
        .invoke_handler(tauri::generate_handler![
            commands::status::get_status,
            commands::status::unlock,
            commands::status::lock,
            commands::upstreams::list_upstreams,
            commands::upstreams::upsert_upstream,
            commands::upstreams::delete_upstream,
            commands::policies::create_policy,
            commands::policies::list_policies,
            commands::policies::get_policy,
            commands::policies::update_policy,
            commands::policies::delete_policy,
            commands::tokens::list_tokens,
            commands::tokens::mint_token,
            commands::tokens::revoke_token,
            commands::tokens::attenuate_token,
            commands::bootstrap::detect_state,
            commands::bootstrap::run_bootstrap,
            keychain::keychain_save,
            keychain::keychain_save_with_biometry,
            keychain::keychain_load,
            keychain::keychain_delete,
            keychain::biometry_available,
            keychain::biometry_authenticate,
            clipboard::clipboard_set_with_clear,
        ])
        .setup(|app| {
            let handle = app.handle().clone();
            let path = default_audit_log_path();
            audit::start_tailer(handle, path);
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

fn default_audit_path() -> String {
    default_audit_log_path().to_string_lossy().into_owned()
}

fn default_audit_log_path() -> std::path::PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("/tmp"))
        .join(".tessera")
        .join("audit.log")
}
