pub mod status;
pub mod upstreams;
pub mod policies;
pub mod tokens;
pub mod bootstrap;

use tokio::sync::RwLock;

pub struct AppState {
    pub socket: RwLock<String>,
    pub audit_path: RwLock<String>,
}
