use serde::Serialize;
use specta::Type;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("http: {0}")]
    Http(String),
    #[error("serde: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("hyper: {0}")]
    Hyper(String),
    #[error("status {0}: {1}")]
    Status(u16, String),
    #[error("not found")]
    NotFound,
    #[error("locked")]
    Locked,
}

impl Serialize for AppError {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&self.to_string())
    }
}

#[derive(Serialize, Type)]
pub struct ErrorMessage {
    pub message: String,
}
