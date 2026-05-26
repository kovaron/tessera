use crate::error::AppError;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{Method, Request, StatusCode};
use hyper_util::client::legacy::Client;
use hyperlocal::{UnixClientExt, Uri as UnixUri};
use serde::{de::DeserializeOwned, Serialize};

pub struct SocketClient {
    socket_path: String,
    client: Client<hyperlocal::UnixConnector, Full<Bytes>>,
}

impl SocketClient {
    pub fn new(socket_path: impl Into<String>) -> Self {
        Self {
            socket_path: socket_path.into(),
            client: Client::unix(),
        }
    }

    async fn request<T: Serialize, R: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<&T>,
    ) -> Result<Option<R>, AppError> {
        let uri: hyper::Uri = UnixUri::new(&self.socket_path, path).into();
        let body_bytes = match body {
            Some(b) => Full::new(Bytes::from(serde_json::to_vec(b)?)),
            None => Full::new(Bytes::new()),
        };
        let req = Request::builder()
            .method(method)
            .uri(uri)
            .header("Content-Type", "application/json")
            .body(body_bytes)
            .map_err(|e| AppError::Http(e.to_string()))?;
        let resp = self
            .client
            .request(req)
            .await
            .map_err(|e| AppError::Hyper(e.to_string()))?;

        let status = resp.status();
        let bytes = resp
            .into_body()
            .collect()
            .await
            .map_err(|e| AppError::Hyper(e.to_string()))?
            .to_bytes();

        if status == StatusCode::NO_CONTENT {
            return Ok(None);
        }
        if !status.is_success() {
            return Err(AppError::Status(
                status.as_u16(),
                String::from_utf8_lossy(&bytes).into_owned(),
            ));
        }
        if bytes.is_empty() {
            return Ok(None);
        }
        Ok(Some(serde_json::from_slice(&bytes)?))
    }

    pub async fn get<R: DeserializeOwned>(&self, path: &str) -> Result<R, AppError> {
        self.request::<(), R>(Method::GET, path, None)
            .await?
            .ok_or(AppError::NotFound)
    }

    pub async fn post<T: Serialize, R: DeserializeOwned>(
        &self,
        path: &str,
        body: &T,
    ) -> Result<R, AppError> {
        self.request::<T, R>(Method::POST, path, Some(body))
            .await?
            .ok_or(AppError::NotFound)
    }

    pub async fn post_no_body<T: Serialize>(&self, path: &str, body: &T) -> Result<(), AppError> {
        self.request::<T, serde_json::Value>(Method::POST, path, Some(body))
            .await
            .map(|_| ())
    }

    pub async fn delete(&self, path: &str) -> Result<(), AppError> {
        self.request::<(), serde_json::Value>(Method::DELETE, path, None)
            .await
            .map(|_| ())
    }
}

pub fn default_socket_path() -> String {
    if let Some(home) = dirs::home_dir() {
        home.join(".tessera").join("admin.sock")
            .to_string_lossy()
            .into_owned()
    } else {
        "/tmp/tessera-admin.sock".into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::Full;
    use hyper::body::Bytes;
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper::{Request, Response};
    use std::convert::Infallible;
    use tempfile::TempDir;
    use tokio::net::UnixListener;

    async fn handle(req: Request<hyper::body::Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
        let body = if req.uri().path() == "/v1/status" {
            r#"{"locked":false,"version":"test"}"#
        } else {
            "{}"
        };
        Ok(Response::new(Full::new(Bytes::from(body))))
    }

    #[tokio::test]
    async fn status_round_trip() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("a.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let path_str = path.to_string_lossy().into_owned();

        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let io = hyper_util::rt::TokioIo::new(stream);
            http1::Builder::new()
                .serve_connection(io, service_fn(handle))
                .await
                .ok();
        });

        let client = SocketClient::new(path_str);
        let status: crate::types::Status = client.get("/v1/status").await.unwrap();
        assert!(!status.locked);
        assert_eq!(status.version, "test");
    }
}
