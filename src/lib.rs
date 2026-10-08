#[derive(Debug)]
pub struct Error {
    pub code: &'static str,
    pub detail: Option<String>,
}
impl Error {
    pub fn policy(code: &'static str) -> Self {
        Self { code, detail: None }
    }
    pub fn internal(detail: impl Into<String>) -> Self {
        Self {
            code: "internal_error",
            detail: Some(detail.into()),
        }
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.code)
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;
/// A JSON string value, or "" for anything else.
pub(crate) fn text(v: &serde_json::Value) -> &str {
    v.as_str().unwrap_or("")
}
pub(crate) async fn sleep(ms: u64) {
    tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
}
pub mod broker;
pub mod cdp;
pub mod diagrams;
pub mod fixture;
pub mod harness;
pub mod http;
pub mod secrets;
