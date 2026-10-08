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
pub mod broker;
pub mod cdp;
pub mod diagrams;
pub mod fixture;
pub mod harness;
pub mod http;
pub mod secrets;
