//! The request gate. Every request the agent's page makes after login passes four layers:
//! hard rules (URL allowlist, method mode), fixed patterns, an optional classifier, and the
//! owner. Only the hard rules can permit; every later layer can only escalate to the owner.
use super::*;
use std::{future::Future, pin::Pin, time::Duration};

pub type Boxed<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// What the classifier and the owner see about one request. The broker builds it from the
/// method, the URL's shape and form field names. It never carries values or the agent's words.
#[derive(Clone, Debug, Default)]
pub struct Summary {
    pub method: String,
    pub origin: String,
    /// Path with numeric and high-entropy segments replaced by `:id`.
    pub path: String,
    /// Query parameter names only.
    pub query: Vec<String>,
    /// Form or JSON body field names only.
    pub fields: Vec<String>,
    /// Label of the element the agent last clicked, as the agent saw it (after masking).
    pub clicked: String,
    /// Page title, as the agent saw it (after masking).
    pub title: String,
    /// CDP resource type: Document, XHR, Fetch, ...
    pub kind: String,
}
impl Summary {
    pub fn from_request(req: &Value, kind: &str, clicked: &str, title: &str) -> Option<Self> {
        let u = Url::parse(text(&req["url"])).ok()?;
        let path = u
            .path()
            .split('/')
            .map(|seg| {
                if !seg.is_empty() && (seg.bytes().all(|b| b.is_ascii_digit()) || above_floor(seg))
                {
                    ":id"
                } else {
                    seg
                }
            })
            .collect::<Vec<_>>()
            .join("/");
        Some(Self {
            method: text(&req["method"]).into(),
            origin: u.origin().ascii_serialization(),
            path,
            query: u.query_pairs().map(|(k, _)| shape(&k)).collect(),
            fields: field_names(text(&req["postData"]))
                .iter()
                .map(|f| shape(f))
                .collect(),
            clicked: clip(clicked),
            title: clip(title),
            kind: kind.into(),
        })
    }
    pub fn to_json(&self) -> Value {
        json!({
            "method": self.method,
            "origin": self.origin,
            "path": self.path,
            "query_names": self.query,
            "field_names": self.fields,
            "clicked_label": self.clicked,
            "page_title": self.title,
            "resource_type": self.kind,
        })
    }
    fn safe_method(&self) -> bool {
        ["GET", "HEAD"].contains(&self.method.as_str())
    }
}
/// Some sites put ids or tokens in parameter names (`answer[aB3dE5fG7hJ9kL1m]`). Those runs
/// become `:id` so a name cannot carry a secret to the classifier.
fn shape(name: &str) -> String {
    static RUN: std::sync::LazyLock<regex::Regex> =
        std::sync::LazyLock::new(|| regex::Regex::new("[A-Za-z0-9]{12,}").unwrap());
    RUN.replace_all(name, |c: &regex::Captures| {
        if above_floor(&c[0]) {
            ":id".to_owned()
        } else {
            c[0].to_owned()
        }
    })
    .into_owned()
}
fn clip(s: &str) -> String {
    s.chars().take(80).collect()
}
fn field_names(body: &str) -> Vec<String> {
    if let Ok(Value::Object(o)) = serde_json::from_str::<Value>(body) {
        return o.keys().cloned().collect();
    }
    let mut names: Vec<String> = url::form_urlencoded::parse(body.as_bytes())
        .map(|(k, _)| k.into_owned())
        .collect();
    names.dedup();
    names
}

/// A second opinion on a request. `Ok(true)` sends it to the owner. There is no way to say
/// "allow": a classifier fooled by page text can only fail to raise an alarm.
pub trait Classifier: Send + Sync {
    fn escalate<'a>(&'a self, s: &'a Summary) -> Boxed<'a, Result<bool>>;
}
/// Asks the owner, out of the agent's reach. `reason` is a fixed code, never page text.
pub trait Approver: Send + Sync {
    fn approve<'a>(&'a self, s: &'a Summary, reason: &'a str) -> Boxed<'a, bool>;
}
#[derive(Clone, Default)]
pub struct Gate {
    pub classifier: Option<Arc<dyn Classifier>>,
    pub approver: Option<Arc<dyn Approver>>,
    pub classifier_timeout: Option<Duration>,
}

pub struct Ruling {
    pub permit: bool,
    /// Refusal code returned to the agent, if any.
    pub code: Option<&'static str>,
    /// Which layer escalated, for the audit log.
    pub reason: Option<&'static str>,
}

/// Requests the classifier and patterns look at. Images, scripts, fonts and styles are left
/// to the hard rules: they are page-originated and far too many to send anywhere.
fn gated(s: &Summary) -> bool {
    matches!(s.kind.as_str(), "Document" | "XHR" | "Fetch" | "Other") || !s.safe_method()
}

impl Gate {
    /// `allowed` is the hard-rule verdict. Nothing below can turn a forbid into a permit.
    pub async fn rule(&self, s: &Summary, allowed: bool) -> Ruling {
        if !allowed {
            return Ruling {
                permit: false,
                code: Some("denied_by_policy"),
                reason: None,
            };
        }
        if !gated(s) {
            return Ruling {
                permit: true,
                code: None,
                reason: None,
            };
        }
        let mut reason = pattern(s);
        if reason.is_none()
            && let Some(c) = &self.classifier
            && (s.kind == "Document" || !s.safe_method())
        {
            let limit = self.classifier_timeout.unwrap_or(Duration::from_secs(4));
            reason = match tokio::time::timeout(limit, c.escalate(s)).await {
                Ok(Ok(false)) => None,
                Ok(Ok(true)) => Some("classifier"),
                // An unreachable classifier asks the owner rather than waving requests through.
                _ => Some("classifier_unavailable"),
            };
        }
        let Some(reason) = reason else {
            return Ruling {
                permit: true,
                code: None,
                reason: None,
            };
        };
        let approved = match &self.approver {
            Some(a) => a.approve(s, reason).await,
            None => false,
        };
        Ruling {
            permit: approved,
            code: (!approved).then_some("needs_owner"),
            reason: Some(reason),
        }
    }
}

const CREDENTIAL: &[&str] = &[
    "token",
    "apikey",
    "key",
    "ssh",
    "gpg",
    "application",
    "secret",
    "credential",
    "pat",
];
const AUTHORIZATION: &[&str] = &[
    "oauth",
    "authorize",
    "authorization",
    "consent",
    "grant",
    "device",
    "activate",
];
const ACCOUNT: &[&str] = &[
    "security", "password", "passwd", "2fa", "mfa", "totp", "factor", "recovery", "backup",
    "account", "email", "sudo",
];
const EGRESS: &[&str] = &[
    "export",
    "forward",
    "forwarding",
    "webhook",
    "hook",
    "integration",
    "invite",
    "invitation",
    "collaborator",
    "member",
    "transfer",
    "share",
];
const DESTRUCTIVE: &[&str] = &["delete", "destroy", "remove", "revoke", "deactivate"];
const FIELDS: &[&str] = &[
    "password",
    "passwd",
    "otp",
    "totp",
    "scope",
    "scopes",
    "client_id",
    "redirect_uri",
    "user_code",
    "public_key",
    "webhook",
    "email",
    "recovery",
];
const QUERY: &[&str] = &[
    "client_id",
    "redirect_uri",
    "response_type",
    "user_code",
    "scope",
];
const LABELS: &[&str] = &[
    "generate",
    "token",
    "key",
    "authorize",
    "allow",
    "approve",
    "grant",
    "confirm",
    "delete",
    "remove",
    "revoke",
    "export",
    "forward",
    "invite",
    "transfer",
    "verify",
];

/// Lowercase alphanumeric words, with a plural `s` dropped: "/api-keys" -> ["api", "key"].
fn words(s: &str) -> Vec<String> {
    s.split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|w| !w.is_empty())
        .map(|w| {
            let w = w.to_ascii_lowercase();
            match w.strip_suffix('s') {
                Some(stem) if stem.len() >= 3 && !w.ends_with("ss") => stem.to_owned(),
                _ => w,
            }
        })
        .collect()
}
/// The pattern category a path falls into, if any.
pub fn path_category(path: &str) -> Option<&'static str> {
    let w = words(path);
    let hit = |list: &[&str]| w.iter().any(|x| list.contains(&x.as_str()));
    [
        ("credential", CREDENTIAL),
        ("authorization", AUTHORIZATION),
        ("account_security", ACCOUNT),
        ("data_egress", EGRESS),
        ("destructive", DESTRUCTIVE),
    ]
    .into_iter()
    .find(|(_, list)| hit(list))
    .map(|(name, _)| name)
}
/// Layer 2: fixed patterns that need no model.
pub fn pattern(s: &Summary) -> Option<&'static str> {
    if let Some(category) = path_category(&s.path) {
        return Some(category);
    }
    // "new_password" and "user[email]" count through their words; "client_id" by full name.
    let named = |names: &[String], list: &[&str]| {
        names.iter().any(|n| {
            list.contains(&n.to_ascii_lowercase().as_str())
                || words(n).iter().any(|w| list.contains(&w.as_str()))
        })
    };
    if named(&s.fields, FIELDS) {
        return Some("sensitive_field");
    }
    if named(&s.query, QUERY) {
        return Some("authorization");
    }
    // Labels belong to the page, so they only matter for what the agent itself triggered.
    if s.kind == "Document"
        && words(&s.clicked)
            .iter()
            .any(|w| LABELS.contains(&w.as_str()))
    {
        return Some("sensitive_action");
    }
    None
}

/// Indexes of observation fields that show a credential the site just made. On pages in the
/// credential, authorization or account-security categories, any long high-entropy run is
/// withheld: a new API token or recovery code is unknown to the matcher, so it has to be caught
/// by shape.
pub fn minted(path: &str, fields: &[String]) -> BTreeSet<usize> {
    if !matches!(
        path_category(path),
        Some("credential" | "authorization" | "account_security")
    ) {
        return BTreeSet::new();
    }
    static RUN: std::sync::LazyLock<regex::Regex> =
        std::sync::LazyLock::new(|| regex::Regex::new(r"[A-Za-z0-9_\-+/=.]{20,}").unwrap());
    fields
        .iter()
        .enumerate()
        .filter(|(_, f)| RUN.find_iter(f).any(|m| above_floor(m.as_str())))
        .map(|(i, _)| i)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Fixed(bool);
    impl Classifier for Fixed {
        fn escalate<'a>(&'a self, _: &'a Summary) -> Boxed<'a, Result<bool>> {
            Box::pin(async move { Ok(self.0) })
        }
    }
    struct Owner(bool);
    impl Approver for Owner {
        fn approve<'a>(&'a self, _: &'a Summary, _: &'a str) -> Boxed<'a, bool> {
            Box::pin(async move { self.0 })
        }
    }
    struct Hang;
    impl Classifier for Hang {
        fn escalate<'a>(&'a self, _: &'a Summary) -> Boxed<'a, Result<bool>> {
            Box::pin(std::future::pending())
        }
    }
    fn summary(method: &str, url: &str, body: &str, clicked: &str) -> Summary {
        Summary::from_request(
            &json!({"method": method, "url": url, "postData": body}),
            "Document",
            clicked,
            "Settings",
        )
        .unwrap()
    }
    #[test]
    fn summary_keeps_names_and_drops_values() {
        let s = summary(
            "POST",
            "https://git.test/user/12345/repo/aB3dE5fG7hJ9kL1m?tab=keys&q=secretvalue",
            "title=laptop&content=ssh-ed25519+AAAAC3Nza",
            "Add key",
        );
        assert_eq!(s.path, "/user/:id/repo/:id");
        assert_eq!(s.query, ["tab", "q"]);
        assert_eq!(s.fields, ["title", "content"]);
        assert!(!s.to_json().to_string().contains("secretvalue"));
        assert!(!s.to_json().to_string().contains("AAAAC3"));
        let n = summary(
            "POST",
            "https://x.test/f?k9XmQ2vL7pR4wZ8t=1",
            "answer[aB3dE5fG7hJ9kL1m]=x&new_password=y",
            "",
        );
        assert_eq!(n.query, [":id"]);
        assert_eq!(n.fields, ["answer[:id]", "new_password"]);
        let j = summary(
            "POST",
            "https://x.test/api",
            r#"{"note":"n","scopes":["repo"]}"#,
            "",
        );
        assert_eq!(j.fields, ["note", "scopes"]);
    }
    #[test]
    fn patterns_catch_credential_and_account_pages() {
        for (url, body, label, want) in [
            (
                "https://g.test/user/settings/applications",
                "",
                "",
                "credential",
            ),
            ("https://g.test/settings/tokens/new", "", "", "credential"),
            ("https://g.test/settings/api-keys", "", "", "credential"),
            ("https://g.test/login/device", "", "", "authorization"),
            (
                "https://g.test/login/oauth/authorize?client_id=1",
                "",
                "",
                "authorization",
            ),
            (
                "https://g.test/settings/security",
                "",
                "",
                "account_security",
            ),
            ("https://g.test/settings/emails", "", "", "account_security"),
            ("https://m.test/settings/forwarding", "", "", "data_egress"),
            ("https://g.test/repo/webhooks", "", "", "data_egress"),
            ("https://g.test/project/42/delete", "", "", "destructive"),
            (
                "https://g.test/profile",
                "name=a&new_password=b",
                "",
                "sensitive_field",
            ),
            ("https://g.test/cb?redirect_uri=x", "", "", "authorization"),
            (
                "https://g.test/mutate",
                "",
                "Confirm email",
                "sensitive_action",
            ),
        ] {
            let method = if body.is_empty() { "GET" } else { "POST" };
            assert_eq!(
                pattern(&summary(method, url, body, label)),
                Some(want),
                "{url}"
            );
        }
        for url in [
            "https://g.test/invoices",
            "https://g.test/search?q=tokens",
            "https://g.test/explore/repos",
            "https://g.test/tokenizer-docs",
            "https://g.test/address",
        ] {
            assert_eq!(
                pattern(&summary("GET", url, "", "Next page")),
                None,
                "{url}"
            );
        }
    }
    #[tokio::test]
    async fn later_layers_only_escalate() {
        let s = summary("GET", "https://g.test/invoices", "", "Invoices");
        let fooled = Gate {
            classifier: Some(Arc::new(Fixed(false))),
            ..Default::default()
        };
        // A classifier saying "fine" cannot rescue a hard-rule forbid.
        assert!(!fooled.rule(&s, false).await.permit);
        let risky = summary("GET", "https://g.test/settings/tokens", "", "");
        // Nor a pattern hit.
        let r = fooled.rule(&risky, true).await;
        assert!(!r.permit);
        assert_eq!(r.code, Some("needs_owner"));
        assert_eq!(r.reason, Some("credential"));
        // An alarmed classifier sends a pattern-clean request to the owner.
        let alarmed = Gate {
            classifier: Some(Arc::new(Fixed(true))),
            ..Default::default()
        };
        assert_eq!(alarmed.rule(&s, true).await.reason, Some("classifier"));
        assert!(!alarmed.rule(&s, true).await.permit);
        // The owner can approve what was escalated.
        let owner = Gate {
            classifier: Some(Arc::new(Fixed(true))),
            approver: Some(Arc::new(Owner(true))),
            ..Default::default()
        };
        assert!(owner.rule(&s, true).await.permit);
        // Nothing to escalate: permitted without asking.
        assert!(fooled.rule(&s, true).await.permit);
    }
    #[tokio::test]
    async fn classifier_timeout_asks_the_owner() {
        let g = Gate {
            classifier: Some(Arc::new(Hang)),
            classifier_timeout: Some(Duration::from_millis(20)),
            ..Default::default()
        };
        let r = g
            .rule(&summary("GET", "https://g.test/invoices", "", ""), true)
            .await;
        assert_eq!(
            (r.permit, r.reason),
            (false, Some("classifier_unavailable"))
        );
    }
    #[test]
    fn minted_tokens_are_withheld_on_credential_pages_only() {
        let fields = vec![
            "Your new API token: ghp_8fK2mQ9xLr4TzW7vN1bC3dE5".to_owned(),
            "Back".to_owned(),
        ];
        assert_eq!(minted("/settings/tokens", &fields), BTreeSet::from([0]));
        assert!(minted("/invoices", &fields).is_empty());
        assert!(
            minted(
                "/settings/tokens",
                &["darkmode-enabled-for-all-users".into()]
            )
            .is_empty()
        );
    }
}
