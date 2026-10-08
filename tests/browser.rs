use blindfold::{
    broker::{Broker, Credential},
    fixture::{Attacker, Fixture, GOOD, Proxy, USER},
};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires CHROME; runs only throwaway localhost browser"]
async fn classic_login_unseals_after_fresh_tab_swap() {
    let a = Attacker::start().unwrap();
    let f = Fixture::start(a.origin()).unwrap();
    let proxy = Proxy::start(BTreeSet::from([f.host()])).unwrap();
    let b = Broker::new(
        std::env::var("CHROME").unwrap(),
        BTreeMap::from([(
            "classic".into(),
            Credential {
                username: USER.into(),
                password: GOOD.into(),
                login_url: format!("{}/login", f.origin()),
                post_login_url: format!("{}/app", f.origin()),
                success: json!({"path":"/app"}),
                user_sel: None,
                pass_sel: None,
            },
        )]),
        BTreeSet::from([f.host()]),
        Some(proxy.server.port),
    );
    let opened = b
        .handle("session.open", json!({"credential_id":"classic"}))
        .await;
    assert_eq!(
        b.handle("session.observe", json!({"session":opened["session"]}))
            .await["error"]["code"],
        "session_sealed"
    );
    let mut status = json!({});
    for _ in 0..80 {
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        status = b
            .handle("session.status", json!({"session":opened["session"]}))
            .await;
        if !["opening", "sealed"].contains(&status["state"].as_str().unwrap_or("")) {
            break;
        }
    }
    assert_eq!(
        status["state"],
        "active",
        "status={status}, errors={:?}",
        b.diag.lock().unwrap().errors
    );
    let obs = b
        .handle("session.observe", json!({"session":opened["session"]}))
        .await;
    let invoice = obs["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["role"] == "link" && i["name"] == "Invoices")
        .unwrap();
    let clicked=b.handle("session.act",json!({"session":opened["session"],"snapshot":obs["snapshot"],"ref":invoice["ref"],"action":"click"})).await;
    let after = b
        .handle("session.observe", json!({"session":opened["session"]}))
        .await;
    b.shutdown();
    assert_eq!(clicked["ok"], true, "{clicked}");
    assert!(after.to_string().contains("INV-1002"));
    assert!(
        obs["items"].as_array().is_some_and(|items| items
            .iter()
            .any(|i| i["role"] == "heading" && i["name"] == "Dashboard")),
        "{obs}"
    );
}
