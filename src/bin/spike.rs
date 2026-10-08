use blindfold::harness::run_once;
#[tokio::main]
async fn main() {
    match run().await {
        Ok(false) => {}
        Ok(true) => std::process::exit(1),
        Err(e) => {
            eprintln!("{}: {}", e, e.detail.as_deref().unwrap_or_default());
            std::process::exit(2);
        }
    }
}
async fn run() -> blindfold::Result<bool> {
    let chrome = std::env::args()
        .nth(1)
        .or_else(|| std::env::var("CHROME").ok())
        .ok_or_else(|| {
            blindfold::Error::internal(
                "usage: cargo run --bin spike -- /path/to/chrome (or CHROME)",
            )
        })?;
    if !std::path::Path::new(&chrome).is_file() {
        return Err(blindfold::Error::internal("Chromium executable not found"));
    }
    let mut results = vec![];
    for proxy in [false, true] {
        let report = run_once(&chrome, proxy).await?;
        println!(
            "\n=== run: request interception {} ===",
            if proxy { "+ egress proxy" } else { "only" }
        );
        for c in report["checks"].as_array().unwrap() {
            println!(
                "{}  {}{}",
                if c["pass"] == true { "PASS" } else { "FAIL" },
                c["name"].as_str().unwrap(),
                if c["pass"] == true {
                    String::new()
                } else {
                    format!("  {}", c["detail"])
                }
            );
        }
        println!(
            "canaries scanned: {}, tap bytes: {}, leaks: {}",
            report["canariesScanned"],
            report["tapBytes"],
            report["leaks"].as_array().unwrap().len()
        );
        for key in [
            "notClaimed",
            "egress",
            "falseTrips",
            "axProbe",
            "brokerErrors",
        ] {
            println!("{key}: {}", report[key]);
        }
        results.push(report);
    }
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("spike/results-rust.json");
    std::fs::write(
        path,
        serde_json::to_vec_pretty(&results)
            .map_err(|e| blindfold::Error::internal(e.to_string()))?,
    )
    .map_err(|e| blindfold::Error::internal(e.to_string()))?;
    let failed = results.iter().any(|r| {
        !r["leaks"].as_array().unwrap().is_empty()
            || r["checks"]
                .as_array()
                .unwrap()
                .iter()
                .any(|c| c["pass"] != true)
    });
    println!("\nRESULT: {}", if failed { "FAIL" } else { "PASS" });
    Ok(failed)
}
