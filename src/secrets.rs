use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};
use std::collections::BTreeSet;

pub fn percent(secret: &str) -> String {
    secret
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}
pub fn hex(secret: &[u8]) -> String {
    secret.iter().map(|b| format!("{b:02x}")).collect()
}
pub fn variants(secret: &str) -> Vec<String> {
    let mut out = BTreeSet::from([secret.to_owned(), percent(secret), hex(secret.as_bytes())]);
    for (off, lead) in [0, 2, 3].into_iter().enumerate() {
        let mut bytes = vec![0; off];
        bytes.extend(secret.as_bytes());
        let e = STANDARD_NO_PAD.encode(&bytes);
        let tail = usize::from(bytes.len() % 3 != 0);
        if lead <= e.len() - tail {
            let v = &e[lead..e.len() - tail];
            out.insert(v.to_owned());
            out.insert(v.replace('+', "-").replace('/', "_"));
        }
    }
    out.into_iter()
        .filter(|v| v.encode_utf16().count() >= 8)
        .collect()
}
pub fn above_floor(s: &str) -> bool {
    if s.encode_utf16().count() < 12 {
        return false;
    }
    let mut counts = std::collections::HashMap::new();
    for c in s.chars() {
        *counts.entry(c).or_insert(0usize) += 1;
    }
    let n = s.encode_utf16().count() as f64;
    let entropy: f64 = counts
        .values()
        .map(|c| {
            let p = *c as f64 / n;
            -p * p.log2()
        })
        .sum();
    static MIXED: std::sync::LazyLock<regex::Regex> =
        std::sync::LazyLock::new(|| regex::Regex::new("[a-z][A-Z]|[A-Z][a-z]+[A-Z]").unwrap());
    (s.bytes().any(|b| b.is_ascii_digit()) && s.bytes().any(|b| b.is_ascii_alphabetic()))
        || MIXED.is_match(s)
        || entropy >= 4.0
}
pub fn matches(
    vault: &[String],
    secrets: &BTreeSet<String>,
    fields: &[String],
) -> Result<BTreeSet<usize>, &'static str> {
    let joined = fields.concat();
    if vault
        .iter()
        .any(|v| variants(v).iter().any(|x| joined.contains(x)))
    {
        return Err("session_killed");
    }
    let mut hit = BTreeSet::new();
    let mut starts = Vec::new();
    let mut pos = 0;
    for f in fields {
        starts.push(pos);
        pos += f.len();
    }
    for sec in secrets {
        for x in variants(sec) {
            let mut from = 0;
            while let Some(offset) = joined[from..].find(&x) {
                let i = from + offset;
                for (n, f) in fields.iter().enumerate() {
                    if starts[n] < i + x.len() && starts[n] + f.len() > i {
                        hit.insert(n);
                    }
                }
                from = i + joined[i..].chars().next().unwrap().len_utf8();
            }
        }
    }
    static TOKEN: std::sync::LazyLock<regex::Regex> =
        std::sync::LazyLock::new(|| regex::Regex::new(r"[A-Za-z0-9_\-+/=%]{12,}").unwrap());
    for (i, f) in fields.iter().enumerate() {
        for token in TOKEN.find_iter(f) {
            if secrets.iter().any(|s| s.contains(token.as_str())) {
                hit.insert(i);
            }
        }
    }
    Ok(hit)
}
pub fn leaves(v: &serde_json::Value, out: &mut Vec<String>) {
    match v {
        serde_json::Value::String(s) => {
            out.push(s.clone());
            if let Ok(j) = serde_json::from_str::<serde_json::Value>(s)
                && (j.is_object() || j.is_array())
            {
                leaves(&j, out);
            }
            static JWT: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
                regex::Regex::new(r"^[\w-]+\.[\w-]+\.[\w-]*$").unwrap()
            });
            if JWT.is_match(s) {
                out.extend(s.split('.').map(str::to_owned));
            }
        }
        serde_json::Value::Array(a) => {
            for x in a {
                leaves(x, out);
            }
        }
        serde_json::Value::Object(o) => {
            for x in o.values() {
                leaves(x, out);
            }
        }
        _ => {}
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn floor_preserves_javascript_utf16_length_for_astral_characters() {
        assert!(above_floor("a1😀😀😀😀😀"));
    }
    #[test]
    fn variants_preserve_javascript_length_floor_for_utf8() {
        assert!(!variants("éééé").contains(&"éééé".to_owned()));
        assert!(variants("éééé").contains(&"c3a9c3a9c3a9c3a9".to_owned()));
    }
    #[test]
    fn matches_across_field_boundaries_and_chunks() {
        let secrets = BTreeSet::from(["abcdefghijkl1234567890".to_owned()]);
        assert_eq!(
            matches(&[], &secrets, &["abcde".into(), "fghijkl1234567890".into()]).unwrap(),
            BTreeSet::from([0, 1])
        );
        assert_eq!(
            matches(&[], &secrets, &["half abcdefghijkl".into()]).unwrap(),
            BTreeSet::from([0])
        );
        assert_eq!(
            matches(
                &["vaultPASSWORD1234".into()],
                &secrets,
                &["vaultPASSWORD1234".into()]
            ),
            Err("session_killed")
        );
    }
    #[test]
    fn floor_does_not_mask_plain_preferences() {
        assert!(!above_floor("darkmode-enabled"));
        assert!(above_floor("aA1223456789"));
    }
    #[test]
    fn includes_plain_percent_hex_and_base64() {
        let got = variants("abcdef1234+/?é");
        for expected in [
            "abcdef1234+/?é",
            "abcdef1234%2B%2F%3F%C3%A9",
            "616263646566313233342b2f3fc3a9",
            "YWJjZGVmMTIzNCsvP8Op",
        ] {
            assert!(got.iter().any(|x| x == expected), "missing {expected}");
        }
    }
}
