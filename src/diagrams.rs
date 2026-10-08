use std::path::Path;
pub const ASSETS: &[(&str, &str)] = &[
    (
        "architecture-dark.svg",
        include_str!("diagram_templates/architecture-dark.svg"),
    ),
    (
        "architecture-light.svg",
        include_str!("diagram_templates/architecture-light.svg"),
    ),
    (
        "banner-dark.svg",
        include_str!("diagram_templates/banner-dark.svg"),
    ),
    (
        "banner-light.svg",
        include_str!("diagram_templates/banner-light.svg"),
    ),
    (
        "lifecycle-dark.svg",
        include_str!("diagram_templates/lifecycle-dark.svg"),
    ),
    (
        "lifecycle-light.svg",
        include_str!("diagram_templates/lifecycle-light.svg"),
    ),
    ("logo.svg", include_str!("diagram_templates/logo.svg")),
    (
        "sealed-login-dark.svg",
        include_str!("diagram_templates/sealed-login-dark.svg"),
    ),
    (
        "sealed-login-light.svg",
        include_str!("diagram_templates/sealed-login-light.svg"),
    ),
    (
        "spike-canaries-dark.svg",
        include_str!("diagram_templates/spike-canaries-dark.svg"),
    ),
    (
        "spike-canaries-light.svg",
        include_str!("diagram_templates/spike-canaries-light.svg"),
    ),
    (
        "spike-egress-dark.svg",
        include_str!("diagram_templates/spike-egress-dark.svg"),
    ),
    (
        "spike-egress-light.svg",
        include_str!("diagram_templates/spike-egress-light.svg"),
    ),
];
// Compile-time SVG templates preserve the original geometry and both theme palettes.
// Only known generated files are replaced; unlike the prototype this never recursively deletes assets/.
pub fn generate(out: &Path) -> std::io::Result<Vec<String>> {
    std::fs::create_dir_all(out)?;
    let mut written = Vec::new();
    for (name, svg) in ASSETS {
        std::fs::write(out.join(name), svg)?;
        written.push((*name).to_owned());
    }
    Ok(written)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn regenerates_thirteen_svg_assets_without_touching_other_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("unrelated.txt"), "keep").unwrap();
        let files = generate(dir.path()).unwrap();
        assert_eq!(files.len(), 13);
        assert_eq!(
            std::fs::read_to_string(dir.path().join("unrelated.txt")).unwrap(),
            "keep"
        );
        for name in files {
            let svg = std::fs::read_to_string(dir.path().join(name)).unwrap();
            assert!(svg.starts_with("<svg "));
            assert!(svg.contains("role=\"img\""));
            assert!(svg.ends_with("</svg>\n"));
        }
        assert!(
            std::fs::read_to_string(dir.path().join("architecture-dark.svg"))
                .unwrap()
                .contains("#0d1117")
        );
        assert!(
            std::fs::read_to_string(dir.path().join("architecture-light.svg"))
                .unwrap()
                .contains("#ffffff")
        );
    }
}
