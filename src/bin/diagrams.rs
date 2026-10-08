fn main() -> std::io::Result<()> {
    let out = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("assets");
    let written = blindfold::diagrams::generate(&out)?;
    println!("wrote {} files", written.len());
    Ok(())
}
