//! Prints the offline JA4 of chrome-156-windows for https://example.com/ — the
//! value scripts/bindings-agree.sh compares across every binding.
fn main() -> Result<(), curlpro::Error> {
    let s = curlpro::Session::new("chrome-156-windows")?;
    println!("{}", s.fingerprint("https://example.com/")?["ja4"].as_str().unwrap_or(""));
    Ok(())
}
