//! CURLPRO_LIBRARY=../../dist/curlpro.dll CURLPRO_PROFILES=../../profiles cargo run --example basic
use std::io::Read;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("libcurlpro {}", curlpro::version()?);
    let s = curlpro::Session::new("chrome-156-windows")?;
    println!("ja4 offline:   {}", s.fingerprint("https://tls.peet.ws/")?["ja4"]);

    let r = s.get("https://tls.peet.ws/api/clean")?;
    let seen: serde_json::Value = r.json()?;
    println!("{} {} {}", r.status, r.proto, r.url);
    println!("ja4 by server: {}", seen["ja4"]);

    let mut st = s.stream(&curlpro::Request::get("https://example.com/"))?;
    let mut body = Vec::new();
    st.read_to_end(&mut body)?;
    println!("stream: {} {}, {} bytes", st.head.status, st.head.proto, body.len());

    match curlpro::Session::new("no-such-browser") {
        Err(e) => println!("error code: {:?}, permanent: {}", e.code, e.permanent()),
        Ok(_) => println!("unexpected"),
    }
    Ok(())
}
