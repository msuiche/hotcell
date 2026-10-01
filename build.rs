fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        // The injected agent observes the renderer's completion handshake.
        println!("cargo:rustc-link-arg-bin=hotcell=-Wl,-export_dynamic");
    }
}
