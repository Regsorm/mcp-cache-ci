fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let mut res = winresource::WindowsResource::new();
        res.set("FileDescription", "MCP Cache CI Proxy");
        res.set("ProductName", "MCP Cache CI");
        res.set("CompanyName", "Regsorm");
        res.set("LegalCopyright", "Copyright (C) 2026 Regsorm");
        res.set("OriginalFilename", "mcp-cache-ci.exe");
        res.set("InternalName", "mcp-cache-ci.exe");
        res.compile().expect("failed to embed Windows resources for mcp-cache-ci");
    }
}
