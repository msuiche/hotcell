# Frida bindings used by hotcell

These are the `frida-sys` 0.17.2 Rust bindings from
<https://github.com/frida/frida-rust>, under the upstream wxWindows license.
Original copyright notices are retained in the source files.

Local changes:

- Pin `FRIDA_VERSION` to 17.19.0, matching hotcell's qualified native runtime.
  The published 0.17.2 crate pins 17.9.5, which failed the malformed-input live
  regression on this macOS host.
- Omit the old documentation-only header; generated bindings use the downloaded
  devkit's matching header.
- Limit generated declarations to Frida and GLib, excluding unrelated libc
  declarations from the devkit's umbrella header.
- Re-export the namespaced GLib cancellation, event-loop, and cleanup functions
  used by hotcell on Linux.

No Frida native binaries are stored here. The upstream `frida-build` build helper
downloads the pinned platform devkit during the first build. Replace this local
crate with an upstream release once it pins a qualified version.
