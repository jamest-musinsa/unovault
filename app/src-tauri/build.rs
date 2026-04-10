//! Tauri build script. Emits the `tauri.conf.json`-driven scaffolding
//! so the macros in `tauri::command` can wire into the runtime at
//! compile time. Required by Tauri v2 — do not delete.

fn main() {
    tauri_build::build();
}
