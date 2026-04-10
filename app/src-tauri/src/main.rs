// Windows release builds must not open a terminal alongside the app.
// macOS does not care but the attribute is harmless. Kept on even in
// debug builds so there is only one build configuration path to audit.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    unovault_app::run();
}
