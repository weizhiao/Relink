#[path = "mod.rs"]
mod fixture_support;

fn main() {
    match std::env::args().nth(1).as_deref() {
        Some("native-exec") => {
            let exec = fixture_support::ensure_native_exec();
            println!("{}", exec.display());
        }
        _ => {
            let fixtures = fixture_support::ensure_all();
            println!("{}", fixtures.native_exec.display());
        }
    }
}
