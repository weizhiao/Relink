#[path = "common/mod.rs"]
mod fixture_support;

fn main() {
    match std::env::args().nth(1).as_deref() {
        Some("exec-a") => {
            let exec = fixture_support::ensure_exec_a();
            println!("{}", exec.display());
        }
        _ => {
            let fixtures = fixture_support::ensure_all();
            println!("{}", fixtures.exec_a.display());
        }
    }
}
