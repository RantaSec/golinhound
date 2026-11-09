#![deny(unsafe_code)]

use std::ffi::CString;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::ExitCode;

use serde::Serialize;
use sudo_rs::sudoers::Sudoers;
use sudo_rs::system::{Hostname, User};

const PASSWD_FILE: &str = "/etc/passwd";
const SUDOERS_FILE: &str = "/etc/sudoers";

#[derive(Serialize)]
struct PolicyDump<'a> {
    username: &'a str,
    commands: Vec<String>,
}

fn read_passwd_usernames(path: &Path) -> Result<Vec<String>, String> {
    let file = File::open(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let mut names = Vec::new();
    for line in BufReader::new(file).lines() {
        let line = line.map_err(|e| format!("reading {}: {e}", path.display()))?;
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((name, _)) = line.split_once(':') {
            if !name.is_empty() {
                names.push(name.to_owned());
            }
        }
    }
    Ok(names)
}

fn dump_all() -> Result<(), String> {
    let usernames = read_passwd_usernames(Path::new(PASSWD_FILE))?;

    let path = Path::new(SUDOERS_FILE);
    let (sudoers, syntax_errors) =
        Sudoers::open(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    for sudo_rs::sudoers::Error { message, .. } in syntax_errors {
        let _ = writeln!(
            std::io::stderr(),
            "lssudo: {}: {message}",
            path.display()
        );
    }

    let hostname = Hostname::resolve();
    let mut out = std::io::stdout().lock();

    for username in &usernames {
        let Ok(name_c) = CString::new(username.as_str()) else {
            continue;
        };
        let Ok(Some(user)) = User::from_name(&name_c) else {
            continue;
        };

        let commands = sudoers
            .matching_entries(&user, &hostname)
            .map(|e| e.to_string().trim_start().to_owned())
            .collect();

        let line = serde_json::to_string(&PolicyDump {
            username: &user.name,
            commands,
        })
        .map_err(|e| format!("json serialization failed: {e}"))?;
        let _ = writeln!(out, "{line}");
    }

    Ok(())
}

fn main() -> ExitCode {
    match dump_all() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            let _ = writeln!(std::io::stderr(), "lssudo: {e}");
            ExitCode::from(1)
        }
    }
}
