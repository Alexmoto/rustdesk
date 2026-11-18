//! Windows-only, read-only PROFINET DCP Identify relay over RustDesk's existing
//! authenticated TCP port-forward transport. No new unauthenticated listener.
use std::{
    fs::OpenOptions,
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{Mutex, OnceLock},
};

pub const DCP_PORT: i32 = 49092;
const MARKER: &str = "__rustdesk_profinet_dcp__:";

pub fn marker(plc_host: &str) -> String {
    format!("{}{}", MARKER, plc_host)
}

/// Special host is recognized only for the internal DCP port.
pub fn target_from_marker(host: &str, port: i32) -> Option<&str> {
    if port != DCP_PORT {
        return None;
    }
    let target = host.strip_prefix(MARKER)?;
    if target.is_empty()
        || target.len() > 253
        || !target
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':' | b'_'))
    {
        return None;
    }
    Some(target)
}

fn helper_path() -> std::io::Result<PathBuf> {
    let exe = std::env::current_exe()?;
    let root = exe.parent().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::NotFound, "RustDesk executable directory missing")
    })?;
    let helper = root
        .join("rustdesk-profinet-dcp")
        .join("rustdesk-profinet-dcp.exe");
    if !helper.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("PROFINET DCP helper not packaged: {}", helper.display()),
        ));
    }
    Ok(helper)
}

fn log_file() -> std::io::Result<std::fs::File> {
    let location = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join("RustDesk");
    std::fs::create_dir_all(&location)?;
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(location.join("profinet-dcp.log"))
}

fn spawn_helper(args: &[&str]) -> std::io::Result<Child> {
    let file = log_file()?;
    Command::new(helper_path()?)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::from(file.try_clone()?))
        .stderr(Stdio::from(file))
        .spawn()
}

pub fn start_local(port: u16) -> std::io::Result<Child> {
    let port = port.to_string();
    spawn_helper(&["local-auto", "--port", &port])
}

static REMOTE_HELPER: OnceLock<Mutex<Option<(String, Child)>>> = OnceLock::new();

/// Start only after a tunnel-authorized login or channel open.
/// A single remote helper owns loopback TCP/49092.
pub fn ensure_remote(target: &str) -> std::io::Result<()> {
    let guard = REMOTE_HELPER.get_or_init(|| Mutex::new(None));
    let mut current = guard.lock().unwrap();
    if let Some((active_target, child)) = current.as_mut() {
        if child.try_wait()?.is_none() {
            if active_target == target {
                return Ok(());
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "Another PROFINET DCP target is already active",
            ));
        }
        *current = None;
    }
    let port = DCP_PORT.to_string();
    let child = spawn_helper(&["remote-auto", "--target", target, "--port", &port])?;
    *current = Some((target.to_owned(), child));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_dcp_marker_on_internal_port_is_special() {
        assert_eq!(
            target_from_marker(&marker("192.168.1.5"), DCP_PORT),
            Some("192.168.1.5")
        );
        assert_eq!(target_from_marker(&marker("192.168.1.5"), 102), None);
        assert_eq!(target_from_marker("localhost", DCP_PORT), None);
        assert_eq!(target_from_marker(&marker("foo bar"), DCP_PORT), None);
        assert_eq!(target_from_marker(&marker(""), DCP_PORT), None);
    }
}
