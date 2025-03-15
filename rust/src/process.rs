//! Utils for dealing with processes

use std::fs::{read, read_dir};

/// return PID given name
pub(crate) fn get_pid(process_name: &str) -> Option<i32> {
    for entry in read_dir("/proc").ok()? {
        let entry = entry.ok()?;
        let path = entry.path();

        if path.is_dir() {
            let cmdline_path = path.join("cmdline");
            if let Ok(cmdline_bytes) = read(cmdline_path) {
                let cmdline = String::from_utf8_lossy(&cmdline_bytes);
                if cmdline == process_name || cmdline.starts_with(process_name) {
                    if let Some(pid_str) = path.file_name().and_then(|s| s.to_str()) {
                        if let Ok(pid) = pid_str.parse::<i32>() {
                            return Some(pid);
                        }
                    }
                }
            }
        }
    }

    None
}
