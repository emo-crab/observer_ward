use std::process::{Command, Stdio};

use serde::{Deserialize, Serialize};

// https://github.com/0x727/FingerprintHub/releases/download/default/plugins.zip
#[derive(Debug, Serialize, Deserialize, Clone)]
struct Template {
    pub template_id: String,
}

pub fn has_nuclei_app() -> bool {
    return if cfg!(target_os = "windows") {
        Command::new("nuclei.exe")
            .args(["-version"])
            .stdin(Stdio::null())
            .output()
            .is_ok()
    } else {
        Command::new("nuclei")
            .args(["-version"])
            .stdin(Stdio::null())
            .output()
            .is_ok()
    };
}