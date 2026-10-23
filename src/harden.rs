//! Process hardening for the offline signer (Linux): no core dumps, not
//! ptrace-able by same-user processes, and memory locked so secrets never reach
//! swap (the live image has no swap either; this covers other setups).

#[cfg(target_os = "linux")]
pub fn harden() -> Vec<String> {
    let mut notes = Vec::new();
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        let none = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        libc::setrlimit(libc::RLIMIT_CORE, &none);
        // MCL_FUTURE under a finite RLIMIT_MEMLOCK turns later allocations into
        // aborts, so lock only when the limit allows it.
        let mut lim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut lim);
        if lim.rlim_cur == libc::RLIM_INFINITY || libc::geteuid() == 0 {
            if libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) != 0 {
                notes.push("could not lock memory (mlockall failed)".into());
            }
        } else {
            notes.push("memory not locked: RLIMIT_MEMLOCK is finite (the live image sets it to infinity)".into());
        }
    }
    notes
}

#[cfg(not(target_os = "linux"))]
pub fn harden() -> Vec<String> {
    vec!["not running on Linux: no memory locking or core-dump suppression".into()]
}

/// Read a line with terminal echo off when stdin is a terminal.
#[cfg(target_os = "linux")]
pub fn read_line_noecho() -> std::io::Result<String> {
    use std::io::BufRead;
    unsafe {
        let mut term: libc::termios = std::mem::zeroed();
        let is_tty = libc::isatty(0) == 1 && libc::tcgetattr(0, &mut term) == 0;
        let saved = term;
        if is_tty {
            term.c_lflag &= !libc::ECHO;
            libc::tcsetattr(0, libc::TCSANOW, &term);
        }
        let mut s = String::new();
        let r = std::io::stdin().lock().read_line(&mut s);
        if is_tty {
            libc::tcsetattr(0, libc::TCSANOW, &saved);
            println!();
        }
        r.map(|_| s)
    }
}

#[cfg(not(target_os = "linux"))]
pub fn read_line_noecho() -> std::io::Result<String> {
    use std::io::BufRead;
    let mut s = String::new();
    std::io::stdin().lock().read_line(&mut s)?;
    Ok(s)
}

/// Run the QR scanner with Ctrl-C delivered to it but not to us, so cancelling a
/// scan returns to the prompt instead of ending the session.
#[cfg(target_os = "linux")]
pub fn scan_qr_with_zbarcam(device: &str) -> Result<String, String> {
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    use zeroize::Zeroize;
    let mut cmd = Command::new("zbarcam");
    cmd.args(["--raw", "--nodisplay", "--oneshot", "-Sdisable", "-Sqrcode.enable", device])
        .stdin(Stdio::null())
        .stderr(Stdio::null());
    unsafe {
        cmd.pre_exec(|| {
            libc::signal(libc::SIGINT, libc::SIG_DFL);
            Ok(())
        });
        libc::signal(libc::SIGINT, libc::SIG_IGN);
    }
    let out = cmd.output();
    unsafe {
        libc::signal(libc::SIGINT, libc::SIG_DFL);
    }
    match out {
        Ok(mut o) if o.status.success() => {
            let text = String::from_utf8_lossy(&o.stdout).trim().to_string();
            o.stdout.zeroize();
            Ok(text)
        }
        Ok(mut o) => {
            o.stdout.zeroize();
            Err("scan cancelled or camera not available".into())
        }
        Err(e) => Err(format!("cannot run zbarcam ({e}); is a camera scanner installed?")),
    }
}

#[cfg(not(target_os = "linux"))]
pub fn scan_qr_with_zbarcam(_device: &str) -> Result<String, String> {
    Err("camera scanning is only supported on Linux".into())
}
