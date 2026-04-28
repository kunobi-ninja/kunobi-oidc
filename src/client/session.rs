//! Per-shell CLI session state, keyed by the parent shell's PID.
//!
//! Several Kunobi CLIs (kobe, kunobi, …) need to remember what the
//! "active target" / "active context" is between invocations — but
//! **per terminal window**, not globally. A shared global file like
//! kubectl's `current-context` makes multi-window workflows painful:
//! `kobe config use prod` in one tab silently flips the active target
//! in every other tab.
//!
//! This module solves it without environment-variable plumbing or
//! shell hooks. Each interactive shell that invokes the CLI has its
//! own PID; the `kobe` (or other CLI) process inherits that PID as
//! its `getppid()`. We use that PID as the filename:
//!
//! ```text
//! <cache>/kunobi/sessions/<product>/<ppid>.json
//! ```
//!
//! Different terminal windows have different shell PIDs ⇒ they get
//! independent session state automatically. When the shell exits its
//! PID disappears; [`gc_dead_sessions`] sweeps stale files at the
//! start of each CLI invocation.
//!
//! ## Generic over the state shape
//!
//! Each consuming CLI defines its own session-state struct (kobe has
//! `{ current_target: String }`, others may have richer state). The
//! [`load`] / [`save`] / [`clear`] functions are generic over any
//! `Serialize + DeserializeOwned`, so products only need to declare a
//! product key (e.g. `"kobe"`) and a state type.
//!
//! ## Cross-platform
//!
//! Parent-PID lookup and PID-liveness probing both go through
//! [`sysinfo`], so the same code path works on Linux, macOS, and
//! Windows. On Windows there is no `kill -0` equivalent; sysinfo
//! abstracts the platform-specific liveness query.
//!
//! ## Example
//!
//! ```rust,no_run
//! # #[cfg(feature = "client")] {
//! use kunobi_auth::client::session;
//! use serde::{Deserialize, Serialize};
//!
//! #[derive(Serialize, Deserialize)]
//! struct MyState {
//!     current_target: String,
//! }
//!
//! const PRODUCT: &str = "kobe";
//!
//! // Save active target for this shell only.
//! session::save(PRODUCT, &MyState {
//!     current_target: "prod".to_string(),
//! }).unwrap();
//!
//! // Read it back later — only succeeds in the same terminal window.
//! if let Some((state, _path, _ppid)) = session::load::<MyState>(PRODUCT).unwrap() {
//!     println!("active target: {}", state.current_target);
//! }
//!
//! // Sweep stale files (call at CLI entry).
//! session::gc_dead_sessions(PRODUCT);
//! # }
//! ```

use anyhow::{Context, Result};
use serde::{Serialize, de::DeserializeOwned};
use std::fs;
use std::path::PathBuf;
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};

/// Return the PID of the process that invoked this CLI (a shell, a
/// make recipe, a CI runner, …). `None` if we can't determine it —
/// callers should treat that as "no session state available" and fall
/// back to flag-only operation.
pub fn parent_pid() -> Option<u32> {
    let me = Pid::from_u32(std::process::id());
    let mut sys = System::new();
    sys.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[me]),
        true,
        ProcessRefreshKind::nothing(),
    );
    sys.process(me).and_then(|p| p.parent()).map(|p| p.as_u32())
}

/// Check whether `pid` corresponds to a currently-running process.
/// Used by [`gc_dead_sessions`] to prune stale session files; exposed
/// publicly because callers occasionally want to verify a recovered
/// PID is still live before trusting any state attached to it.
pub fn is_pid_alive(pid: u32) -> bool {
    let pid = Pid::from_u32(pid);
    let mut sys = System::new();
    sys.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[pid]),
        true,
        ProcessRefreshKind::nothing(),
    );
    sys.process(pid).is_some()
}

/// Return the directory holding all session files for `product`.
///
/// On Linux this is typically `~/.cache/kunobi/sessions/<product>/`,
/// on macOS `~/Library/Caches/kunobi/sessions/<product>/`, on Windows
/// `%LOCALAPPDATA%\kunobi\sessions\<product>\`. Cache (not config)
/// because session state is volatile and recoverable.
///
/// The `KUNOBI_SESSIONS_DIR` env var overrides the resolved location
/// (the product-named subdirectory is still appended). Intended for
/// tests, but operators may also use it to relocate state onto a
/// faster filesystem.
pub fn sessions_dir(product: &str) -> Result<PathBuf> {
    if let Ok(custom) = std::env::var("KUNOBI_SESSIONS_DIR")
        && !custom.is_empty()
    {
        return Ok(PathBuf::from(custom).join(product));
    }
    let cache = dirs::cache_dir()
        .ok_or_else(|| anyhow::anyhow!("Cannot determine user cache directory"))?;
    Ok(cache.join("kunobi").join("sessions").join(product))
}

/// Path to the current shell's session file for `product`. `None` if
/// the parent PID couldn't be resolved.
pub fn current_session_path(product: &str) -> Result<Option<PathBuf>> {
    let Some(ppid) = parent_pid() else {
        return Ok(None);
    };
    Ok(Some(sessions_dir(product)?.join(format!("{ppid}.json"))))
}

/// Load the current shell's session state for `product`, if any.
///
/// Returns `Ok(None)` for a missing or unparseable file (a corrupt
/// session file should never block the CLI — the user can always
/// `<cli> use <name>` to re-establish state). I/O errors that aren't
/// "missing" are surfaced as `Err`.
pub fn load<T>(product: &str) -> Result<Option<(T, PathBuf, u32)>>
where
    T: DeserializeOwned,
{
    let Some(ppid) = parent_pid() else {
        return Ok(None);
    };
    let path = sessions_dir(product)?.join(format!("{ppid}.json"));
    if !path.exists() {
        return Ok(None);
    }
    let raw = match fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, path = %path.display(), "ignoring unreadable session file");
            return Ok(None);
        }
    };
    match serde_json::from_str::<T>(&raw) {
        Ok(state) => Ok(Some((state, path, ppid))),
        Err(e) => {
            tracing::warn!(error = %e, path = %path.display(), "ignoring malformed session file");
            Ok(None)
        }
    }
}

/// Persist the current shell's session state for `product`,
/// replacing any previous content.
///
/// Writes atomically (`rename`-after-write) so a concurrent reader
/// never sees a half-written file. Sets file mode to `0o600` on Unix.
/// Errors if the parent PID can't be resolved — callers should
/// surface that as "per-shell state unavailable, use --flag instead."
pub fn save<T>(product: &str, state: &T) -> Result<PathBuf>
where
    T: Serialize,
{
    let Some(path) = current_session_path(product)? else {
        anyhow::bail!("Cannot determine parent shell PID; per-shell session state is unavailable.");
    };
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "Failed to create sessions directory at {}",
                parent.display()
            )
        })?;
    }
    let json = serde_json::to_string_pretty(state).context("Failed to serialize session state")?;
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, &json).with_context(|| format!("Failed to write {}", tmp.display()))?;
    fs::rename(&tmp, &path)
        .with_context(|| format!("Failed to rename {} -> {}", tmp.display(), path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
    }
    Ok(path)
}

/// Remove the current shell's session file for `product`. No-op if it
/// doesn't exist.
pub fn clear(product: &str) -> Result<()> {
    let Some(path) = current_session_path(product)? else {
        return Ok(());
    };
    if path.exists() {
        fs::remove_file(&path).with_context(|| format!("Failed to remove {}", path.display()))?;
    }
    Ok(())
}

/// Sweep session files for `product` whose owning PID is no longer
/// running.
///
/// Designed to be called at the start of every CLI invocation: cheap
/// (one `readdir` + one [`is_pid_alive`] per entry) and idempotent.
/// Errors are silently ignored — GC failures must never block real
/// work.
pub fn gc_dead_sessions(product: &str) {
    let dir = match sessions_dir(product) {
        Ok(d) => d,
        Err(_) => return,
    };
    let entries = match fs::read_dir(&dir) {
        Ok(it) => it,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let stem = match path.file_stem().and_then(|s| s.to_str()) {
            Some(s) => s.to_string(),
            None => continue,
        };
        let ext_ok = path
            .extension()
            .and_then(|s| s.to_str())
            .map(|s| s == "json")
            .unwrap_or(false);
        if !ext_ok {
            continue;
        }
        let Ok(pid) = stem.parse::<u32>() else {
            continue;
        };
        if !is_pid_alive(pid) {
            let _ = fs::remove_file(&path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    /// Sample state shape used by tests. Each consuming CLI defines
    /// its own equivalent; the session module is generic over
    /// `Serialize + DeserializeOwned` so this isn't part of the public
    /// API.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    struct TestState {
        current_target: String,
        attempts: u32,
    }

    /// Mutex around `KUNOBI_SESSIONS_DIR` so the cache-redirect tests
    /// don't race against each other when cargo runs them in parallel.
    static SESSIONS_DIR_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Set `KUNOBI_SESSIONS_DIR` to a tempdir for the lifetime of the
    /// returned guard, restoring the previous value on drop.
    struct ScopedSessionsDir {
        _td: tempfile::TempDir,
        _guard: std::sync::MutexGuard<'static, ()>,
        prev: Option<std::ffi::OsString>,
    }

    impl ScopedSessionsDir {
        fn new() -> Self {
            let guard = SESSIONS_DIR_GUARD.lock().unwrap_or_else(|p| p.into_inner());
            let td = tempfile::tempdir().expect("tempdir");
            let prev = std::env::var_os("KUNOBI_SESSIONS_DIR");
            // SAFETY: tests run with std env access; we restore in Drop.
            unsafe { std::env::set_var("KUNOBI_SESSIONS_DIR", td.path()) };
            Self {
                _td: td,
                _guard: guard,
                prev,
            }
        }
    }

    impl Drop for ScopedSessionsDir {
        fn drop(&mut self) {
            unsafe {
                match &self.prev {
                    Some(v) => std::env::set_var("KUNOBI_SESSIONS_DIR", v),
                    None => std::env::remove_var("KUNOBI_SESSIONS_DIR"),
                }
            }
        }
    }

    #[test]
    fn parent_pid_returns_running_process() {
        let ppid = parent_pid().expect("test process has a parent");
        assert!(
            is_pid_alive(ppid),
            "parent PID {ppid} should be alive while we're running"
        );
    }

    #[test]
    fn is_pid_alive_returns_false_for_definitely_dead_pid() {
        assert!(!is_pid_alive(u32::MAX));
    }

    #[test]
    fn is_pid_alive_returns_true_for_self() {
        assert!(is_pid_alive(std::process::id()));
    }

    #[test]
    fn sessions_dir_is_namespaced_by_product() {
        let scoped = ScopedSessionsDir::new();
        let kobe = sessions_dir("kobe").expect("dir");
        let kunobi = sessions_dir("kunobi").expect("dir");
        assert_ne!(
            kobe, kunobi,
            "different products must NOT share the same sessions dir — they'd collide on PID keys"
        );
        assert!(kobe.ends_with("kobe"));
        assert!(kunobi.ends_with("kunobi"));
        drop(scoped);
    }

    #[test]
    fn sessions_dir_falls_back_to_cache_when_env_empty() {
        let _guard = SESSIONS_DIR_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        let prev = std::env::var_os("KUNOBI_SESSIONS_DIR");
        unsafe { std::env::set_var("KUNOBI_SESSIONS_DIR", "") };
        let dir = sessions_dir("kobe").expect("dir");
        let s = dir.to_string_lossy();
        assert!(
            s.ends_with("kunobi/sessions/kobe") || s.ends_with("kunobi\\sessions\\kobe"),
            "empty override should fall back to cache_dir/kunobi/sessions/<product>, got: {s}"
        );
        unsafe {
            match prev {
                Some(v) => std::env::set_var("KUNOBI_SESSIONS_DIR", v),
                None => std::env::remove_var("KUNOBI_SESSIONS_DIR"),
            }
        }
    }

    #[test]
    fn save_load_roundtrip() {
        let _scoped = ScopedSessionsDir::new();

        let state = TestState {
            current_target: "prod".to_string(),
            attempts: 3,
        };
        let saved_path = save("kobe", &state).expect("save");
        assert!(saved_path.exists());

        let loaded = load::<TestState>("kobe").expect("load").expect("Some");
        assert_eq!(loaded.0, state);
        assert_eq!(loaded.1, saved_path);

        clear("kobe").expect("clear");
        assert!(!saved_path.exists());
    }

    #[test]
    fn save_for_one_product_does_not_affect_another() {
        let _scoped = ScopedSessionsDir::new();
        save(
            "kobe",
            &TestState {
                current_target: "prod".to_string(),
                attempts: 1,
            },
        )
        .unwrap();
        // kunobi product hasn't saved anything — must not see kobe's state.
        let loaded = load::<TestState>("kunobi").expect("load");
        assert!(
            loaded.is_none(),
            "products must not see each other's session state"
        );
    }

    #[test]
    fn malformed_session_file_returns_none() {
        let _scoped = ScopedSessionsDir::new();
        // Place garbage bytes at the path that load() would consult.
        let dir = sessions_dir("kobe").unwrap();
        fs::create_dir_all(&dir).unwrap();
        let ppid = parent_pid().expect("ppid");
        let path = dir.join(format!("{ppid}.json"));
        fs::write(&path, "{ this is not json").unwrap();

        // load() must NOT panic and must NOT return the corrupt state.
        // Returning None lets the caller fall back to defaults.
        let loaded = load::<TestState>("kobe").expect("load returns Ok");
        assert!(
            loaded.is_none(),
            "malformed session file should be ignored, not propagate as an error"
        );
    }

    #[test]
    fn gc_removes_dead_session_files_only() {
        let _scoped = ScopedSessionsDir::new();
        let dir = sessions_dir("kobe").expect("dir");
        fs::create_dir_all(&dir).expect("mkdir");

        let live_path = dir.join(format!("{}.json", std::process::id()));
        fs::write(&live_path, r#"{"current_target":"live","attempts":0}"#).unwrap();

        let dead_path = dir.join(format!("{}.json", u32::MAX));
        fs::write(&dead_path, r#"{"current_target":"dead","attempts":0}"#).unwrap();

        let tmp_path = dir.join("999999.json.tmp");
        fs::write(&tmp_path, "in-flight").unwrap();

        gc_dead_sessions("kobe");

        assert!(live_path.exists(), "live session must survive GC");
        assert!(!dead_path.exists(), "dead session must be reaped");
        assert!(tmp_path.exists(), "non-json files must be ignored");
    }

    #[test]
    fn gc_for_one_product_does_not_touch_another() {
        let _scoped = ScopedSessionsDir::new();

        // Put a live + dead session for product A.
        let dir_a = sessions_dir("a").unwrap();
        fs::create_dir_all(&dir_a).unwrap();
        let live_a = dir_a.join(format!("{}.json", std::process::id()));
        let dead_a = dir_a.join(format!("{}.json", u32::MAX));
        fs::write(&live_a, "{}").unwrap();
        fs::write(&dead_a, "{}").unwrap();

        // Same shape for product B.
        let dir_b = sessions_dir("b").unwrap();
        fs::create_dir_all(&dir_b).unwrap();
        let dead_b = dir_b.join(format!("{}.json", u32::MAX));
        fs::write(&dead_b, "{}").unwrap();

        // GC product A only — product B must remain untouched (even
        // its dead file).
        gc_dead_sessions("a");
        assert!(live_a.exists());
        assert!(!dead_a.exists());
        assert!(
            dead_b.exists(),
            "GC must scope to the named product — product B's files are off-limits"
        );
    }
}
