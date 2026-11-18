// SPDX-License-Identifier: MIT OR Apache-2.0

//! Logging initialization for florestad.
//!
//! This module provides [`init_logging`] which sets up a [`tracing`] subscriber with optional
//! stdout and file output layers. It is used by both the CLI binary and the FFI layer.

use std::fs;
use std::io;
use std::io::IsTerminal;

use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::Layer;
use tracing_subscriber::fmt;
use tracing_subscriber::fmt::time::ChronoLocal;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

/// Set up the logger for `florestad`.
///
/// This logger will subscribe to `tracing` events, filter them according to the defined log
/// level, and format them based on the output destination. Logs can be directed to `stdout`, a
/// file, both, or neither.
pub fn init_logging(
    data_dir: &str,
    log_to_file: bool,
    log_to_stdout: bool,
    debug: bool,
) -> Result<Option<WorkerGuard>, io::Error> {
    // Get the log level from `--debug`.
    let log_level = if debug { "debug" } else { "info" };

    // Try to build an `EnvFilter` from the `RUST_LOG` env variable, or fallback to `log_level`.
    let log_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(log_level));

    let base_filter = log_filter.clone();

    // Validate the log file path.
    if log_to_file {
        let file_path = format!("{data_dir}/debug.log");
        fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&file_path)?;
    }

    // Timer for log events.
    let log_timer = ChronoLocal::new("%Y-%m-%d %H:%M:%S".to_string());

    // Standard Output layer: human-friendly formatting and level; ANSI only on a real TTY.
    let fmt_layer_stdout = log_to_stdout.then(|| {
        fmt::layer()
            .with_writer(io::stdout)
            .with_ansi(IsTerminal::is_terminal(&io::stdout()))
            .with_timer(log_timer.clone())
            .with_target(true)
            .with_level(true)
            .with_filter(log_filter.clone())
    });

    // File layer: non-blocking writer. Keep the `WorkerGuard` so logs flush on drop.
    let mut guard = None;
    let fmt_layer_logfile = log_to_file.then(|| {
        let file_appender = tracing_appender::rolling::never(data_dir, "debug.log");
        let (non_blocking, file_guard) = tracing_appender::non_blocking(file_appender);
        guard = Some(file_guard);

        fmt::layer()
            .with_writer(non_blocking)
            .with_ansi(false)
            .with_timer(log_timer)
            .with_target(true)
            .with_level(true)
            .with_filter(log_filter.clone())
    });

    // Build the registry and attach layers to it. An embedder (the FFI) can start
    // the node more than once in a process; the first subscriber stays in place,
    // and a second one is an error to report, not a reason to abort the process.
    tracing_subscriber::registry()
        .with(base_filter)
        .with(fmt_layer_stdout)
        .with(fmt_layer_logfile)
        .try_init()
        .map_err(io::Error::other)?;

    Ok(guard)
}

#[cfg(test)]
mod tests {
    use super::init_logging;

    #[test]
    fn a_second_init_is_an_error_not_a_panic() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().to_str().unwrap();

        // The first call may already fail if another test in this binary set a subscriber.
        let _first = init_logging(data_dir, false, false, false);
        assert!(init_logging(data_dir, false, false, false).is_err());
    }
}
