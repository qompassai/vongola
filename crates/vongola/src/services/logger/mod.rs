// #################################################################
// /qompassai/vongola/crates/vongola/src/services/logger/mod.rs
// Qompass AI Logger mod
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Qompass AI
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::{
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicI64, AtomicU64, Ordering},
    },
    task::{Context, Poll},
};

use async_trait::async_trait;
use pingora::{
    server::{ListenFds, ShutdownWatch},
    services::Service,
};
use rotation::Rotation;
use tokio::{
    io::AsyncWriteExt,
    sync::mpsc::{Receiver, Sender},
};
use tracing_subscriber::fmt::MakeWriter;

use crate::config::{Config, LogRotation};

mod rotation;

/// Maximum number of formatted log lines buffered between the request
/// path and the background log writer. One entry is one formatted line
/// (typically well under 1 KiB), so the queue stays within a few MiB.
/// When the queue is full the writer drops lines — counted in
/// [`DROPPED_LOG_LINES`] — rather than blocking request handling on
/// logging or growing memory without bound.
pub const LOG_CHANNEL_CAPACITY: usize = 1024;

/// Number of log lines dropped because the log channel was full.
pub static DROPPED_LOG_LINES: AtomicU64 = AtomicU64::new(0);

/// A `io::Write` implementation that sends logs to a background service
#[derive(Debug, Clone)]
pub struct StdoutWriter<'a> {
    chan: &'a Sender<Vec<u8>>,
    skip_log: bool,
}

impl io::Write for StdoutWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if !self.skip_log {
            match self.chan.try_send(buf.to_vec()) {
                Ok(()) => {}
                Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                    DROPPED_LOG_LINES.fetch_add(1, Ordering::Relaxed);
                }
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {}
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.skip_log {
            return Ok(());
        }

        io::stdout().flush()
    }
}

/// A naive implementation of a logger that delegate sending logs to a
/// background channel
#[derive(Debug)]
pub struct ProxyLog {
    enabled: bool,
    chan: Sender<Vec<u8>>,
    access_logs: bool,
    error_logs: bool,
}

impl ProxyLog {
    #[allow(clippy::fn_params_excessive_bools)]
    pub fn new(
        sender: Sender<Vec<u8>>,
        log_enabled: bool,
        access_logs: bool,
        error_logs: bool,
    ) -> Self {
        ProxyLog {
            // level,
            enabled: log_enabled,
            access_logs,
            error_logs,
            chan: sender,
        }
    }
}

/// impl from `tracing_subscriber::fmt::MakeWriter`
impl<'a> MakeWriter<'a> for ProxyLog {
    type Writer = StdoutWriter<'a>;

    fn make_writer(&'a self) -> Self::Writer {
        StdoutWriter {
            skip_log: false,
            chan: &self.chan,
        }
    }

    fn make_writer_for(&'a self, meta: &tracing::Metadata<'_>) -> Self::Writer {
        // if access_logs are disabled, we run a logic to skip them
        let mut skip_log = false;

        if !self.error_logs {
            skip_log = meta.level() == &tracing::Level::ERROR;
        }

        if !self.access_logs {
            skip_log = meta.fields().field("access_log").is_some();
        }

        StdoutWriter {
            skip_log: skip_log || !self.enabled,
            chan: &self.chan,
        }
    }
}

/// Common ENUM that implements the `AsyncWrite` trait
pub enum LogWriter {
    Stdout(tokio::io::Stdout),
    File(tokio::fs::File),
}

impl tokio::io::AsyncWrite for LogWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        match self.get_mut() {
            LogWriter::Stdout(w) => Pin::new(w).poll_write(cx, buf),
            LogWriter::File(w) => Pin::new(w).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        match self.get_mut() {
            LogWriter::Stdout(w) => Pin::new(w).poll_flush(cx),
            LogWriter::File(w) => Pin::new(w).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        match self.get_mut() {
            LogWriter::Stdout(w) => Pin::new(w).poll_shutdown(cx),
            LogWriter::File(w) => Pin::new(w).poll_shutdown(cx),
        }
    }
}

/// A background service that receives logs from the main thread and writes them
/// to stdout
pub struct ProxyLoggerReceiver {
    receiver: Receiver<Vec<u8>>,
    config: Arc<Config>,
    bufwriter: tokio::io::BufWriter<LogWriter>,
    suffix: String,
    state: Inner,
    rotation: Rotation,
}

// Inner state for the LoggerReceiver
pub struct Inner {
    next_date: AtomicI64,
}

impl ProxyLoggerReceiver {
    pub fn new(receiver: Receiver<Vec<u8>>, config: Arc<Config>) -> Self {
        ProxyLoggerReceiver {
            receiver,
            config,
            bufwriter: tokio::io::BufWriter::with_capacity(
                1024,
                LogWriter::Stdout(tokio::io::stdout()),
            ),
            suffix: String::new(),
            state: Inner {
                next_date: AtomicI64::new(0),
            },
            rotation: Rotation(LogRotation::Never),
        }
    }

    /// Based on the defined rotation strategy, create a new file for the logs
    /// and set the suffix for the file name
    /// If the rotation strategy is `NEVER`, the suffix is empty
    /// If the rotation strategy is `DAILY`, the suffix is the date in the
    /// format defined in the config The state of the rotation is updated
    /// with the next date to rotate
    async fn file_buf_writer(&mut self, date: time::OffsetDateTime) {
        self.suffix = if self.rotation == Rotation::NEVER {
            String::new()
        } else {
            format!(
                ".{}",
                date.format(&self.rotation.date_format())
                    .expect("Invalid date format returned from rotation; it's a bug")
            )
        };

        let mut op = tokio::fs::OpenOptions::new();
        let open_options = op.create(true).append(true);
        let Ok(path) = std::path::absolute(self.config.logging.path.as_ref().unwrap()) else {
            tracing::error!("Failed to get absolute path for log file");
            return;
        };
        let Ok(file) = open_options
            .open(path.join(format!("vongola{}.log", self.suffix)))
            .await
        else {
            tracing::error!("Failed to open log file");
            return;
        };

        self.bufwriter = Self::new_buf_writer(LogWriter::File(file));

        if let Some(next_date) = self.rotation.next_date(&date) {
            self.state
                .next_date
                .swap(next_date.unix_timestamp(), Ordering::Relaxed);
        }
    }

    /// Creates a new `BufWriter` with a buffer size of 1024 bytes
    fn new_buf_writer(writer: LogWriter) -> tokio::io::BufWriter<LogWriter> {
        tokio::io::BufWriter::with_capacity(1024, writer)
    }

    /// Prepares the `BufWriter` for the next log file
    async fn prepare_buf_writer(&mut self) {
        if self.config.logging.path.is_some() {
            self.rotation = Rotation(self.config.logging.clone().rotation);
            self.file_buf_writer(time::OffsetDateTime::now_utc()).await;
        }

        // Default is stdout, do nothing
    }

    /// If this method returns `Some`, we should roll to a new log file.
    /// Otherwise, if this returns we should not rotate the log file.
    fn should_rollover(&self, date: time::OffsetDateTime) -> Option<i64> {
        let next_date = self.state.next_date.load(Ordering::Acquire);
        // if the next date is 0, this appender *never* rotates log files.
        if next_date == 0 {
            return None;
        }

        if date.unix_timestamp() >= next_date {
            return Some(next_date);
        }

        None
    }

    /// Handles log rotation if the rotation strategy is not `NEVER`
    /// Also flushes the buffer writer and creates a new file if the rollover
    /// date is reached
    async fn handle_log_rotation(&mut self) {
        if self.rotation == Rotation::NEVER {
            return;
        }

        // If the rotation strategy is `NEVER`, the suffix is empty
        if let Some(next_date) = self.should_rollover(time::OffsetDateTime::now_utc()) {
            let date = time::OffsetDateTime::from_unix_timestamp(next_date).unwrap();
            self.bufwriter.flush().await.ok();
            self.file_buf_writer(date).await;
        }
    }
}

#[async_trait]
impl Service for ProxyLoggerReceiver {
    async fn start_service(&mut self, _fds: Option<ListenFds>, _shutdown: ShutdownWatch) {
        tracing::info!("starting logger service");
        self.prepare_buf_writer().await;

        while let Some(buf) = self.receiver.recv().await {
            let _ = self.bufwriter.write(&buf).await.unwrap();

            self.handle_log_rotation().await;
        }
    }

    fn name(&self) -> &str { "logging_service" }

    fn threads(&self) -> Option<usize> { Some(1) }
}
