//! Append-only replay ring file.
//!
//! All raw signals are written here in binary (length-prefixed protobuf).
//! Max size is capped — once full, oldest frames are overwritten (ring).
//! On incident, the queen can replay this file for forensic analysis.

use anyhow::Result;
use anthill_core::proto::ThreatSignal;
use prost::Message;
use std::fs::OpenOptions;
use std::io::{BufWriter, Seek, SeekFrom, Write};
use std::path::Path;
use tokio::sync::Mutex;

const FRAME_HEADER: usize = 4; // u32 LE length prefix

pub struct ReplayRing {
    writer:   Mutex<BufWriter<std::fs::File>>,
    max_bytes: u64,
    written:   Mutex<u64>,
}

impl ReplayRing {
    pub fn open(path: &Path, max_mb: u64) -> Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .read(true)
            .open(path)?;
        let written = file.metadata()?.len();
        Ok(Self {
            writer:    Mutex::new(BufWriter::new(file)),
            max_bytes: max_mb * 1024 * 1024,
            written:   Mutex::new(written),
        })
    }

    pub async fn append(&self, signal: &ThreatSignal) -> Result<()> {
        let payload = signal.encode_to_vec();
        let len = payload.len() as u32;

        let mut w = self.writer.lock().await;
        let mut written = self.written.lock().await;

        // Wrap around if at capacity
        if *written + (FRAME_HEADER + payload.len()) as u64 > self.max_bytes {
            w.seek(SeekFrom::Start(0))?;
            *written = 0;
        }

        w.write_all(&len.to_le_bytes())?;
        w.write_all(&payload)?;
        *written += (FRAME_HEADER + payload.len()) as u64;
        Ok(())
    }
}
