//! The TCP adapter. Frames are concatenated and split using `length`, so this is a
//! strict transport (`docs/PROTOCOL.md`, section 5.3).
#![forbid(unsafe_code)]

use qalqon_core::session::TransportCaps;
use qalqon_core::wire::FrameDecoder;
use qalqon_transport::Link;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// One TCP connection.
#[derive(Debug)]
pub struct TcpLink {
    stream: TcpStream,
    decoder: FrameDecoder,
    buffer: Vec<u8>,
}

impl TcpLink {
    /// Wraps a connected stream.
    pub fn new(stream: TcpStream) -> io::Result<Self> {
        stream.set_nodelay(true)?;
        Ok(TcpLink {
            stream,
            decoder: FrameDecoder::new(),
            buffer: vec![0; 64 * 1024],
        })
    }
}

impl Link for TcpLink {
    fn caps(&self) -> TransportCaps {
        TransportCaps::STREAM
    }

    fn send(&mut self, frame: &[u8]) -> io::Result<()> {
        self.stream.write_all(frame)
    }

    fn recv(&mut self, timeout: Duration) -> io::Result<Option<Vec<u8>>> {
        let corrupt = || {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "the stream is not Qalqon frames",
            )
        };
        if let Some(frame) = self.decoder.next_frame().map_err(|_| corrupt())? {
            return Ok(Some(frame));
        }
        self.stream
            .set_read_timeout(Some(timeout.max(Duration::from_millis(1))))?;
        match self.stream.read(&mut self.buffer) {
            Ok(0) => Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => {
                self.decoder.push(&self.buffer[..n]);
                self.decoder.next_frame().map_err(|_| corrupt())
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }
}
