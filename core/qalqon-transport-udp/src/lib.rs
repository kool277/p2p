//! The UDP adapter. One frame per datagram, so this is a lossy transport
//! (`docs/PROTOCOL.md`, section 5.3).
#![forbid(unsafe_code)]

use qalqon_core::session::TransportCaps;
use qalqon_transport::Link;
use std::io;
use std::net::UdpSocket;
use std::time::Duration;

/// One UDP socket, connected to a peer.
#[derive(Debug)]
pub struct UdpLink {
    socket: UdpSocket,
    buffer: Vec<u8>,
    caps: TransportCaps,
}

impl UdpLink {
    /// Wraps a socket that has been connected to its peer.
    pub fn new(socket: UdpSocket) -> Self {
        UdpLink {
            socket,
            buffer: vec![0; 65_536],
            caps: TransportCaps::DATAGRAM,
        }
    }

    /// Sets the largest frame this link sends, for paths with a small MTU.
    pub fn with_max_frame(mut self, max_frame_len: usize) -> Self {
        self.caps.max_frame_len = max_frame_len;
        self
    }
}

impl Link for UdpLink {
    fn caps(&self) -> TransportCaps {
        self.caps
    }

    fn send(&mut self, frame: &[u8]) -> io::Result<()> {
        match self.socket.send(frame) {
            Ok(_) => Ok(()),
            // Loopback reports an unreachable peer as an error. On a lossy transport
            // that is one more lost frame, and the retransmission timers deal with it.
            Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => Ok(()),
            Err(e) => Err(e),
        }
    }

    fn recv(&mut self, timeout: Duration) -> io::Result<Option<Vec<u8>>> {
        self.socket
            .set_read_timeout(Some(timeout.max(Duration::from_millis(1))))?;
        match self.socket.recv(&mut self.buffer) {
            Ok(n) => Ok(Some(self.buffer[..n].to_vec())),
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::ConnectionRefused
                ) =>
            {
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }
}
