//! What a transport adapter implements, and a blocking driver that joins one link to
//! one session. The engine itself never touches a socket (ADR-0002, part 1).
#![forbid(unsafe_code)]

use qalqon_core::session::TransportCaps;
use qalqon_core::{Event, Session};
use std::io;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// A bidirectional carrier of whole frames.
pub trait Link: Send {
    /// What this link can do.
    fn caps(&self) -> TransportCaps;
    /// Sends one frame.
    fn send(&mut self, frame: &[u8]) -> io::Result<()>;
    /// Waits up to `timeout` for one frame. `Ok(None)` means nothing arrived. An
    /// `UnexpectedEof` error means the peer closed the transport.
    fn recv(&mut self, timeout: Duration) -> io::Result<Option<Vec<u8>>>;
}

/// The current time in the form the engine wants.
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

/// Sends everything the session has queued.
pub fn flush(session: &mut Session, link: &mut dyn Link) -> io::Result<()> {
    while let Some(frame) = session.poll_transmit() {
        link.send(&frame)?;
    }
    Ok(())
}

/// Runs a session until `on_event` returns false or the session ends. `on_event` may
/// call the session. Time comes from the system clock.
pub fn drive<F>(
    session: &mut Session,
    link: &mut dyn Link,
    deadline: Duration,
    mut on_event: F,
) -> io::Result<()>
where
    F: FnMut(&mut Session, Event) -> bool,
{
    let give_up = Instant::now() + deadline;
    loop {
        flush(session, link)?;
        while let Some(event) = session.poll_event() {
            if !on_event(session, event) {
                flush(session, link)?;
                return Ok(());
            }
        }
        flush(session, link)?;
        if session.is_closed() {
            return Ok(());
        }
        if Instant::now() >= give_up {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "the session did not finish in time",
            ));
        }
        let now = now_ms();
        let wait = session
            .next_timeout()
            .map_or(50, |t| t.saturating_sub(now))
            .clamp(1, 50);
        match link.recv(Duration::from_millis(wait)) {
            Ok(Some(frame)) => session.handle_frame(now_ms(), &frame),
            Ok(None) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                session.on_transport_closed(now_ms())
            }
            Err(e) => return Err(e),
        }
        session.handle_timeout(now_ms());
    }
}
