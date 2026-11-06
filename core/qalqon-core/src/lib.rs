//! The sans-I/O Qalqon engine, as specified in `docs/PROTOCOL.md`.
//!
//! The engine never touches a socket or a clock. A caller hands it frames and the
//! current time, then drains the frames and events it produces. It builds without
//! an operating system when given an allocator.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod cert;
pub mod control;
pub mod crl;
pub mod error;
pub mod frag;
pub(crate) mod handshake;
pub mod pins;
pub mod record;
pub mod relay;
pub mod schedule;
pub mod session;
pub mod wire;

pub use crypto_provider as crypto;
pub use error::{ErrorCode, HandshakeFailure};
pub use session::{
    ChannelOptions, Event, Limits, PeerExpectation, PeerInfo, PeerRejection, PeerVerifier,
    PinStatus, Plane, Role, Session, SessionConfig, TransportCaps, UncheckedPeers,
};
