//! Transport-independent connection ownership and protocol progress.

mod client;
mod quic;
mod quic_client;
mod tcp;

pub use client::{ClientConnection, HandshakeProgress};
pub use quic::{QuicControlError, QuicPostHandshake};
pub use quic_client::{QuicClientConnection, QuicConnectionEstablished, QuicLevel};
pub use tcp::{ReadProgress, TcpConnection};
