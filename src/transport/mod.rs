pub mod adaptation;
pub mod audio_datagram;
pub mod clipboard;
pub mod configuration;
pub mod file_transfer;
pub mod input;
pub mod pairing;
pub mod protocol;
pub mod recovery;
pub mod session;
pub mod statistics;
pub mod video_datagram;

#[cfg(feature = "quic-transport")]
pub mod datagram;

#[cfg(feature = "quic-transport")]
pub mod application;

#[cfg(feature = "quic-transport")]
pub mod identity;

#[cfg(feature = "quic-transport")]
pub mod quic;

#[cfg(feature = "quic-transport")]
pub mod reliable;
