//! airsign: an amnesic offline signer for single-key BIP86 taproot wallets,
//! with a compact request format small enough to type as words or scan as one
//! static QR code. See DESIGN.md.

pub mod codec;
pub mod combine;
pub mod frame;
pub mod harden;
pub mod keygen;
pub mod qr;
pub mod request;
pub mod signer;
pub mod ui;
