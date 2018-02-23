//! # pretty-good overview
//!
//! pretty-good is an implementation of RFC4880 (OpenPGP Message Format), capable of reading
//! OpenPGP packets into usable Rust structures, and creating and writing OpenPGP packets
//! programmatically in Rust.
//!
//! The primary structure of pretty-good is the [`Packet`] enum, which contains a variant for each
//! possible type of OpenPGP packet. Each variant that has been implemented contains a single
//! field, which is a structure representing the contents of that packet type. For example,
//! `Packet::Signature` contains a [`SignaturePacket`], which can be used to read and write OpenPGP
//! signatures.
//!
//! [`Packet`]s are read by calling [`Packet::from_bytes`], and can be serialized by calling
//! [`Packet::to_bytes`].
//!
//! [`Packet`]: enum.Packet.html
//! [`Packet::to_bytes`]: enum.Packet.html#method.to_bytes
//! [`Packet::from_bytes`]: enum.Packet.html#method.from_bytes
//! [`SignaturePacket`]: struct.SignaturePacket.html
extern crate asn1;
extern crate byteorder;
extern crate digest;
#[macro_use]
extern crate failure;
#[macro_use]
extern crate failure_derive;
extern crate gcrypt;
extern crate md5;
#[macro_use]
extern crate nom;
extern crate ripemd160;
extern crate sha1;
extern crate sha2;

mod packet;
mod signature;
mod types;

pub use packet::*;
pub use signature::*;
pub use types::*;
