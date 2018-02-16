use failure::Error;
use nom::{ErrorKind, be_u16, be_u32, be_u8};
use nom::IResult::{self, *};

use signature::*;
use types::NomError;

named!(old_tag_format<(&[u8], usize), (u8, &[u8])>,
    do_parse!(
        tag: take_bits!(u8, 4) >>
        length: switch!(take_bits!(u8, 2),
            0 => bytes!(map!(be_u8, u32::from)) |
            1 => bytes!(map!(be_u16, u32::from)) |
            2 => bytes!(call!(be_u32)) |
            _ => value!(0)
        ) >>
        data: bytes!(take!(length)) >>
        ((tag, data))
    )
);

fn new_tag_format(inp: (&[u8], usize)) -> IResult<(&[u8], usize), (u8, &[u8])> {
    let (remaining, tag) = match take_bits!(inp, u8, 6) {
        Done(remaining, tag) => (remaining, tag),
        Error(e) => return Error(e),
        Incomplete(i) => return Incomplete(i),
    };

    let (remaining, first_octet) = match bytes!(remaining, be_u8) {
        Done(remaining, first_octet) => (remaining, first_octet),
        Error(e) => return Error(e),
        Incomplete(i) => return Incomplete(i),
    };

    if first_octet < 192 {
        match bytes!(remaining, take!(first_octet)) {
            Done(remaining, contents) => return Done(remaining, (tag, contents)),
            Error(e) => return Error(e),
            Incomplete(i) => return Incomplete(i),
        }
    } else if first_octet < 224 {
        let (remaining, second_octet) = match bytes!(remaining, be_u8) {
            Done(remaining, second_octet) => (remaining, second_octet),
            Error(e) => return Error(e),
            Incomplete(i) => return Incomplete(i),
        };

        let length = ((first_octet as u16 - 192) << 8) + second_octet as u16 + 192;

        match bytes!(remaining, take!(length)) {
            Done(remaining, contents) => return Done(remaining, (tag, contents)),
            Error(e) => return Error(e),
            Incomplete(i) => return Incomplete(i),
        }
    } else if first_octet == 255 {
        let (remaining, length) = match bytes!(remaining, be_u32) {
            Done(remaining, length) => (remaining, length),
            Error(e) => return Error(e),
            Incomplete(i) => return Incomplete(i),
        };

        match bytes!(remaining, take!(length)) {
            Done(remaining, contents) => return Done(remaining, (tag, contents)),
            Error(e) => return Error(e),
            Incomplete(i) => return Incomplete(i),
        }
    }

    // If we've gotten here, it's a partial-length packet, which we don't support (yet?).
    IResult::Error(ErrorKind::Custom(NomError::Unimplemented as u32))
}

named!(
    pgp_packet_header<(u8, &[u8])>,
    bits!(preceded!(
        tag_bits!(u8, 1, 0b1),
        switch!(take_bits!(u8, 1),
            0 => call!(old_tag_format) |
            1 => call!(new_tag_format)
        )
    ))
);

#[derive(Clone, Debug)]
pub enum Packet {
    PublicKeySessionKey,
    Signature(SignaturePacket),
    SymmetricKeySessionKey,
    OnePassSignature,
    SecretKey,
    PublicKey,
    SecretSubkey,
    CompressedData,
    SymmetricEncryptedData,
    Marker,
    LiteralData,
    Trust,
    UserId,
    PublicSubkey,
    UserAttribute,
    SymmetricEncryptedIntegrityProtectedData,
    ModificationDetectionCode,
}

impl Packet {
    pub fn from_bytes(bytes: &[u8]) -> Result<Packet, Error> {
        let (packet_tag, packet_data) = match pgp_packet_header(bytes) {
            Done(_, (tag, data)) => (tag, data),
            Error(ErrorKind::Custom(e)) => {
                let e = NomError::from(e);

                bail!(PacketError::UnsupportedHeader {
                    reason: format!("{:?}", e),
                })
            }
            Error(e) => bail!(PacketError::InvalidHeader {
                reason: format!("{}", e),
            }),
            Incomplete(i) => bail!(PacketError::InvalidHeader {
                reason: format!("{:?}", i),
            }),
        };

        let packet = match packet_tag {
            0 => bail!(PacketError::InvalidHeader {
                reason: format!("packet has reserved tag"),
            }),
            1 => Packet::PublicKeySessionKey,
            2 => Packet::Signature(SignaturePacket::from_bytes(packet_data)?),
            3 => Packet::SymmetricKeySessionKey,
            4 => Packet::OnePassSignature,
            5 => Packet::SecretKey,
            6 => Packet::PublicKey,
            7 => Packet::SecretSubkey,
            8 => Packet::CompressedData,
            9 => Packet::SymmetricEncryptedData,
            10 => Packet::Marker,
            11 => Packet::LiteralData,
            12 => Packet::Trust,
            13 => Packet::UserId,
            14 => Packet::PublicSubkey,
            17 => Packet::UserAttribute,
            18 => Packet::SymmetricEncryptedIntegrityProtectedData,
            19 => Packet::ModificationDetectionCode,
            _ => bail!(PacketError::InvalidHeader {
                reason: format!("unknown tag"),
            }),
        };

        Ok(packet)
    }
}

#[derive(Debug, Fail)]
pub enum PacketError {
    #[fail(display = "Invalid packet header: {}", reason)] InvalidHeader { reason: String },
    #[fail(display = "Unsupported packet header: {}", reason)] UnsupportedHeader { reason: String },
}