use byteorder::{BigEndian, WriteBytesExt};
use failure::Error;
use nom::{ErrorKind, be_u16, be_u32, be_u8};
use nom::Err as NomErr;
use nom::IResult;

use compression::*;
use key::*;
use literal::*;
use marker;
use signature::*;
use types::NomError;
use userid;

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
        IResult::Done(remaining, tag) => (remaining, tag),
        IResult::Error(e) => return IResult::Error(e),
        IResult::Incomplete(i) => return IResult::Incomplete(i),
    };

    let (remaining, first_octet) = match bytes!(remaining, be_u8) {
        IResult::Done(remaining, first_octet) => (remaining, first_octet),
        IResult::Error(e) => return IResult::Error(e),
        IResult::Incomplete(i) => return IResult::Incomplete(i),
    };

    if first_octet < 192 {
        match bytes!(remaining, take!(first_octet)) {
            IResult::Done(remaining, contents) => return IResult::Done(remaining, (tag, contents)),
            IResult::Error(e) => return IResult::Error(e),
            IResult::Incomplete(i) => return IResult::Incomplete(i),
        }
    } else if first_octet < 224 {
        let (remaining, second_octet) = match bytes!(remaining, be_u8) {
            IResult::Done(remaining, second_octet) => (remaining, second_octet),
            IResult::Error(e) => return IResult::Error(e),
            IResult::Incomplete(i) => return IResult::Incomplete(i),
        };

        let length = ((first_octet as u16 - 192) << 8) + second_octet as u16 + 192;

        match bytes!(remaining, take!(length)) {
            IResult::Done(remaining, contents) => return IResult::Done(remaining, (tag, contents)),
            IResult::Error(e) => return IResult::Error(e),
            IResult::Incomplete(i) => return IResult::Incomplete(i),
        }
    } else if first_octet == 255 {
        let (remaining, length) = match bytes!(remaining, be_u32) {
            IResult::Done(remaining, length) => (remaining, length),
            IResult::Error(e) => return IResult::Error(e),
            IResult::Incomplete(i) => return IResult::Incomplete(i),
        };

        match bytes!(remaining, take!(length)) {
            IResult::Done(remaining, contents) => return IResult::Done(remaining, (tag, contents)),
            IResult::Error(e) => return IResult::Error(e),
            IResult::Incomplete(i) => return IResult::Incomplete(i),
        }
    }

    // If we've gotten here, it's a partial-length packet, which we don't support (yet?).
    IResult::Error(NomErr::Code(ErrorKind::Custom(
        NomError::Unimplemented as u32,
    )))
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

/// An OpenPGP packet.
///
/// Each currently-implemented variant contains a single structure representing the contents of
/// that packet type.
#[derive(Clone, Debug)]
pub enum Packet {
    PublicKeySessionKey,
    Signature(SignaturePacket),
    SymmetricKeySessionKey,
    OnePassSignature,
    SecretKey(Key),
    PublicKey(Key),
    SecretSubkey(Key),
    CompressedData(CompressedDataPacket),
    SymmetricEncryptedData,
    Marker,
    LiteralData(LiteralPacket),
    Trust,
    UserId(String),
    PublicSubkey(Key),
    UserAttribute,
    SymmetricEncryptedIntegrityProtectedData,
    ModificationDetectionCode,
}

impl Packet {
    fn packet_tag(&self) -> u8 {
        match *self {
            Packet::PublicKeySessionKey => 1,
            Packet::Signature(_) => 2,
            Packet::SymmetricKeySessionKey => 3,
            Packet::OnePassSignature => 4,
            Packet::SecretKey(_) => 5,
            Packet::PublicKey(_) => 6,
            Packet::SecretSubkey(_) => 7,
            Packet::CompressedData(_) => 8,
            Packet::SymmetricEncryptedData => 9,
            Packet::Marker => 10,
            Packet::LiteralData(_) => 11,
            Packet::Trust => 12,
            Packet::UserId(_) => 13,
            Packet::PublicSubkey(_) => 14,
            Packet::UserAttribute => 17,
            Packet::SymmetricEncryptedIntegrityProtectedData => 18,
            Packet::ModificationDetectionCode => 19,
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();

        let body = match self {
            &Packet::Signature(ref signature) => signature.to_bytes()?,
            &Packet::SecretKey(ref key) => key.to_bytes()?,
            &Packet::PublicKey(ref key) => key.to_bytes()?,
            &Packet::SecretSubkey(ref key) => key.to_bytes()?,
            &Packet::CompressedData(ref cdata) => cdata.to_bytes()?,
            &Packet::Marker => Vec::from(marker::MARKER_PACKET),
            &Packet::LiteralData(ref data) => data.to_bytes()?,
            &Packet::UserId(ref id) => Vec::from(id.as_bytes()),
            &Packet::PublicSubkey(ref key) => key.to_bytes()?,
            p => bail!(PacketError::UnimplementedType { packet_type: format!("{:?}", p) }),
        };

        let mut packet_tag = 0b1000_0000;
        let packet_type = self.packet_tag() << 2;
        packet_tag |= packet_type;

        if body.len() < ::std::u8::MAX as usize {
            // Header is 2 octets long. packet_tag is unchanged.
            out.push(packet_tag);
            out.push(body.len() as u8);
        } else if body.len() < ::std::u16::MAX as usize {
            // Header is 3 octets long.
            out.push(packet_tag | 0x1);
            out.write_u16::<BigEndian>(body.len() as u16)?;
        } else {
            // Header is 5 octets long.
            out.push(packet_tag | 0x2);
            out.write_u32::<BigEndian>(body.len() as u32)?;
        }

        out.extend(&body);

        Ok(out)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<(Packet, &[u8]), Error> {
        let (remaining, packet_tag, packet_data) = match pgp_packet_header(bytes) {
            IResult::Done(remaining, (tag, data)) => (remaining, tag, data),
            IResult::Error(NomErr::Code(ErrorKind::Custom(e))) => {
                let e = NomError::from(e);

                bail!(PacketError::UnsupportedHeader {
                    reason: format!("{:?}", e),
                })
            }
            IResult::Error(e) => bail!(PacketError::InvalidHeader {
                reason: format!("{}", e),
            }),
            IResult::Incomplete(i) => bail!(PacketError::InvalidHeader {
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
            5 => Packet::SecretKey(Key::from_bytes(packet_data)?),
            6 => Packet::PublicKey(Key::from_bytes(packet_data)?),
            7 => Packet::SecretSubkey(Key::from_bytes(packet_data)?),
            8 => Packet::CompressedData(CompressedDataPacket::from_bytes(packet_data)?),
            9 => Packet::SymmetricEncryptedData,
            10 => {
                marker::verify_marker(packet_data)?;
                Packet::Marker
            }
            11 => Packet::LiteralData(LiteralPacket::from_bytes(packet_data)?),
            12 => Packet::Trust,
            13 => Packet::UserId(userid::parse_userid(packet_data)?),
            14 => Packet::PublicSubkey(Key::from_bytes(packet_data)?),
            17 => Packet::UserAttribute,
            18 => Packet::SymmetricEncryptedIntegrityProtectedData,
            19 => Packet::ModificationDetectionCode,
            _ => bail!(PacketError::InvalidHeader {
                reason: format!("unknown tag"),
            }),
        };

        Ok((packet, remaining))
    }

    pub fn all_from_bytes(mut bytes: &[u8]) -> Result<Vec<Packet>, Error> {
        let mut out = Vec::new();

        while !bytes.is_empty() {
            let (packet, remaining) = Packet::from_bytes(bytes)?;
            out.push(packet);
            bytes = remaining;
        }

        Ok(out)
    }
}

/// Error type for [`Packet`]-level errors.
///
/// [`Packet`]: enum.Packet.html
#[derive(Debug, Fail)]
pub enum PacketError {
    #[fail(display = "Invalid packet header: {}", reason)]
    InvalidHeader { reason: String },
    #[fail(display = "Unsupported packet header: {}", reason)]
    UnsupportedHeader { reason: String },
    #[fail(display = "Unimplemented packet type: {}", packet_type)]
    UnimplementedType { packet_type: String },
}
