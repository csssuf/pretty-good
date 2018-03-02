use std::cell::RefCell;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use failure::Error;
use nom::{rest, be_u16, be_u32, be_u64, be_u8};
use nom::{ErrorKind, IResult};
use nom::Err as NomErr;
use num::BigUint;

use types::*;

#[cfg_attr(rustfmt, rustfmt_skip)]
named!(
    v3_sig<SignaturePacket>,
    do_parse!(
        tag!(b"\x03") >>
        tag!(b"\x05") >>
        signature_type: be_u8 >>
        creation_time: be_u32 >>
        signer: be_u64 >>
        pubkey_algo: be_u8 >>
        hash_algo: be_u8 >>
        take!(2) >>
        signature: call!(rest) >>
        (SignaturePacket {
            sig_type: SignatureType::from(signature_type),
            timestamp: Some(Duration::from_secs(u64::from(creation_time))),
            signer: Some(signer),
            pubkey_algo: PublicKeyAlgorithm::from(pubkey_algo),
            hash_algo: HashAlgorithm::from(hash_algo),
            hashed_subpackets: Vec::new(),
            unhashed_subpackets: Vec::new(),
            signature_contents: Vec::from(signature),
            payload_hash: RefCell::new(None),
        })
    )
);

fn subpacket_length(inp: &[u8]) -> IResult<&[u8], u32> {
    let (remaining, first_octet) = match be_u8(inp) {
        IResult::Done(remaining, first_octet) => (remaining, first_octet),
        IResult::Error(e) => return IResult::Error(e),
        IResult::Incomplete(i) => return IResult::Incomplete(i),
    };

    if first_octet < 192 {
        IResult::Done(remaining, u32::from(first_octet))
    } else if first_octet < 255 {
        let (remaining, second_octet) = match be_u8(remaining) {
            IResult::Done(remaining, second_octet) => (remaining, second_octet),
            IResult::Error(e) => return IResult::Error(e),
            IResult::Incomplete(i) => return IResult::Incomplete(i),
        };

        let length = ((u16::from(first_octet) - 192) << 8) + u16::from(second_octet) + 192;

        IResult::Done(remaining, u32::from(length))
    } else {
        be_u32(remaining)
    }
}

fn parse_subpacket(inp: &[u8]) -> IResult<&[u8], Subpacket> {
    let (remaining, length) = match subpacket_length(inp) {
        IResult::Done(remaining, length) => (remaining, length),
        IResult::Error(e) => return IResult::Error(e),
        IResult::Incomplete(i) => return IResult::Incomplete(i),
    };

    let (remaining, subpacket_type) = match be_u8(remaining) {
        IResult::Done(remaining, subpacket_type) => (remaining, subpacket_type),
        IResult::Error(e) => return IResult::Error(e),
        IResult::Incomplete(i) => return IResult::Incomplete(i),
    };

    let (remaining, mut packet_contents) = match take!(remaining, length - 1) {
        IResult::Done(remaining, contents) => (remaining, contents),
        IResult::Error(e) => return IResult::Error(e),
        IResult::Incomplete(i) => return IResult::Incomplete(i),
    };

    match subpacket_type {
        0 | 1 | 8 | 13 | 14 | 15 | 17 | 18 | 19 => IResult::Error(NomErr::Code(
            ErrorKind::Custom(NomError::UseOfReservedValue as u32),
        )),
        2 => {
            let time_secs = match packet_contents.read_u32::<BigEndian>() {
                Ok(val) => val,
                Err(_) => {
                    return IResult::Error(NomErr::Code(ErrorKind::Custom(
                        NomError::IntegerReadError as u32,
                    )))
                }
            };
            let subpacket =
                Subpacket::SignatureCreationTime(Duration::from_secs(u64::from(time_secs)));
            IResult::Done(remaining, subpacket)
        }
        3 => {
            let time_secs = match packet_contents.read_u32::<BigEndian>() {
                Ok(val) => val,
                Err(_) => {
                    return IResult::Error(NomErr::Code(ErrorKind::Custom(
                        NomError::IntegerReadError as u32,
                    )))
                }
            };
            let subpacket =
                Subpacket::SignatureExpirationTime(Duration::from_secs(u64::from(time_secs)));
            IResult::Done(remaining, subpacket)
        }
        16 => {
            let issuer = match packet_contents.read_u64::<BigEndian>() {
                Ok(val) => val,
                Err(_) => {
                    return IResult::Error(NomErr::Code(ErrorKind::Custom(
                        NomError::IntegerReadError as u32,
                    )))
                }
            };
            let subpacket = Subpacket::Issuer(issuer);
            IResult::Done(remaining, subpacket)
        }
        t => IResult::Done(remaining, Subpacket::Unknown(t, length)),
    }
}

named!(subpackets<Vec<Subpacket>>, many0!(parse_subpacket));

fn find_timestamp(subpackets: &[Subpacket]) -> Option<Duration> {
    for subpacket in subpackets {
        if let Subpacket::SignatureCreationTime(out) = *subpacket {
            return Some(out);
        }
    }

    None
}

fn find_signer(subpackets: &[Subpacket]) -> Option<u64> {
    for subpacket in subpackets {
        if let Subpacket::Issuer(out) = *subpacket {
            return Some(out);
        }
    }

    None
}

#[cfg_attr(rustfmt, rustfmt_skip)]
named!(
    v4_sig<SignaturePacket>,
    do_parse!(
        tag!(b"\x04") >>
        signature_type: be_u8 >>
        pubkey_algo: be_u8 >>
        hash_algo: be_u8 >>
        hashed_subs: length_value!(be_u16, subpackets) >>
        unhashed_subs: length_value!(be_u16, subpackets) >>
        take!(2) >>
        signature: call!(rest) >>
        (SignaturePacket {
            sig_type: SignatureType::from(signature_type),
            timestamp: find_timestamp(&hashed_subs).or_else(|| find_timestamp(&unhashed_subs)),
            signer: find_signer(&hashed_subs).or_else(|| find_signer(&unhashed_subs)),
            pubkey_algo: PublicKeyAlgorithm::from(pubkey_algo),
            hash_algo: HashAlgorithm::from(hash_algo),
            hashed_subpackets: hashed_subs,
            unhashed_subpackets: unhashed_subs,
            signature_contents: Vec::from(signature),
            payload_hash: RefCell::new(None),
        })
    )
);

named!(signature<SignaturePacket>, alt!(v3_sig | v4_sig));

/// The contents of a PGP signature packet.
#[derive(Clone, Debug)]
pub struct SignaturePacket {
    pub sig_type: SignatureType,
    timestamp: Option<Duration>,
    signer: Option<u64>,
    pub pubkey_algo: PublicKeyAlgorithm,
    pub hash_algo: HashAlgorithm,
    pub hashed_subpackets: Vec<Subpacket>,
    pub unhashed_subpackets: Vec<Subpacket>,
    signature_contents: Vec<u8>,
    payload_hash: RefCell<Option<Vec<u8>>>,
}

impl SignaturePacket {
    /// Create a new signature with the given parameters. The new signature's creation time will be
    /// set to the current system time, and the contents will be empty.
    pub fn new(
        sig_type: SignatureType,
        pubkey_algo: PublicKeyAlgorithm,
        hash_algo: HashAlgorithm,
    ) -> Result<SignaturePacket, Error> {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?;

        Ok(SignaturePacket {
            sig_type: sig_type,
            timestamp: Some(timestamp),
            signer: None,
            pubkey_algo: pubkey_algo,
            hash_algo: hash_algo,
            hashed_subpackets: Vec::new(),
            unhashed_subpackets: Vec::new(),
            signature_contents: Vec::new(),
            payload_hash: RefCell::new(None),
        })
    }

    /// Retrieve the contents of this signature. For RSA signatures, this is a single
    /// multiprecision integer representing `m^d mod n`; for DSA signatures this is two
    /// multiprecision integers representing `r` and `s`.
    pub fn contents(&self) -> Result<Signature, Error> {
        match self.pubkey_algo {
            PublicKeyAlgorithm::Rsa
            | PublicKeyAlgorithm::RsaEncryptOnly
            | PublicKeyAlgorithm::RsaSignOnly => {
                let (mut header_slice, mpi_slice) = self.signature_contents.split_at(2);
                let header = header_slice.read_u16::<BigEndian>()?;
                // GPG uses the header to indicate the number of bits in the MPI; we care about the
                // number of bytes.
                let header = (header as f64 / 8.0).ceil() as usize;

                if mpi_slice.len() < header {
                    bail!(SignatureError::MalformedMpi);
                }
                let (mpi_slice, _) = mpi_slice.split_at(header);

                let mpi = BigUint::from_bytes_be(mpi_slice);
                Ok(Signature::Rsa(mpi))
            }
            PublicKeyAlgorithm::Dsa => {
                let (mut header_r_slice, remaining) = self.signature_contents.split_at(2);
                let header_r = header_r_slice.read_u16::<BigEndian>()?;
                // GPG uses the header to indicate the number of bits in the MPI; we care about the
                // number of bytes.
                let header_r = (header_r as f64 / 8.0).ceil() as usize;

                if remaining.len() < header_r {
                    bail!(SignatureError::MalformedMpi);
                }

                let (mpi_r_slice, remaining) = remaining.split_at(header_r);

                let (mut header_s_slice, mpi_s_slice) = remaining.split_at(2);
                let header_s = header_s_slice.read_u16::<BigEndian>()?;
                let header_s = (header_s as f64 / 8.0).ceil() as usize;

                if mpi_s_slice.len() < header_s {
                    bail!(SignatureError::MalformedMpi);
                }

                let mpi_r = BigUint::from_bytes_be(mpi_r_slice);
                let mpi_s = BigUint::from_bytes_be(mpi_s_slice);

                Ok(Signature::Dsa(mpi_r, mpi_s))
            }
            _ => Ok(Signature::Unknown(self.signature_contents.clone())),
        }
    }

    /// Set the contents of this signature.
    pub fn set_contents(&mut self, sig: Signature) -> Result<(), Error> {
        match sig {
            Signature::Rsa(mpi) => {
                let mut mpi_header = Vec::new();

                mpi_header.write_u16::<BigEndian>(mpi.bits() as u16)?;
                mpi_header.extend(&mpi.to_bytes_be());

                self.signature_contents = mpi_header;
            }
            Signature::Dsa(r, s) => {
                let mut mpis = Vec::new();

                mpis.write_u16::<BigEndian>(r.bits() as u16)?;
                mpis.extend(&r.to_bytes_be());

                mpis.write_u16::<BigEndian>(s.bits() as u16)?;
                mpis.extend(&s.to_bytes_be());

                self.signature_contents = mpis;
            }
            Signature::Unknown(payload) => self.signature_contents = payload.clone(),
        }

        Ok(())
    }

    /// Retrive the creation time of this signature.
    pub fn timestamp(&self) -> Option<Duration> {
        find_timestamp(&self.hashed_subpackets)
            .or_else(|| find_timestamp(&self.unhashed_subpackets))
            .or(self.timestamp)
    }

    /// Set the creation time of this signature.
    pub fn set_timestamp(&mut self, timestamp: Duration) {
        self.hashed_subpackets.retain(|subpacket| {
            if let Subpacket::SignatureCreationTime(_) = *subpacket {
                false
            } else {
                true
            }
        });
        self.unhashed_subpackets.retain(|subpacket| {
            if let Subpacket::SignatureCreationTime(_) = *subpacket {
                false
            } else {
                true
            }
        });

        self.hashed_subpackets
            .push(Subpacket::SignatureCreationTime(timestamp));
        self.timestamp = Some(timestamp);
    }

    /// Retrieve the key ID of this signature's issuer.
    pub fn signer(&self) -> Option<u64> {
        find_signer(&self.hashed_subpackets)
            .or_else(|| find_signer(&self.unhashed_subpackets))
            .or(self.signer)
    }

    /// Set the key ID of this signature's issuer.
    pub fn set_signer(&mut self, signer: u64) {
        self.hashed_subpackets.retain(|subpacket| {
            if let Subpacket::Issuer(_) = *subpacket {
                false
            } else {
                true
            }
        });
        self.unhashed_subpackets.retain(|subpacket| {
            if let Subpacket::Issuer(_) = *subpacket {
                false
            } else {
                true
            }
        });

        self.unhashed_subpackets.push(Subpacket::Issuer(signer));
        self.signer = Some(signer);
    }

    fn common_header(&self) -> Result<Vec<u8>, Error> {
        let mut header = Vec::new();

        // Signature version 4
        header.push(4);
        header.push(self.sig_type.into());
        header.push(self.pubkey_algo.into());
        header.push(self.hash_algo.into());

        // Since we may be an old (v3) signature packet, but we only emit new (v4) signature
        // packets, ensure that there is a hashed subpacket with the timestamp available, since a
        // signature _must_ have a timestamp hashed subpacket. However, we do not want to save this
        // new hashed subpacket in this signature's real list, so we forget about it after this
        // function.
        let mut hashed_subpackets = self.hashed_subpackets.clone();
        match find_timestamp(&self.hashed_subpackets) {
            Some(_) => {}
            None => match self.timestamp {
                Some(timestamp) => {
                    hashed_subpackets.push(Subpacket::SignatureCreationTime(timestamp))
                }
                None => bail!(SignatureError::Unusable {
                    reason: "no SignatureCreationTime".to_string(),
                }),
            },
        }

        let mut hashed_subpackets_bytes: Vec<u8> = Vec::new();
        for packet in &hashed_subpackets {
            let packet_bytes = packet.to_bytes()?;
            hashed_subpackets_bytes.extend(&packet_bytes);
        }
        // The hashed subpackets are preceded by a two-octet big-endian value representing the
        // total length of all hashed subpackets.
        header.write_u16::<BigEndian>(hashed_subpackets_bytes.len() as u16)?;
        header.extend(&hashed_subpackets_bytes);

        Ok(header)
    }

    /// Build a payload suitable for signing.
    ///
    /// Note that this payload must be placed in an ASN.1 DigestInfo structure prior to signing,
    /// which is outside the scope of this library.
    pub fn signable_payload<T: AsRef<[u8]>>(&self, payload: T) -> Result<Vec<u8>, Error> {
        let mut signing_payload = Vec::from(payload.as_ref());

        let common_header = self.common_header()?;
        signing_payload.extend(&common_header);

        // From RFC4880, Section 5.2.4:
        // V4 signatures also hash in a final trailer of six octets: the
        // version of the Signature packet, i.e., 0x04; 0xFF; and a four-octet,
        // big-endian number that is the length of the hashed data from the
        // Signature packet (note that this number does not include these final
        // six octets).
        let mut suffix = Vec::new();
        suffix.push(0x04);
        suffix.push(0xFF);
        suffix.write_u32::<BigEndian>(common_header.len() as u32)?;
        signing_payload.extend(&suffix);

        let hash = self.hash_algo.hash(signing_payload)?;
        self.payload_hash.replace(Some(hash.clone()));

        Ok(hash)
    }

    /// Retrieve the header for this signature, i.e. everything except the MPI contents of the
    /// signature.
    pub fn header(&self) -> Result<Vec<u8>, Error> {
        let mut header = self.common_header()?;

        let mut unhashed_subpackets_bytes: Vec<u8> = Vec::new();
        for packet in &self.unhashed_subpackets {
            let packet_bytes = packet.to_bytes()?;
            unhashed_subpackets_bytes.extend(&packet_bytes);
        }
        // The unhashed subpackets are preceded by a two-octet big-endian value representing the
        // total length of all unhashed subpackets.
        header.write_u16::<BigEndian>(unhashed_subpackets_bytes.len() as u16)?;
        header.extend(&unhashed_subpackets_bytes);

        match *self.payload_hash.borrow() {
            Some(ref hash) => {
                header.push(hash[0]);
                header.push(hash[1]);
            }
            None => {
                header.push(0);
                header.push(0);
            }
        }

        Ok(header)
    }

    /// Serialize this signature to bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut out = self.header()?;
        out.extend(&self.signature_contents);

        Ok(out)
    }

    /// Read in a signature from some bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<SignaturePacket, Error> {
        match signature(bytes) {
            IResult::Done(_, sig) => Ok(sig),
            IResult::Error(NomErr::Code(ErrorKind::Custom(e))) => {
                let e = NomError::from(e);

                bail!(SignatureError::InvalidFormat {
                    reason: format!("{:?}", e),
                })
            }
            IResult::Error(e) => bail!(SignatureError::InvalidFormat {
                reason: format!("{}", e),
            }),
            IResult::Incomplete(i) => bail!(SignatureError::InvalidFormat {
                reason: format!("{:?}", i),
            }),
        }
    }
}

/// The type of content a signature covers. See [RFC4880 &sect;5.2.1].
///
/// [RFC4880 &sect;5.2.1]: https://tools.ietf.org/html/rfc4880#section-5.2.1
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SignatureType {
    BinaryDocument = 0x00,
    TextDocument = 0x01,
    Standalone = 0x02,
    GenericCertification = 0x10,
    PersonaCertification = 0x11,
    CasualCertification = 0x12,
    PositiveCertification = 0x13,
    SubkeyBinding = 0x18,
    PrimaryKeyBinding = 0x19,
    DirectKey = 0x1F,
    KeyRevocation = 0x20,
    SubkeyRevocation = 0x28,
    CertificationRevocation = 0x30,
    Timestamp = 0x40,
    ThirdPartyConfirmation = 0x50,
    Unknown = 255,
}

impl From<u8> for SignatureType {
    fn from(val: u8) -> SignatureType {
        match val {
            0x00 => SignatureType::BinaryDocument,
            0x01 => SignatureType::TextDocument,
            0x02 => SignatureType::Standalone,
            0x10 => SignatureType::GenericCertification,
            0x11 => SignatureType::PersonaCertification,
            0x12 => SignatureType::CasualCertification,
            0x13 => SignatureType::PositiveCertification,
            0x18 => SignatureType::SubkeyBinding,
            0x19 => SignatureType::PrimaryKeyBinding,
            0x1F => SignatureType::DirectKey,
            0x20 => SignatureType::KeyRevocation,
            0x28 => SignatureType::SubkeyRevocation,
            0x30 => SignatureType::CertificationRevocation,
            0x40 => SignatureType::Timestamp,
            0x50 => SignatureType::ThirdPartyConfirmation,
            _ => SignatureType::Unknown,
        }
    }
}

impl From<SignatureType> for u8 {
    fn from(val: SignatureType) -> u8 {
        match val {
            SignatureType::BinaryDocument => 0x00,
            SignatureType::TextDocument => 0x01,
            SignatureType::Standalone => 0x02,
            SignatureType::GenericCertification => 0x10,
            SignatureType::PersonaCertification => 0x11,
            SignatureType::CasualCertification => 0x12,
            SignatureType::PositiveCertification => 0x13,
            SignatureType::SubkeyBinding => 0x18,
            SignatureType::PrimaryKeyBinding => 0x19,
            SignatureType::DirectKey => 0x1F,
            SignatureType::KeyRevocation => 0x20,
            SignatureType::SubkeyRevocation => 0x28,
            SignatureType::CertificationRevocation => 0x30,
            SignatureType::Timestamp => 0x40,
            SignatureType::ThirdPartyConfirmation => 0x50,
            SignatureType::Unknown => 0xFF,
        }
    }
}

/// Type for [`SignaturePacket`] subpackets. See [RFC4880 &sect;5.2.3.1].
///
/// [`SignaturePacket`]: struct.SignaturePacket.html
/// [RFC4880 &sect;5.2.3.1]: https://tools.ietf.org/html/rfc4880#section-5.2.3.1
#[derive(Clone, Debug)]
pub enum Subpacket {
    SignatureCreationTime(Duration),
    SignatureExpirationTime(Duration),
    ExportableCertification,
    TrustSignature,
    RegularExpression,
    Revocable,
    KeyExpirationTime(Duration),
    PreferredSymmetricAlgorithms,
    RevocationKey,
    Issuer(u64),
    NotationData,
    PreferredHashAlgorithms,
    PreferredCompressionAlgorithms,
    KeyServerPreferences,
    PreferredKeyServer,
    PrimaryUserId,
    PolicyUri,
    KeyFlags,
    SignerUserId,
    RevocationReason,
    Features,
    SignatureTarget,
    EmbeddedSignature,
    Unknown(u8, u32),
}

impl Subpacket {
    fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut out: Vec<u8> = Vec::new();

        match *self {
            Subpacket::SignatureCreationTime(time) => {
                // Subpacket type
                out.push(2);
                out.write_u32::<BigEndian>(time.as_secs() as u32)?;
            }
            Subpacket::Issuer(issuer) => {
                // Subpacket type
                out.push(16);
                out.write_u64::<BigEndian>(issuer)?;
            }
            _ => {}
        }

        let mut packet_len = if out.len() < 192 {
            vec![out.len() as u8]
        } else {
            let mut packet_len = vec![255u8];
            packet_len.write_u32::<BigEndian>(out.len() as u32)?;
            packet_len
        };

        packet_len.extend(&out);
        Ok(packet_len)
    }
}

/// Actual multiprecision integer signature contents.
///
/// For RSA signatures, this is the multiprecision integer representing `m^d mod n`. For DSA
/// signatures, this is two multiprecision integers representing `r` and `s`, respectively.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Signature {
    Rsa(BigUint),
    Dsa(BigUint, BigUint),
    Unknown(Vec<u8>),
}

/// Error type for [`SignaturePacket`]-level errors.
///
/// [`SignaturePacket`]: struct.SignaturePacket.html
#[derive(Debug, Fail)]
pub enum SignatureError {
    #[fail(display = "Invalid signature format: {}", reason)]
    InvalidFormat { reason: String },
    #[fail(display = "Unusable signature: {}", reason)]
    Unusable { reason: String },
    #[fail(display = "Malformed MPI payload")]
    MalformedMpi,
}
